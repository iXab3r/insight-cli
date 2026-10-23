import {readFile,realpath} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {ownedDirectory} from './directory-identity.js';
import {fail,object,stable} from './model.js';
import type {ChildProcess} from 'node:child_process';

/** Bind the real child before allocating its credential; preserve uncertain children. */
export async function launchContextCredential<T extends ChildProcess>(secrets:{set(name:string,value:string):Promise<void>},
 name:string,token:string,start:(onSpawn:(child:T)=>Promise<void>)=>Promise<T>,
 bind:(child:T)=>Promise<void>,retire:(child:T)=>Promise<void>):Promise<T>{
 let child:T|undefined;
 try{return await start(async spawned=>{child=spawned;await bind(spawned);await secrets.set(name,token);});}
 catch(error){
  if(child&&(child.exitCode!==null||child.signalCode!==null))await retire(child);
  throw error;
 }
}

export interface ContextCredentialBinding {
 root:string;kind:string;target:string;context?:string;pid:number;tokenSecret:string;runtimeFingerprint:string;
}

/** Release one retired worker credential, never inventory or sweep the OS store. */
export async function releaseStoppedContextCredential(directory:string,binding:ContextCredentialBinding,
 secrets:{delete(name:string):Promise<void>},alive:(pid:number)=>boolean,retired?:()=>Promise<boolean>):Promise<boolean>{
 // A matching stop receipt is required even when the supervisor proves retirement.
 const root=await realpath(binding.root);
 if(!ownedDirectory(root,directory,[binding.kind,binding.context??binding.target,basename(root)])||
    !/^context-[a-f0-9-]{36}$/.test(binding.tokenSecret)||
    stable(JSON.parse(await readFile(join(root,'process.json'),'utf8')))!==stable(binding))
  fail('binding','Retired native credential receipt changed.');
 let stopped:Record<string,unknown>;
 try{stopped=object(JSON.parse(await readFile(join(root,'stopped.json'),'utf8')));}
 catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return false;throw error;}
 if(stopped.pid!==binding.pid||stopped.tokenSecret!==binding.tokenSecret)return false;
 const ended=async()=>!alive(binding.pid)||await retired?.()===true;
 if(!await ended())return false;
 // The parent lane serializes context reuse. Check liveness again after disk reads.
 if(!await ended())return false;
 await secrets.delete(binding.tokenSecret);
 return true;
}
