// Disposable acceptance wrapper around the installed CLI and its real Ghidra publisher.
// Barriers exist only here, never in the shipped command tree or runtime environment.
import {readFile,writeFile,appendFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {AppArguments,KeyringSecretStore} from '@eyeauras/cli-factory';
import {runHosted} from '@eyeauras/cli-factory-ipc';
import {createDefinition} from '@ixab3r/insight-cli/dist/src/prototype-cli.js';
import {GhidraRuntime} from '@ixab3r/insight-cli/dist/src/ghidra.js';

const config=JSON.parse(await readFile(new URL('./fixture-config.json',import.meta.url),'utf8'));
const appArguments=new AppArguments(config.appArguments);
const directory=appArguments.AppDataDirectory;
const native=new KeyringSecretStore();
const secretStore={
  get:(service,account)=>native.get(service,account),
  delete:(service,account)=>native.delete(service,account),
  async set(service,account,value){
    // Only non-secret key names are recorded so this unique fixture namespace can be cleaned.
    await appendFile(join(directory,'secret-keys.jsonl'),JSON.stringify({service,account})+'\n',{mode:0o600});
    return native.set(service,account,value);
  },
};
const publisher=context=>{
  const real=new GhidraRuntime(join(directory,'ghidra'),context);
  let binding;
  async function barrier(method,position,target){
    let fault;try{fault=JSON.parse(await readFile(join(directory,'fault.json'),'utf8'));}catch{return;}
    const at={application:['apply','after'],save:['save','after'],checkin:['checkIn','before'],committed:['checkIn','after'],verification:['published','after']}[fault.phase];
    if(!at||at[0]!==method||at[1]!==position||fault.targetId!==target.id)return;
    await writeFile(join(directory,'barrier.json'),JSON.stringify({phase:fault.phase,ownerPid:process.pid,binding}),{mode:0o600});
    for(;;)await delay(1000);
  }
  return new Proxy(real,{get(object,name){const value=object[name];if(typeof value!=='function')return value;return async(...args)=>{
    await barrier(name,'before',args[0]);
    const result=await value.apply(object,args);
    if(name==='open')binding=result;
    await barrier(name,'after',args[0]);
    return result;
  };}});
};
process.exitCode=await runHosted({entryPoint:import.meta.url,createDefinition:()=>{
  const definition=createDefinition({runtime:{appArguments,secretStore},publisher});
  definition.applicationId=config.applicationId;
  return definition;
}});
