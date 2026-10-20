import {CliError,type CommandContext} from '@eyeauras/cli-factory';
import {lstatSync,readFileSync,realpathSync} from 'node:fs';
import {link,lstat,open,realpath,unlink} from 'node:fs/promises';
import {isAbsolute,join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {digest} from './model.js';
import {atomicWrite,withToolLock} from './tool-runtime/store.js';

type Context=Pick<CommandContext,'profile'|'appArguments'>;
export const analysisTrees=['workspace','materials','temp','runtime'];
export interface StorageDefault {
  schema:1;base:string;application:string;binding:string;id:string;baseInode:string;revision:string;
}
type Marker=Omit<StorageDefault,'revision'>;
const uuid=(value:unknown)=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const absent=(error:unknown)=>(error as NodeJS.ErrnoException).code==='ENOENT';
function fail(code:string,message:string):never{throw new CliError(message,{code:'storage.'+code});}
const policyPath=(c:Context)=>join(c.appArguments.RoamingAppDataDirectory,'.analysis-storage-default.json');
const markerPath=(base:string)=>join(base,'.insight-storage-root.json');
const binding=(c:Context)=>digest(realpathSync.native(c.appArguments.RoamingAppDataDirectory));
function readOwnedJson(path:string):unknown{
  if(!lstatSync(path).isFile())fail('configuration','Storage default metadata must be an ordinary file.');
  return JSON.parse(readFileSync(path,'utf8'));
}
function valid(c:Context,value:unknown):value is Marker{
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  const v=value as Marker;
  return v.schema===1&&v.application===c.appArguments.AppName&&v.binding===binding(c)&&uuid(v.id)&&
    typeof v.base==='string'&&isAbsolute(v.base)&&v.base===resolve(v.base)&&!/[\0\r\n]/.test(v.base)&&
    typeof v.baseInode==='string'&&/^\d+$/.test(v.baseInode);
}
/** Storage control metadata, independent of Factory's profile/settings document. */
export function storageDefault(c:Context):StorageDefault|undefined{
  let value:unknown;
  try{value=readOwnedJson(policyPath(c));}
  catch(error){if(absent(error))return;fail('configuration','Installation storage default is unreadable; preserve its control metadata.');}
  if(!valid(c,value)||!uuid((value as StorageDefault).revision))fail('configuration','Installation storage default failed its application binding.');
  return value as StorageDefault;
}
export function validateStorageDefault(c:Context,value:StorageDefault):void{
  try{
    if(!valid(c,value)||!uuid(value.revision))throw Error('binding');
    const st=lstatSync(value.base,{bigint:true}),marker=readOwnedJson(markerPath(value.base));
    if(!st.isDirectory()||realpathSync.native(value.base)!==value.base||String(st.ino)!==value.baseInode||
      !valid(c,marker)||marker.id!==value.id||marker.base!==value.base||marker.baseInode!==value.baseInode)throw Error('binding');
  }catch{fail('unavailable','Installation analysis storage is missing or changed; mount its original volume. No fallback was created.');}
}
/** Preserve pre-existing local analysis until it is explicitly migrated. */
export function legacyAnalysis(c:Context):boolean{
  return analysisTrees.some(tree=>{try{return !lstatSync(join(c.appArguments.AppDataDirectory,tree)).isSymbolicLink();}catch(error){if(absent(error))return false;throw error;}});
}
export function inheritedStorage(c:Context):StorageDefault|undefined{
  if(c.profile.values.analysisDirectory!==undefined||legacyAnalysis(c))return;
  return storageDefault(c);
}
export async function checkStorageDefaultBase(c:Context,base:string):Promise<void>{
  let marker:unknown;
  try{marker=readOwnedJson(markerPath(base));}catch(error){if(absent(error))return;fail('binding','Storage base ownership metadata is unreadable; preserve it.');}
  if(!valid(c,marker)||marker.base!==base)fail('binding','Storage base belongs to another application/control root; no data was adopted.');
  const st=await lstat(base,{bigint:true});
  if(!st.isDirectory()||await realpath(base)!==base||String(st.ino)!==marker.baseInode)fail('binding','Storage base directory was replaced.');
}
export async function writeStorageDefault(c:Context,base:string,revision:string=randomUUID(),expected?:string|null):Promise<{state:'configured'|'superseded';base:string|null;revision:string|null;binding?:StorageDefault}>{
  return withToolLock(c.appArguments.RoamingAppDataDirectory,'analysis-storage-default',async()=>{
    const current=storageDefault(c);
    if(current?.revision===revision){if(current.base!==base)fail('binding','Storage default intent changed.');validateStorageDefault(c,current);return {state:'configured',base,revision,binding:current};}
    // A resumed migration must never overwrite a later user's default selection.
    if(expected!==undefined&&(current?.revision??null)!==expected)return {state:'superseded',base:current?.base??null,revision:current?.revision??null};
    const st=await lstat(base,{bigint:true});
    if(!st.isDirectory()||await realpath(base)!==base)fail('path','Choose an existing ordinary storage base directory.');
    await checkStorageDefaultBase(c,base);
    let marker:Marker;
    try{marker=readOwnedJson(markerPath(base)) as Marker;}
    catch(error){
      if(!absent(error))throw error;
      marker={schema:1,base,application:c.appArguments.AppName,binding:binding(c),id:randomUUID(),baseInode:String(st.ino)};
      const temporary=markerPath(base)+'.new-'+randomUUID(),file=await open(temporary,'wx',0o600);
      try{
        try{await file.writeFile(JSON.stringify(marker)+'\n');await file.sync();}finally{await file.close();}
        try{await link(temporary,markerPath(base));}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
      }finally{await unlink(temporary);}
      await checkStorageDefaultBase(c,base);marker=readOwnedJson(markerPath(base)) as Marker;
    }
    const next={...marker,revision};validateStorageDefault(c,next);
    if(process.platform!=='win32'){const dir=await open(base,'r');try{await dir.sync();}finally{await dir.close();}}
    await atomicWrite(policyPath(c),next);
    return {state:'configured',base,revision,binding:next};
  },(c as CommandContext).signal);
}
