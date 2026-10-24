import {mkdir,open,rename,rm,readFile,readdir,lstat,realpath} from 'node:fs/promises';
import {createReadStream,existsSync} from 'node:fs';
import {dirname,basename,join,resolve,relative,sep} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {AsyncLocalStorage} from 'node:async_hooks';
import {CliError} from '@eyeauras/cli-factory';
import {fail} from '../model.js';

export async function atomicWrite(path:string,value:unknown){
 const parent=await physicalDirectory(dirname(path)),target=join(parent,basename(path));
 await mkdir(parent,{recursive:true,mode:0o700});const temporary=target+'.new-'+randomUUID(),file=await open(temporary,'wx',0o600);
 try{await file.writeFile(JSON.stringify(value,null,2)+'\n');await file.sync();}finally{await file.close();}
 await rename(temporary,target);
 if(process.platform!=='win32'){const handle=await open(parent,'r');try{await handle.sync();}finally{await handle.close();}}
}

async function physicalDirectory(path:string):Promise<string>{
 try{return await realpath(path);}catch(error){
  if((error as NodeJS.ErrnoException).code!=='ENOENT'||dirname(path)===path)throw error;
  return join(await physicalDirectory(dirname(path)),basename(path));
 }
}

/** Create new run folders through the physical runtime, retaining logical receipt identity. */
export async function prepareRunRoot(directory:string,id:string){
 const runtime=join(directory,'runtime');if(!existsSync(runtime))await mkdir(runtime,{recursive:true,mode:0o700});
 await mkdir(join(await realpath(runtime),'runs',id),{recursive:true,mode:0o700});
}
export async function readJson<T>(path:string):Promise<T|undefined>{try{return JSON.parse(await readFile(path,'utf8')) as T;}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return;throw e;}}
export function toolRoot(directory:string,tool:string){if(!/^[a-z][a-z0-9-]*$/.test(tool))fail('invalid','Invalid tool identity.');return tool==='ghidra'?join(directory,'runtime'):join(directory,'runtime','tools',tool);}
const queues=new Map<string,Promise<void>>(),held=new AsyncLocalStorage<Set<string>>(),uses=new Map<string,number>();
const key=(directory:string,tool:string)=>resolve(directory)+'\0'+tool;
/** CLI clients already share Factory's elected owner. Do not create another IPC/lease protocol. */
export async function withToolLock<T>(directory:string,tool:string,action:()=>Promise<T>,signal?:AbortSignal):Promise<T>{
 signal?.throwIfAborted();const k=key(directory,tool);if(held.getStore()?.has(k))return action();
 const previous=queues.get(k)??Promise.resolve();
 let started=false;const execution=previous.then(()=>{signal?.throwIfAborted();started=true;return held.run(new Set([...(held.getStore()??[]),k]),action);});
 const tail=execution.then(()=>{},()=>{});queues.set(k,tail);void tail.then(()=>{if(queues.get(k)===tail)queues.delete(k);});
 if(!signal)return execution;
 return new Promise<T>((ok,bad)=>{
  const aborted=()=>{if(!started)bad(signal.reason);};signal.addEventListener('abort',aborted,{once:true});
  if(signal.aborted)aborted();
  execution.then(ok,bad).finally(()=>signal.removeEventListener('abort',aborted));
 });
}
export function toolProfileBusy(directory:string){const prefix=resolve(directory)+'\0';return [...queues.keys(),...uses.keys()].some(k=>k.startsWith(prefix));}
export function toolUseCount(directory:string,tool:string){return uses.get(key(directory,tool))??0;}
export async function withToolUse<T>(directory:string,tool:string,acquire:()=>Promise<T>,signal?:AbortSignal):Promise<{value:T;release:()=>void}>{
 return withToolLock(directory,tool,async()=>{
  const value=await acquire();signal?.throwIfAborted();const k=key(directory,tool);uses.set(k,(uses.get(k)??0)+1);let released=false;
  return {value,release(){if(released)return;released=true;const n=(uses.get(k)??1)-1;if(n)uses.set(k,n);else uses.delete(k);}};
 },signal);
}
export async function assertUnused(directory:string,tool:string){
 if(toolUseCount(directory,tool))fail('busy','Tool installation is reserved by an active operation.');
 let names:string[];const root=join(directory,'runtime/processes');try{names=await readdir(root);}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return;throw e;}
 for(const name of names){if(!/^[a-f0-9-]{36}\.json$/.test(name))continue;
  const retained=await readJson<{tool:string}>(join(root,name));if(!retained||retained.tool!==tool)continue;
  const {processStatus}=await import('./supervisor.js'),record=await processStatus(directory,name.slice(0,-5));
  if(['exited','failed'].includes(record.state))continue;
  if(record.phase==='native_children_pending'||record.phase==='native_children_unverified')fail('busy','Tool has an active or unverified native helper; inspect its retained records before changing installations.');
  if(!record.pid){
   if(record.gated&&record.ownerPid)try{process.kill(record.ownerPid,0);}catch(e){if((e as NodeJS.ErrnoException).code==='ESRCH')continue;throw e;}
   fail('busy','Tool has an unresolved process launch; inspect its process record.');
  }
  try{process.kill(record.pid,0);fail('busy','Tool has an active or unverified process; stop it before changing installations.');}
  catch(e){if((e as NodeJS.ErrnoException).code!=='ESRCH')throw e;}
 }
}
export async function installationStage<T>(root:string,id:string,prepare:(stage:string,installed:string)=>Promise<T>,verify:(receipt:T)=>Promise<void>,signal?:AbortSignal){
 if(!/^[a-f0-9]{64}$/.test(id))fail('invalid','Invalid installation identity.');signal?.throwIfAborted();
 const installed=join(root,'installations',id),receipt=await readJson<T>(join(installed,'ready.json'));
 if(receipt){await verify(receipt);return receipt;}
 const stage=join(root,'stages',randomUUID());await mkdir(stage,{recursive:true,mode:0o700});
 try{
  const value=await prepare(stage,installed);signal?.throwIfAborted();await atomicWrite(join(stage,'ready.json'),value);
  await mkdir(dirname(installed),{recursive:true,mode:0o700});
  try{await lstat(installed);fail('binding','Incomplete installation is retained; inspect it before removing it.');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  await rename(stage,installed);if(process.platform!=='win32'){const p=await open(dirname(installed),'r');try{await p.sync();}finally{await p.close();}}
  return value;
 }catch(error){
  const code=error instanceof CliError?error.code:'installation';
  await atomicWrite(join(stage,'failure.json'),{state:'failed',code});
  if(error instanceof CliError)throw new CliError(error.message,{code:error.code,result:{...(error.result&&typeof error.result==='object'?error.result:{}),diagnostics:stage}});
  throw new CliError('Tool installation failed; the prior selection and diagnostic stage are retained.',{code:'tool.installation',cause:error,result:{diagnostics:stage}});
 }
}
export async function removeInstallation(root:string,id:string){
 if(!/^[a-f0-9]{64}$/.test(id))fail('binding','Invalid installation identity.');
 const path=join(root,'installations',id);let actual:string;
 try{actual=await realpath(path);}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return;throw e;}
 if(actual!==join(await realpath(root),'installations',id))fail('binding','Owned installation path was replaced by an external link.');
 await rm(path,{recursive:true,force:true});
}
export async function treeFingerprint(root:string){
 const hash=createHash('sha256'),canonicalRoot=await realpath(root);let count=0;
 async function visit(path:string):Promise<void>{
  for(const name of (await readdir(path)).sort()){
   if(path===root&&name==='ready.json')continue;
   const at=join(path,name),st=await lstat(at);if(++count>100000)fail('limit','Tool installation exceeds its file bound.');
   hash.update(relative(root,at).replaceAll('\\','/')+'\0');
   if(st.isDirectory())await visit(at);
   else if(st.isSymbolicLink()){
    const destination=await realpath(at);if(!destination.startsWith(canonicalRoot+sep))fail('binding','Installed component link escapes its owned directory.');
    hash.update('link:'+relative(canonicalRoot,destination));
   }else if(st.isFile()){const leaf=createHash('sha256');for await(const b of createReadStream(at))leaf.update(b);hash.update('file:'+st.size+':'+leaf.digest('hex')+'\0');}
   else fail('binding','Unsupported tool installation entry.');
  }
 }
 await visit(root);return hash.digest('hex');
}
