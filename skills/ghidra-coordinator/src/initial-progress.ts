import {readFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {atomicWrite} from './tool-runtime/store.js';

/** Observation only. Completion receipts and the workspace remain the outcome authority. */
export async function readInitialProgress(directory:string,target:string){
  try{
    const value=JSON.parse(await readFile(join(directory,'ghidra-native','initial',target,'progress.json'),'utf8'));
    if(value.schema!==1||value.target!==target)throw Error('Invalid initial progress binding');
    const ageMs=Math.max(0,Date.now()-Date.parse(value.updatedAt));
    let workerAlive:boolean|undefined;
    if(Number.isSafeInteger(value.pid)&&value.pid>0)try{process.kill(value.pid,0);workerAlive=true;}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH')workerAlive=false;}
    return {...value,operation:'initial-model',ageMs,elapsedMs:Math.max(0,(value.state==='running'?Date.now():Date.parse(value.updatedAt))-Date.parse(value.startedAt)),
      ...(workerAlive===undefined?{}:{workerAlive}),
      observation:value.state==='running'&&(workerAlive===false||ageMs>15000)?'stale':'current'};
  }catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return null;throw error;}
}
export async function initialProgress(root:string,target:string,phase:string,state='running'){
  await mkdir(root,{recursive:true,mode:0o700});
  let startedAt=new Date().toISOString(),previous:Record<string,unknown>|undefined;
  try{const saved=JSON.parse(await readFile(join(root,'progress.json'),'utf8'));if(saved.schema===1&&saved.target===target){previous=saved;startedAt=saved.startedAt;}}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  // A terminal observation describes the worker's last task, not a fresh owner task.
  // Keep its counters/message/PID so timeout handling cannot erase native progress.
  const retained:Record<string,unknown>={};
  if(state!=='running'&&previous?.phase===phase)for(const key of ['pid','message','completed','total','indeterminate'])
    if(previous[key]!==undefined)retained[key]=previous[key];
  await atomicWrite(join(root,'progress.json'),{schema:1,target,phase,state,pid:process.pid,startedAt,indeterminate:true,
    ...(previous?.attempt===undefined?{}:{attempt:previous.attempt}),...retained,updatedAt:new Date().toISOString()});
}
export async function progressPhase<T>(root:string,target:string,phase:string,action:()=>Promise<T>){
  await initialProgress(root,target,phase);
  let pending=Promise.resolve(),failure:unknown;
  const timer=setInterval(()=>{pending=pending.then(()=>initialProgress(root,target,phase)).catch(error=>{failure=error;});},2000);timer.unref();
  let actionFailed=false;
  try{return await action();}catch(error){actionFailed=true;throw error;}finally{clearInterval(timer);await pending;if(failure&&!actionFailed)throw failure;}
}
