import {AsyncLocalStorage} from 'node:async_hooks';
import {randomUUID} from 'node:crypto';
import {mkdir,appendFile,stat,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {performance} from 'node:perf_hooks';

interface Trace {id:string;command:string;started:number;rows:Record<string,unknown>[];parent?:string;overflow:{count:number}}
const current=new AsyncLocalStorage<Trace>(),writes=new Map<string,Promise<void>>();
/** Internal diagnostics only: fixed operation names, never argv, payloads, paths or errors. */
export async function timed<T>(phase:string,operation:string,action:()=>Promise<T>):Promise<T>{
 const trace=current.getStore();if(!trace)return action();
 const span=randomUUID(),started=performance.now();let outcome='success';
 try{return await current.run({...trace,parent:span},action);}catch(error){outcome='failure';throw error;}
 finally{if(trace.rows.length<1024)trace.rows.push({trace:trace.id,span,parent:trace.parent??null,command:trace.command,phase,operation,startedMs:started-trace.started,durationMs:performance.now()-started,outcome});else trace.overflow.count++;}
}
export async function traceCommand<T>(root:string,command:string,action:()=>Promise<T>):Promise<T>{
 const trace:Trace={id:randomUUID(),command,started:performance.now(),rows:[],overflow:{count:0}},at=new Date().toISOString();
 try{return await current.run(trace,()=>timed('facade.command',command,action));}
 finally{
  const directory=join(root,'diagnostics'),path=join(directory,'timings.jsonl'),previous=writes.get(path)??Promise.resolve();
  const pending=previous.catch(()=>{}).then(async()=>{
   await mkdir(directory,{recursive:true,mode:0o700});
   if(await stat(path).then(s=>s.size,()=>0)>8*1024**2)await rename(path,path+'.previous');
   await appendFile(path,trace.rows.map(row=>JSON.stringify({schema:1,at,...row,droppedSpans:trace.overflow.count})).join('\n')+'\n',{mode:0o600});
  });writes.set(path,pending);
  // Telemetry loss cannot change an acknowledged program operation into a failed write.
  try{await pending;}catch{}finally{if(writes.get(path)===pending)writes.delete(path);}
 }
}
