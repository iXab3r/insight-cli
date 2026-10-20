import {spawn,type ChildProcessWithoutNullStreams} from 'node:child_process';
import {StringDecoder} from 'node:string_decoder';

export class InsightCommandError extends Error {
  constructor(readonly rpc:{code:number;message:string;data?:unknown}){super(rpc.message);this.name='InsightCommandError';}
}
export class InsightTransportError extends Error {
  constructor(message:string,readonly dispatched:boolean){super(message);this.name='InsightTransportError';}
}
export interface InsightConnectionOptions {
  executable:string;
  /** For example [installedBin] with executable: process.execPath. No shell is used. */
  arguments?:readonly string[];
  cwd?:string;
  env?:NodeJS.ProcessEnv;
}
export interface InsightConnection {
  execute<T=unknown>(argv:readonly string[]):Promise<T>;
  /** Drain admitted requests, then end this transport. Does not stop the owner or Ghidra. */
  close():Promise<void>;
}
/** A thin client of Factory's existing stream, with no reconnect or command replay. */
export async function connectInsight(options:InsightConnectionOptions):Promise<InsightConnection> {
  const child:ChildProcessWithoutNullStreams=spawn(options.executable,[...(options.arguments??[]),'--json-rpc'],{cwd:options.cwd,env:options.env,stdio:['pipe','pipe','pipe'],shell:false});
  const maximum=4*1024**2,decoder=new StringDecoder('utf8');let buffer='',bytes=0,sequence=0,accepting=true,failed=false,ended=false;
  let closePromise:Promise<void>|undefined,tail:Promise<unknown>=Promise.resolve();
  const pending=new Map<number,{resolve:(v:unknown)=>void;reject:(e:unknown)=>void}>();
  // Drain diagnostics without retaining arbitrary stderr, paths, tokens or unbounded output.
  child.stderr.resume();
  const fail=(message:string)=>{
    if(failed)return;failed=true;accepting=false;
    for(const p of pending.values())p.reject(new InsightTransportError(message,true));pending.clear();
    child.stdin.destroy();child.stdout.destroy();
  };
  child.on('error',()=>fail('Persistent CLI process failed.'));
  child.stdout.on('error',()=>fail('Persistent CLI output was lost.'));
  child.stderr.on('error',()=>fail('Persistent CLI diagnostic stream was lost.'));
  child.stdin.on('error',()=>fail('Persistent CLI input was lost; inspect request/status before retrying a changing command.'));
  const exited=new Promise<void>((resolve,reject)=>{
    child.once('close',(code,signal)=>{
      ended=true;
      if(code!==0||signal||pending.size||buffer.trim()){fail('Persistent CLI closed without a complete acknowledged response.');reject(new InsightTransportError('Persistent CLI transport ended unexpectedly.',false));}
      else if(failed)reject(new InsightTransportError('Persistent CLI transport failed.',false));else resolve();
    });
  });void exited.catch(()=>{});
  child.stdout.on('data',(chunk:Buffer)=>{
    if(failed)return;buffer+=decoder.write(chunk);bytes+=chunk.length;
    if(bytes>maximum){fail('Persistent CLI response exceeded the bounded transport limit.');return;}
    for(;;){const newline=buffer.indexOf('\n');if(newline<0)break;const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);bytes=Buffer.byteLength(buffer);
      if(!line.trim())continue;
      try{
        const r=JSON.parse(line) as {jsonrpc?:unknown;id?:unknown;result?:unknown;error?:{code:number;message:string;data?:unknown}};
        if(!r||r.jsonrpc!=='2.0'||typeof r.id!=='number'||!pending.has(r.id)||Object.hasOwn(r,'result')===Object.hasOwn(r,'error'))throw Error();
        const p=pending.get(r.id)!;
        if(Object.hasOwn(r,'error')&&(!r.error||typeof r.error!=='object'||typeof r.error.code!=='number'||!Number.isInteger(r.error.code)||typeof r.error.message!=='string'))throw Error();
        pending.delete(r.id);
        if(r.error)p.reject(new InsightCommandError(r.error));else p.resolve(r.result);
      }catch{fail('Persistent CLI returned a malformed or uncorrelated response.');return;}
    }
  });
  await new Promise<void>((resolve,reject)=>{child.once('spawn',resolve);child.once('error',()=>reject(new InsightTransportError('Could not start persistent CLI.',false)));});
  return {
    execute<T=unknown>(argv:readonly string[]):Promise<T>{
      if(!Array.isArray(argv)||argv.length>512||argv.some(x=>typeof x!=='string'||x.includes('\0'))||Buffer.byteLength(JSON.stringify(argv))>1024**2)return Promise.reject(new TypeError('argv must be a bounded array of strings without NUL.'));
      if(!accepting||failed||ended)return Promise.reject(new InsightTransportError('Persistent CLI connection is closed.',false));
      const args=[...argv];
      const request=tail.then(()=>{
        if(failed||ended)throw new InsightTransportError('Persistent CLI connection was lost before dispatch.',false);
        const id=++sequence;
        return new Promise<unknown>((resolve,reject)=>{
          pending.set(id,{resolve,reject});
          try{child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method:'cli.execute',params:{argv:args}})+'\n');}
          catch{fail('Persistent CLI input was lost; inspect request/status before retrying a changing command.');}
        });
      });
      tail=request.catch(()=>{});return request as Promise<T>;
    },
    close(){
      accepting=false;
      return closePromise??=tail.then(async()=>{if(!failed&&!ended)child.stdin.end();await exited;});
    }
  };
}
