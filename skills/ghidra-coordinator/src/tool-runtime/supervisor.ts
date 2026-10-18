import {spawn,type ChildProcess,type SpawnOptions} from 'node:child_process';
import {access,mkdir,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,isAbsolute,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {Writable} from 'node:stream';
import {setTimeout as delay} from 'node:timers/promises';
import {CliError} from '@eyeauras/cli-factory';
import {atomicWrite,readJson,toolRoot,withToolLock} from './store.js';
import {processIdentity} from './identity.js';
import {javaClasspathArguments} from './java-arguments.js';
import {digest} from '../model.js';
import type {ToolProcess} from './definition.js';
export interface ProcessRecord extends ToolProcess {
 root:string;ownerPid:number;profileBinding:string;phase?:string;strongIdentity?:boolean;processGroup?:number;gated:boolean;
 metadata?:Record<string,unknown>;outcome?:string;requestedStop?:'stop'|'kill';launchError?:string;
}
export interface ProcessSpec {tool:string;role:string;installation:string;session?:string;target?:string;metadata?:Record<string,unknown>}
interface Owned {child:ChildProcess;closed:Promise<void>;record:ProcessRecord}
const owned=new Map<string,Owned>();
const ownedKey=(directory:string,id:string)=>resolve(directory)+'\0'+id;
export interface TrackedChild extends ChildProcess {toolProcessId:string;toolClosed:Promise<void>}
export type OwnershipVerifier=(record:ProcessRecord)=>Promise<boolean|undefined>;
/** Receipts report pending lifetime only; they never authorize a signal to another PID. */
async function nativeChildren(record:ProcessRecord){
 if(record.metadata?.nativeChildDeadlines!==true)return [];
 let names:string[];try{names=await readdir(join(record.root,'native-deadlines'));}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return [];throw e;}
 if(names.length>100)throw new CliError('Native helper receipt count exceeds its bound.',{code:'tool.process.unverified'});
 return Promise.all(names.map(async name=>{
  const value=await readJson<{protocol:number;pid:number;parentPid:number;birthSeconds:number;birthMicroseconds:number;deadlineUnixSeconds:number}>(join(record.root,'native-deadlines',name));
  if(!/^\d+\.json$/.test(name)||!value||value.protocol!==1||!Number.isSafeInteger(value.pid)||value.pid<1||value.pid>2147483647||name!==value.pid+'.json'||!Number.isSafeInteger(value.parentPid)||value.parentPid<1||!Number.isSafeInteger(value.birthSeconds)||value.birthSeconds<1||!Number.isSafeInteger(value.birthMicroseconds)||value.birthMicroseconds<0||value.birthMicroseconds>=1000000||!Number.isSafeInteger(value.deadlineUnixSeconds)||value.deadlineUnixSeconds<=0)throw new CliError('Native helper receipt is invalid; no cleanup was assumed.',{code:'tool.process.unverified'});
  const receiptDigest=digest(value),acknowledgment=join(record.root,'native-deadline-exits',name),previous=await readJson<{receiptDigest:string}>(acknowledgment);
  if(previous?.receiptDigest===receiptDigest)return {...value,state:'exited'};
  const identity=await processIdentity(value.pid),seconds=identity&&process.platform==='darwin'?Date.parse(identity.birth+' GMT')/1000:NaN;
  // A different observable birth proves reuse, without granting permission to signal that PID.
  const exited=!identity||Number.isFinite(seconds)&&seconds!==value.birthSeconds;
  if(exited)await atomicWrite(acknowledgment,{receiptDigest,observedAt:new Date().toISOString()});
  return {...value,state:exited?'exited':'pending'};
 }));
}
export async function launchProcess(directory:string,spec:ProcessSpec,executable:string,args:string[],options:SpawnOptions={},control:{id?:string;finalize?:boolean;onSpawn?:(child:TrackedChild)=>void|Promise<void>;signal?:AbortSignal}={}):Promise<TrackedChild>{
 return withToolLock(directory,spec.tool,async()=>{
  control.signal?.throwIfAborted();toolRoot(directory,spec.tool);if(!isAbsolute(executable))throw new CliError('Tool executable must be absolute.',{code:'tool.configuration'});
  const id=control.id??randomUUID();if(!/^[a-f0-9-]{36}$/.test(id))throw Error('Invalid process identity');
  const root=join(directory,'runtime/runs',id),path=join(directory,'runtime/processes',id+'.json');await mkdir(root,{recursive:true,mode:0o700});
  const gated=process.platform!=='win32'&&typeof process.execve==='function';
  const record:ProcessRecord={schema:1,id,...spec,state:'starting',executable,root,ownerPid:process.pid,profileBinding:digest(resolve(directory)),gated,phase:'reserved',createdAt:new Date().toISOString()};
  await atomicWrite(path,record);try{control.signal?.throwIfAborted();await access(executable,process.platform==='win32'?constants.F_OK:constants.X_OK);}catch(error){Object.assign(record,{state:'failed',phase:'preflight_failed'});await atomicWrite(path,record);throw error;}
  const environment=options.env??{PATH:process.env.PATH,HOME:root,TMPDIR:root};
  const stdio=Array.isArray(options.stdio)?[...options.stdio]:Array(3).fill(options.stdio??'pipe'),fd=stdio.length,nonce=randomUUID();if(gated)stdio.push('pipe');
  let child:TrackedChild;try{args=await javaClasspathArguments(root,spec.tool,executable,args);control.signal?.throwIfAborted();child=spawn(gated?process.execPath:executable,gated?['--no-warnings',fileURLToPath(new URL('./launch-worker.js',import.meta.url)),directory,id,String(fd)]:args,
   {cwd:root,...options,stdio,windowsHide:true,env:gated?{PATH:environment.PATH,HOME:root,TMPDIR:root}:environment}) as TrackedChild;}catch(error){Object.assign(record,{state:'failed',phase:'spawn_failed'});await atomicWrite(path,record);throw error;}
  const closed=new Promise<void>((ok,bad)=>{child.on('error',error=>{if(!child.pid)bad(error);});child.once('close',ok);});void closed.catch(()=>{});
  const handle:Owned={child,closed,record};owned.set(ownedKey(directory,id),handle);
  const finalized=control.finalize===false?closed:closed.then(async()=>{
   const current=await readJson<ProcessRecord>(path)??record;
   if(current.state!=='failed'&&current.state!=='unverified')Object.assign(current,{state:'exited',exitCode:child.exitCode,signal:child.signalCode,endedAt:new Date().toISOString(),outcome:current.requestedStop==='kill'?'killed':current.requestedStop==='stop'?'stopped':'completed'});
   await atomicWrite(path,current);
  },async()=>{Object.assign(record,{state:'failed',phase:'spawn_failed'});await atomicWrite(path,record);});
  handle.closed=finalized.finally(()=>{owned.delete(ownedKey(directory,id));});void handle.closed.catch(()=>{});
  Object.assign(child,{toolProcessId:id,toolClosed:handle.closed});
  try{
   await control.onSpawn?.(child);if(!child.pid)throw Error('Owned tool spawn did not obtain a PID');
   if(gated){
    const channel=child.stdio[fd] as Writable;channel.on('error',()=>{});channel.end(JSON.stringify({executable,arguments:args,environment:Object.fromEntries(Object.entries(environment).filter(([,v])=>v!==undefined)),nonce}));
    let armed=false;
    for(let i=0;i<400;i++){
     control.signal?.throwIfAborted();const ready=await readJson<{pid:number;nonce:string}>(join(root,'armed.json'));
     if(ready&&ready.pid===child.pid&&ready.nonce===nonce){armed=true;break;}
     if(child.exitCode!==null||child.signalCode!==null)break;await delay(25);
    }
    if(!armed)throw Error('Owned launch did not become armed');
    Object.assign(record,await readJson(path),{state:'running',phase:'exec_authorized'});await atomicWrite(path,record);await atomicWrite(join(root,'go.json'),{nonce});
   }else{
    if(!child.pid)throw Error('No child process');const identity=await processIdentity(child.pid);Object.assign(record,{pid:child.pid,identity:identity?.birth,strongIdentity:identity?.strong,processGroup:identity?.group,state:'running',phase:'direct_child_only'});await atomicWrite(path,record);
   }
   return child;
  }catch(error){
   if(child.exitCode===null&&child.signalCode===null)try{child.kill('SIGKILL');}catch{}
   await Promise.race([handle.closed.catch(()=>{}),delay(2000)]);
   Object.assign(record,{state:child.exitCode!==null||child.signalCode!==null?'failed':'unverified',phase:'launch_failed'});await atomicWrite(path,record);throw error;
  }
 },control.signal);
}
export async function processStatus(directory:string,id:string,verify?:OwnershipVerifier):Promise<ProcessRecord>{
 if(!/^[a-f0-9-]{36}$/.test(id))throw new CliError('Invalid process identity.',{code:'tool.process.invalid'});
 const record=await readJson<ProcessRecord>(join(directory,'runtime/processes',id+'.json'));if(!record||record.id!==id)throw new CliError('Unknown tool process.',{code:'tool.process.missing'});
 if(record.root!==join(directory,'runtime/runs',id)||record.profileBinding!==digest(resolve(directory)))return {...record,state:'unverified',phase:'profile_binding_changed'};
 const finishing=owned.get(ownedKey(directory,id));if(finishing&&(finishing.child.exitCode!==null||finishing.child.signalCode!==null)){await finishing.closed;return processStatus(directory,id,verify);}
 let children:Awaited<ReturnType<typeof nativeChildren>>;
 try{children=await nativeChildren(record);}catch{return {...record,state:'unverified',phase:'native_children_unverified'};}
 const pending=children.some(c=>c.state==='pending');
 const observed={...record,...(children.length?{nativeChildren:children}:{})};
 if(['exited','failed'].includes(record.state))return pending?{...observed,state:'unverified',phase:'native_children_pending'}:observed;
 if(!record.pid){
  try{process.kill(record.ownerPid,0);return record;}catch{return {...record,state:record.gated?'failed':'unverified',phase:'owner_lost_before_pid'};}
 }
 const identity=await processIdentity(record.pid);if(!identity)return {...observed,state:pending?'unverified':'exited',phase:pending?'native_children_pending':'observed_exit',outcome:'unknown'};
 if(identity.birth!==record.identity)return {...record,state:'unverified',phase:'pid_identity_changed'};
 const current=owned.get(ownedKey(directory,id)),local=current?.child.pid===record.pid&&current.record.identity===record.identity&&current.child.exitCode===null&&current.child.signalCode===null;
 const proof=verify?await verify(record):undefined;
 if(local||proof===true||proof===undefined&&record.strongIdentity&&identity.strong)return {...observed,state:'running'};
 return {...observed,state:'unverified',phase:'tool_identity_required'};
}
export async function listProcesses(directory:string,filter:{tool?:string;session?:string;target?:string}={},verify?:OwnershipVerifier){
 let names:string[];try{names=await readdir(join(directory,'runtime/processes'));}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return [];throw e;}
 const items:ProcessRecord[]=[];
 for(const name of names){if(!/^[a-f0-9-]{36}\.json$/.test(name))continue;const record=await processStatus(directory,name.slice(0,-5),verify);
  if(filter.tool&&record.tool!==filter.tool||filter.session&&record.session!==filter.session||filter.target&&record.target!==filter.target)continue;items.push(record);
 }
 return items.sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
}
export async function terminateProcess(directory:string,id:string,force:boolean,verify?:OwnershipVerifier,graceful?:(record:ProcessRecord)=>Promise<void>){
 const path=join(directory,'runtime/processes',id+'.json'),record=await processStatus(directory,id,verify);
 if(['exited','failed'].includes(record.state))return {process:id,state:'already_exited'};
 if(record.state!=='running'||!record.pid)throw new CliError('Process ownership is unverified; no signal was sent.',{code:'tool.process.unverified'});
 if(!force&&graceful)await graceful(record);
 let current=await processStatus(directory,id,verify);
 if(!['exited','failed'].includes(current.state)){
  if(current.state!=='running'||current.pid!==record.pid)throw new CliError('Process identity changed during stop.',{code:'tool.process.unverified'});
  current.requestedStop=force?'kill':'stop';await atomicWrite(path,current);
  const identity=await processIdentity(record.pid);if(!identity||identity.birth!==record.identity)throw new CliError('Process identity changed before signalling.',{code:'tool.process.unverified'});
  try{if(process.platform!=='win32'&&record.processGroup===record.pid&&identity.group===record.pid)process.kill(-record.pid,force?'SIGKILL':'SIGTERM');else process.kill(record.pid,force?'SIGKILL':'SIGTERM');}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ESRCH')throw error;}
  for(let i=0;i<100;i++){if(!await processIdentity(record.pid))break;await delay(50);}
  if(await processIdentity(record.pid))throw new CliError('Owned process did not stop; its record is retained.',{code:'tool.process.busy'});
 }
 await owned.get(ownedKey(directory,id))?.closed;
 current={...(await readJson<ProcessRecord>(path)??record),state:'exited',outcome:force?'killed':'stopped',endedAt:new Date().toISOString()};await atomicWrite(path,current);
 return {process:id,state:force?'killed':'stopped',interrupted:force,tool:record.tool,session:record.session,target:record.target};
}
/** Migration/reconnection only: an adapter must authenticate a known existing tool before registration. */
export async function registerExistingProcess(directory:string,spec:ProcessSpec,executable:string,pid:number,verify:OwnershipVerifier):Promise<string>{
 toolRoot(directory,spec.tool);const identity=await processIdentity(pid);if(!identity)throw new CliError('Existing tool process has exited.',{code:'tool.process.missing'});
 const hex=digest({profile:resolve(directory),...spec,pid,identity:identity.birth}).slice(0,32),id=[hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
 const root=join(directory,'runtime/runs',id),path=join(directory,'runtime/processes',id+'.json');
 const record:ProcessRecord={schema:1,id,...spec,root,ownerPid:process.pid,profileBinding:digest(resolve(directory)),gated:false,state:'running',phase:'adopted_verified',createdAt:new Date().toISOString(),executable,pid,identity:identity.birth,strongIdentity:identity.strong,processGroup:identity.group};
 if(!await verify(record))throw new CliError('Existing process did not authenticate as the owned tool.',{code:'tool.process.unverified'});
 if((await processIdentity(pid))?.birth!==identity.birth)throw new CliError('Existing process identity changed during registration.',{code:'tool.process.unverified'});
 const previous=await readJson<ProcessRecord>(path);if(previous)return id;
 await mkdir(root,{recursive:true,mode:0o700});await atomicWrite(path,record);return id;
}
