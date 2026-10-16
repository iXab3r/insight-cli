import {spawn,type ChildProcess} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,isAbsolute} from 'node:path';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {CliError,type CommandContext} from '@eyeauras/cli-factory';
import {atomicWrite,withToolUse,toolRoot} from './store.js';
import type {ToolProcess} from './definition.js';
export interface RunSpec {
 tool:string;role:string;installation?:string;executable:string;arguments?:string[];
 environment?:Record<string,string|undefined>;cwd?:string;input?:string;
 timeoutMs?:number;maxOutputBytes?:number;acceptedCodes?:number[];session?:string;target?:string;
}
export interface RunResult {process:string;stdout:string;stderr:string;exitCode:number|null;signal:string|null;elapsedMs:number;truncated:boolean;diagnostics:string}
export interface RunContext {appArguments:Pick<CommandContext['appArguments'],'AppDataDirectory'>;signal:AbortSignal;environment:CommandContext['environment']}
export async function runTool(c:RunContext,spec:RunSpec):Promise<RunResult>{
 c.signal.throwIfAborted();const directory=c.appArguments.AppDataDirectory;toolRoot(directory,spec.tool);
 if(!isAbsolute(spec.executable))throw new CliError('Tool executable must be an absolute path.',{code:'tool.configuration'});
 const id=randomUUID(),root=join(directory,'runtime/runs',id),path=join(directory,'runtime/processes',id+'.json');
 const started=performance.now(),limit=spec.maxOutputBytes??4*1024**2;let child:ChildProcess|undefined,outcome:string|undefined,truncated=false,bytes=0;
 const stdout:Buffer[]=[],stderr:Buffer[]=[],record:ToolProcess&{root:string;ownerPid:number;outcome?:string;terminationError?:string}={schema:1,id,tool:spec.tool,role:spec.role,installation:spec.installation??'probe',state:'starting',executable:spec.executable,createdAt:new Date().toISOString(),root,ownerPid:process.pid,...(spec.session?{session:spec.session}:{}),...(spec.target?{target:spec.target}:{})};
 const lease=await withToolUse(directory,spec.tool,async()=>{await mkdir(root,{recursive:true,mode:0o700});await atomicWrite(path,record);});
 const environment={PATH:c.environment.PATH??process.env.PATH,HOME:root,TMPDIR:root,...spec.environment};
 const secrets=Object.entries(environment).filter(([key,value])=>/TOKEN|PASSWORD|SECRET|KEY/i.test(key)&&value&&value.length>=4).map(([,v])=>v!);
 const redact=(value:string)=>secrets.reduce((text,secret)=>text.split(secret).join('[redacted]'),value);
 let timer:NodeJS.Timeout|undefined,force:NodeJS.Timeout|undefined,drain:NodeJS.Timeout|undefined,hard:NodeJS.Timeout|undefined,settled=false,abandon:((error:Error)=>void)|undefined;
 const signal=(name:NodeJS.Signals)=>{
  if(!child?.pid||settled)return;
  try{if(process.platform!=='win32')process.kill(-child.pid,name);else if(child.exitCode===null&&child.signalCode===null)child.kill(name);}catch(e){if((e as NodeJS.ErrnoException).code==='ESRCH')return;record.terminationError=(e as NodeJS.ErrnoException).code??'signal_failed';if(child.exitCode===null&&child.signalCode===null)try{child.kill(name);}catch{}}
 };
 const stop=(reason:string)=>{if(settled)return;outcome??=reason;signal('SIGTERM');force??=setTimeout(()=>{signal('SIGKILL');hard=setTimeout(()=>{if(settled)return;outcome='termination_unverified';record.state='unverified';child?.stdin?.destroy();child?.stdout?.destroy();child?.stderr?.destroy();child?.unref();abandon?.(new Error('termination_unverified'));},1000);hard.unref();},1000);force.unref();};
 const aborted=()=>stop('cancelled');
 try{
  c.signal.throwIfAborted();
  child=spawn(spec.executable,spec.arguments??[],{cwd:spec.cwd??root,env:environment,windowsHide:true,detached:process.platform!=='win32',stdio:['pipe','pipe','pipe']});
  const closed=new Promise<void>((ok,bad)=>{abandon=bad;child!.once('error',bad);child!.once('close',()=>{settled=true;ok();});});void closed.catch(()=>{});
  child.once('exit',()=>{drain=setTimeout(()=>stop('background_output'),300);drain.unref();});
  const capture=(chunks:Buffer[],b:Buffer)=>{const available=Math.max(0,limit-bytes);if(available)chunks.push(Buffer.from(b.subarray(0,available)));bytes+=b.length;if(bytes>limit){truncated=true;stop('output_limit');}};
  child.stdout!.on('data',b=>capture(stdout,b));child.stderr!.on('data',b=>capture(stderr,b));child.stdin!.on('error',()=>{});child.stdin!.end(spec.input);
  record.pid=child.pid;record.state='running';await atomicWrite(path,record);
  c.signal.addEventListener('abort',aborted,{once:true});if(c.signal.aborted)aborted();
  timer=setTimeout(()=>stop('timeout'),spec.timeoutMs??120000);timer.unref();
  await closed;
  if(!outcome&&(child.exitCode===null||!(spec.acceptedCodes??[0]).includes(child.exitCode)))outcome='exit_code';
  const result:RunResult={process:id,stdout:redact(Buffer.concat(stdout).toString('utf8')),stderr:redact(Buffer.concat(stderr).toString('utf8')),exitCode:child.exitCode,signal:child.signalCode,elapsedMs:Math.round(performance.now()-started),truncated,diagnostics:root};
  await writeFile(join(root,'stdout.log'),result.stdout,{mode:0o600});await writeFile(join(root,'stderr.log'),result.stderr,{mode:0o600});
  Object.assign(record,{state:outcome?'failed':'exited',outcome:outcome??'completed',exitCode:result.exitCode,signal:result.signal,elapsedMs:result.elapsedMs,endedAt:new Date().toISOString()});await atomicWrite(path,record);
  if(outcome)throw new CliError('Tool execution did not complete successfully: '+outcome+'.',{code:'tool.'+outcome.replaceAll('_','.'),result});
  return result;
 }catch(error){
  if(child&&!settled&&record.state!=='unverified'){stop('failed');await new Promise<void>(ok=>{if(settled){ok();return;}child!.once('close',()=>ok());setTimeout(()=>{signal('SIGKILL');ok();},1500).unref();});}
  if(record.state==='starting'||record.state==='running'){Object.assign(record,{state:'failed',outcome:outcome??'launch_failed',endedAt:new Date().toISOString(),elapsedMs:Math.round(performance.now()-started)});await atomicWrite(path,record);}
  if(record.state==='unverified')await atomicWrite(path,record);
  if(error instanceof CliError)throw error;
  if(record.state==='unverified')throw new CliError('Tool termination could not be verified; its process record blocks removal.',{code:'tool.termination.unverified',result:{process:id,diagnostics:root}});
  throw new CliError('Tool launch failed; inspect its retained process record.',{code:'tool.launch',cause:error,result:{process:id,diagnostics:root}});
 }finally{if(timer)clearTimeout(timer);if(force)clearTimeout(force);if(drain)clearTimeout(drain);if(hard)clearTimeout(hard);c.signal.removeEventListener('abort',aborted);lease.release();}
}
