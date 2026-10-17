import {type ChildProcess} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,isAbsolute,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {CliError,type CommandContext} from '@eyeauras/cli-factory';
import {atomicWrite,withToolUse,toolRoot,readJson} from './store.js';
import {launchProcess,type TrackedChild,type ProcessRecord} from './supervisor.js';
import {digest} from '../model.js';
import type {ToolProcess} from './definition.js';
import {deadlineLaunch} from './deadline.js';
import {windowsJobLaunch,windowsJobResult} from './windows-job.js';
export interface RunSpec {
 tool:string;role:string;installation?:string;executable:string;arguments?:string[];
 environment?:Record<string,string|undefined>;cwd?:string;input?:string;
 timeoutMs?:number;maxOutputBytes?:number;outputFile?:string;acceptedCodes?:number[];session?:string;target?:string;
 /** Adapter opt-in only after verifying its native signal/child cleanup contract. */
 nativeDeadline?:boolean;
 /** Adapter's native helper constructor persists per-exec deadline receipts in the run root. */
 nativeChildDeadlines?:boolean;
 /** Hold an authenticated borrowed Windows subject handle; never assign it to the owned job. */
 observedSubject?:{pid:number;birth:string};
 /** Serialize the native singleton without introducing another service. */
 nativeMutex?:'procmon';
 /** Private process-local HKCU for the admitted ProcMon child. */
 nativeRegistry?:'procmon';
 /** Owned temporary DOS path for a pinned vendor loader that still marshals ANSI filenames. */
 nativeAsciiPath?:'dnspy';
 metadata?:Record<string,unknown>;
}
export interface RunResult {process:string;stdout:string;stderr:string;exitCode:number|null;signal:string|null;elapsedMs:number;truncated:boolean;diagnostics:string}
export interface RunContext {appArguments:Pick<CommandContext['appArguments'],'AppDataDirectory'>;signal:AbortSignal;environment:CommandContext['environment']}
export async function runTool(c:RunContext,spec:RunSpec):Promise<RunResult>{
 c.signal.throwIfAborted();const directory=c.appArguments.AppDataDirectory;toolRoot(directory,spec.tool);
 if(!isAbsolute(spec.executable))throw new CliError('Tool executable must be an absolute path.',{code:'tool.configuration'});
 if((spec.observedSubject||spec.nativeMutex||spec.nativeRegistry||spec.nativeAsciiPath)&&(!spec.nativeDeadline||process.platform!=='win32'))throw new CliError('Native subject/mutex/registry binding requires an owned Windows job.',{code:'tool.configuration'});
 if(spec.nativeChildDeadlines&&!spec.nativeDeadline)throw new CliError('Native child deadlines require the native collector deadline.',{code:'tool.configuration'});
 let launch={executable:spec.executable,arguments:spec.arguments??[]};
 const id=randomUUID(),root=join(directory,'runtime/runs',id),path=join(directory,'runtime/processes',id+'.json');
 const started=performance.now(),limit=spec.maxOutputBytes??4*1024**2;let child:ChildProcess|undefined,outcome:string|undefined,truncated=false,bytes=0;
 const stdout:Buffer[]=[],stderr:Buffer[]=[],record:ProcessRecord&{terminationError?:string}={schema:1,id,tool:spec.tool,role:spec.role,installation:spec.installation??'probe',state:'starting',executable:spec.executable,createdAt:new Date().toISOString(),root,ownerPid:process.pid,profileBinding:digest(resolve(directory)),gated:process.platform!=='win32'&&typeof process.execve==='function',phase:'reserved',...(spec.session?{session:spec.session}:{}),...(spec.target?{target:spec.target}:{})};
 const lease=await withToolUse(directory,spec.tool,async()=>{await mkdir(root,{recursive:true,mode:0o700});},c.signal);
 const environment={PATH:c.environment.PATH??process.env.PATH,HOME:root,TMPDIR:root,...(process.platform==='win32'?{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,ComSpec:process.env.ComSpec,TEMP:root,TMP:root,USERPROFILE:root,LOCALAPPDATA:root,APPDATA:root}:{}),...spec.environment};
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
  if(spec.nativeDeadline)launch=process.platform==='win32'?await windowsJobLaunch(root,id,spec.executable,spec.arguments??[],spec.cwd??root,spec.timeoutMs??120000,{observedSubject:spec.observedSubject,nativeMutex:spec.nativeMutex,nativeRegistry:spec.nativeRegistry,nativeAsciiPath:spec.nativeAsciiPath}):await deadlineLaunch(spec.executable,spec.arguments??[],spec.timeoutMs??120000);
  child=await launchProcess(directory,{tool:spec.tool,role:spec.role,installation:spec.installation??'probe',session:spec.session,target:spec.target,...(spec.metadata||spec.nativeDeadline?{metadata:{...spec.metadata,...(spec.observedSubject?{observedSubject:spec.observedSubject}:{}),...(spec.nativeMutex?{nativeMutex:spec.nativeMutex}:{}),...(spec.nativeRegistry?{nativeRegistry:spec.nativeRegistry,nativeAsciiPath:spec.nativeAsciiPath}:{}),...(spec.nativeDeadline?{nativeDeadlineSeconds:Math.ceil((spec.timeoutMs??120000)/1000),nativeExecutable:spec.executable,...(spec.nativeChildDeadlines?{nativeChildDeadlines:true}:{})}:{})}}:{})},launch.executable,launch.arguments,
   {cwd:spec.cwd??root,env:environment,windowsHide:true,detached:process.platform!=='win32',stdio:['pipe','pipe','pipe']},
   {id,finalize:false,signal:c.signal,onSpawn:launched=>{
    child=launched;child.once('close',()=>{settled=true;});
    child.once('exit',()=>{drain=setTimeout(()=>stop('background_output'),300);drain.unref();});
    const capture=(chunks:Buffer[],b:Buffer)=>{const available=Math.max(0,limit-bytes);if(available)chunks.push(Buffer.from(b.subarray(0,available)));bytes+=b.length;if(bytes>limit){truncated=true;stop('output_limit');}};
    child.stdout!.on('data',b=>capture(stdout,b));child.stderr!.on('data',b=>capture(stderr,b));child.stdin!.on('error',()=>{});child.stdin!.end(spec.input);
    c.signal.addEventListener('abort',aborted,{once:true});if(c.signal.aborted)aborted();
    timer=setTimeout(()=>stop('timeout'),spec.timeoutMs??120000);timer.unref();
   }});
  await Promise.race([(child as TrackedChild).toolClosed,new Promise<never>((_ok,bad)=>{abandon=bad;})]);settled=true;Object.assign(record,await readJson(path));
  if((record as ToolProcess&{launchError?:string}).launchError)outcome='launch_failed';
  let exitCode=child.exitCode;
  if(spec.nativeDeadline&&process.platform==='win32'&&!outcome){
   try{const job=await windowsJobResult(root,id,child.pid!,Boolean(spec.nativeRegistry));exitCode=job.childExitCode;Object.assign(record,{windowsJob:job});if(job.phase!=='completed')outcome=job.phase;}catch{outcome='job_result_unverified';}
  }
  if(!outcome&&spec.nativeDeadline&&child.signalCode==='SIGALRM')outcome='timeout';
  if(!outcome&&(exitCode===null||!(spec.acceptedCodes??[0]).includes(exitCode)))outcome='exit_code';
  const result:RunResult={process:id,stdout:redact(Buffer.concat(stdout).toString('utf8')),stderr:redact(Buffer.concat(stderr).toString('utf8')),exitCode,signal:child.signalCode,elapsedMs:Math.round(performance.now()-started),truncated,diagnostics:root};
  await writeFile(join(root,'stdout.log'),result.stdout,{mode:0o600});await writeFile(join(root,'stderr.log'),result.stderr,{mode:0o600});
  Object.assign(record,{state:outcome?'failed':'exited',outcome:outcome??'completed',exitCode:result.exitCode,signal:result.signal,elapsedMs:result.elapsedMs,endedAt:new Date().toISOString()});await atomicWrite(path,record);
  if(outcome)throw new CliError('Tool execution did not complete successfully: '+outcome+'.',{code:'tool.'+outcome.replaceAll('_','.'),result});
  if(spec.outputFile)try{await writeFile(spec.outputFile,Buffer.concat(stdout),{flag:'wx',mode:0o600});}
  catch(error){throw new CliError('Tool completed, but its binary output could not be written to a new file.',{code:'tool.output',cause:error,result:{process:id,diagnostics:root}});}
  return result;
 }catch(error){
  const failure=error as Error&{code?:string;cause?:Error};await atomicWrite(join(root,'error.json'),{name:failure.name,code:failure.code,message:redact(failure.message??String(error)),...(failure.cause?{cause:{name:failure.cause.name,message:redact(failure.cause.message)}}:{})});
  if(child&&!settled&&record.state!=='unverified'){stop('failed');await new Promise<void>(ok=>{if(settled){ok();return;}child!.once('close',()=>ok());setTimeout(()=>{signal('SIGKILL');ok();},1500).unref();});}
  Object.assign(record,await readJson(path));if(c.signal.aborted&&!outcome)outcome='cancelled';
  if(record.state==='starting'||record.state==='running'||record.state==='failed'){Object.assign(record,{state:'failed',outcome:outcome??'launch_failed',endedAt:new Date().toISOString(),elapsedMs:Math.round(performance.now()-started)});await atomicWrite(path,record);}
  if(record.state==='unverified')await atomicWrite(path,record);
  if(error instanceof CliError)throw error;
  if(record.state==='unverified')throw new CliError('Tool termination could not be verified; its process record blocks removal.',{code:'tool.termination.unverified',result:{process:id,diagnostics:root}});
  throw new CliError('Tool execution failed; inspect its retained process record.',{code:outcome?'tool.'+outcome.replaceAll('_','.'): 'tool.launch',cause:error,result:{process:id,diagnostics:root}});
 }finally{if(timer)clearTimeout(timer);if(force)clearTimeout(force);if(drain)clearTimeout(drain);if(hard)clearTimeout(hard);c.signal.removeEventListener('abort',aborted);lease.release();}
}
