import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,type ChildProcess} from 'node:child_process';
import {createRequire,syncBuiltinESMExports} from 'node:module';
import fs from 'node:fs/promises';
import {mkdir,mkdtemp,readFile,readdir,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {CliError} from '@eyeauras/cli-factory';
import {runTool,type RunContext} from '../src/tool-runtime/run.js';
import {launchProcess,processStatus,terminateProcess,type ProcessRecord} from '../src/tool-runtime/supervisor.js';
import {assertUnused,toolUseCount} from '../src/tool-runtime/store.js';

const spec={tool:'fixture',role:'startup',installation:'fixture'};
const streamFault=()=>Object.assign(new Error('Disposable output transport failed'),{code:'ENOTCONN'});
function observePipes(child:ChildProcess,observed:{stream:number;code?:string}[]){
 child.stdio.forEach((stream,index)=>{if(!stream)return;const emit=stream.emit;
  // Observe without adding an error listener that would mask the original bug.
  stream.emit=(event:string|symbol,...values:any[])=>{if(event==='error')observed.push({stream:index,code:(values[0] as NodeJS.ErrnoException).code});return emit.call(stream,event,...values);};
 });
}
async function records(root:string){
 return Promise.all((await readdir(join(root,'runtime/processes'))).map(async name=>JSON.parse(await readFile(join(root,'runtime/processes',name),'utf8')) as ProcessRecord));
}
async function followup(c:RunContext){
 const result=await runTool(c,{...spec,executable:process.execPath,arguments:['-e','process.stdout.write(Buffer.from([0,255,128,13,10]));process.stderr.write(process.env.FIXTURE_SECRET)'],environment:{FIXTURE_SECRET:'synthetic-startup-secret'},retainRawOutput:true,timeoutMs:10000});
 assert.equal(result.exitCode,0);assert.equal(result.truncated,false);assert.equal(result.stderr,'[redacted]');
 assert.deepEqual(await readFile(result.rawStdout!),Buffer.from([0,255,128,13,10]));
 assert.equal(await readFile(result.rawStderr!,'utf8'),'synthetic-startup-secret');
 assert.equal(await readFile(join(result.diagnostics,'stderr.log'),'utf8'),'[redacted]');
 const record=await processStatus(c.appArguments.AppDataDirectory,result.process);assert.equal(record.state,'exited');assert.equal(record.outcome,'completed');
 assert.equal(toolUseCount(c.appArguments.AppDataDirectory,'fixture'),0);await assertUnused(c.appArguments.AppDataDirectory,'fixture');
 return result.process;
}

// Each case owns a real Node subprocess. An unhandled pipe error must fail the
// owner-exit assertion, rather than being hidden by a test-level error listener.
async function exercise(mode:string,root:string){
 const c={appArguments:{AppDataDirectory:root},signal:new AbortController().signal,environment:{PATH:process.env.PATH}} as RunContext;
 if(mode==='missing-cwd'||mode==='long-cwd'){
  const cwd=mode==='missing-cwd'?join(root,'absent'):join(root,'x'.repeat(273-root.length-1));
  if(mode==='long-cwd'){assert.equal(cwd.length,273);await mkdir(cwd);}
  let failure:CliError|undefined;
  await assert.rejects(runTool(c,{...spec,executable:process.execPath,arguments:['-e','process.stdout.write("must-not-execute")'],cwd,timeoutMs:10000}),error=>{
   assert.ok(error instanceof CliError);failure=error;assert.equal(error.code,'tool.launch');return true;
  });
  const rows=await records(root);assert.equal(rows.length,1);const record=rows[0]!;
  assert.equal(record.state,'failed');assert.equal(record.phase,'launch_failed');assert.equal(record.launchError,'ENOENT');assert.equal(record.outcome,'launch_failed');assert.equal(record.pid,undefined);assert.ok(record.endedAt);
  assert.equal((failure!.result as {process:string}).process,record.id);
  const diagnostics=JSON.parse(await readFile(join(record.root,'error.json'),'utf8'));assert.equal(diagnostics.code,'ENOENT');
  assert.equal(await readFile(join(record.root,'stdout.log'),'utf8'),'');
  const next=await followup(c);assert.notEqual(next,record.id);
  return {mode,pid:process.pid,failure:failure!.code,record,next,cwdLength:cwd.length};
 }
 if(mode==='callback-write-fault'||mode==='empty-callback-write-fault'){
  const originalRename=fs.rename;let injected=false,held:ChildProcess|undefined,closed:Promise<void>|undefined;
  const adapter=mode==='callback-write-fault'?Object.assign(new Error('Disposable adapter rejected startup'),{code:'EADAPTER'}):undefined;
  fs.rename=async(from,to)=>{
   if(!injected&&typeof to==='string'&&dirname(to)===join(root,'runtime/processes')){
    const receipt=JSON.parse(await readFile(from,'utf8'));
    if(receipt.phase==='launch_failed'){injected=true;throw Object.assign(new Error('Disposable failure-receipt write refused once'),{code:'EIO'});}
   }
   return originalRename(from,to);
  };syncBuiltinESMExports();
  try{
   await assert.rejects(launchProcess(root,spec,process.execPath,['-e','setTimeout(()=>{},15000)'],{stdio:'pipe'},{onSpawn:async child=>{
    held=child;closed=child.toolClosed;await delay(25);throw adapter;
   }}),error=>(error as NodeJS.ErrnoException).code==='EIO');
   assert.ok(injected);assert.ok(closed);await closed;
   const record=(await records(root))[0]!;assert.equal(record.state,'failed');assert.equal(record.phase,'launch_failed');assert.equal(record.outcome,'launch_failed');assert.equal(record.launchError,adapter?.code??'launch');assert.ok(record.endedAt);
   await assertUnused(root,'fixture');const next=await followup(c);return {mode,pid:process.pid,injected,record,next};
  }finally{fs.rename=originalRename;syncBuiltinESMExports();if(held&&held.exitCode===null&&held.signalCode===null)held.kill('SIGKILL');await closed;}
 }
 if(mode==='adapter-gap'){
  let child:ChildProcess|undefined;const observed:{stream:number;code?:string}[]=[];
  try{
   await assert.rejects(launchProcess(root,spec,process.execPath,['-e','setTimeout(()=>{},15000)'],{stdio:'pipe'},{onSpawn:async launched=>{
    child=launched;observePipes(launched,observed);await delay(25);
    // Include the POSIX exec-gate pipe, when present, while the adapter is awaiting.
    for(const stream of launched.stdio.slice(1))stream?.destroy(streamFault());
    await delay(25);
   }}),/Disposable output transport failed/);
   assert.ok(observed.length>=2);const record=(await records(root))[0]!;assert.equal(record.state,'failed');assert.equal(record.launchError,'ENOTCONN');assert.equal(record.outcome,'launch_failed');
   await assertUnused(root,'fixture');const next=await followup(c);return {mode,pid:process.pid,observed,record,next};
  }finally{if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');}
 }
 const uncertain=mode.startsWith('unverified');
 const cp=createRequire(import.meta.url)('node:child_process') as {spawn:typeof spawn},original=cp.spawn;
 let held:ChildProcess|undefined,kill:ChildProcess['kill']|undefined,closed:Promise<void>|undefined,armed=true,signals=0;
 const observed:{stream:number;code?:string}[]=[];
 cp.spawn=((...args:Parameters<typeof spawn>)=>{
  const child=original(...args);
  if(armed){
   armed=false;held=child;kill=child.kill.bind(child);closed=new Promise<void>(ok=>child.once('close',()=>ok()));
   child.kill=((...args:Parameters<ChildProcess['kill']>)=>{signals++;return uncertain?false:kill!(...args);}) as ChildProcess['kill'];
   observePipes(child,observed);
   if(mode==='unverified')queueMicrotask(()=>{child.stdout!.destroy(streamFault());child.stderr!.destroy(streamFault());});
   else child.stdout!.once('data',()=>queueMicrotask(()=>child.stdout!.destroy(streamFault())));
  }
  return child;
 }) as typeof spawn;
 syncBuiltinESMExports();
 try{
  let failure:CliError|undefined;
  // The output control waits for the durable running receipt, so it also exercises
  // runTool's own bounded cleanup after launchProcess has returned its child.
  const output=mode==='unverified-output'?'const fs=require("node:fs"),p=require("node:path");const timer=setInterval(()=>{const path=p.join(process.cwd(),"../../processes",p.basename(process.cwd())+".json");if(JSON.parse(fs.readFileSync(path,"utf8")).state!=="running")return;clearInterval(timer);setTimeout(()=>process.stdout.write(Buffer.from([0,255,1])),50)},25);':mode==='unverified'?'':'process.stdout.write(Buffer.from([0,255,1]));';
  await assert.rejects(runTool(c,{...spec,executable:process.execPath,arguments:['-e',output+'setTimeout(()=>{},15000)'],retainRawOutput:true,timeoutMs:10000}),error=>{
   assert.ok(error instanceof CliError);failure=error;assert.match(error.code,uncertain?/^tool\.termination\.unverified$/:/^tool\.(launch|launch\.failed)$/);return true;
  });
  assert.ok(held?.pid);assert.ok(observed.some(e=>e.stream===1&&e.code==='ENOTCONN'));
  const record=(await records(root))[0]!;assert.notEqual(record.outcome,'completed');assert.equal(record.state,uncertain?'unverified':'failed');
  if(uncertain){
   assert.equal(held.exitCode,null);assert.equal(held.signalCode,null);assert.equal(record.endedAt,undefined);
   await assert.rejects(assertUnused(root,'fixture'),/unresolved|unverified/);
   if(!record.pid){const before=signals;await assert.rejects(terminateProcess(root,record.id,true),/unverified/);assert.equal(signals,before);}
   if(mode==='unverified-output'){assert.equal(record.pid,held.pid);assert.deepEqual(await readFile(join(record.root,'stdout.bin')),Buffer.from([0,255,1]));}
  }else{
   assert.deepEqual(await readFile(join(record.root,'stdout.bin')),Buffer.from([0,255,1]));
   assert.ok(record.endedAt);await assertUnused(root,'fixture');
   cp.spawn=original;syncBuiltinESMExports();await followup(c);
  }
  assert.equal(toolUseCount(root,'fixture'),0);
  return {mode,pid:process.pid,failure:failure!.code,observed,signals,record};
 }finally{
  cp.spawn=original;syncBuiltinESMExports();
  // Only the exact held child handle supplies cleanup authority in this fixture.
  if(held&&held.exitCode===null&&held.signalCode===null)kill!('SIGKILL');await closed;
 }
}

if(process.argv[2]==='--startup-owner'){
 // Factory has its own IPC lifetime even when bounded cleanup unrefs a child.
 const lifetime=setInterval(()=>{},1000);
 try{const result=await exercise(process.argv[3]!,process.argv[4]!);console.log(JSON.stringify(result));}finally{clearInterval(lifetime);}
}else{
 for(const [mode,name] of [
  ['missing-cwd','a failed spawn is a structured terminal failure and the same owner can run again'],
  ['long-cwd','Windows early ENOTCONN from an existing long cwd cannot crash the owner'],
  ['adapter-gap','the supervisor contains pipe errors during an asynchronous adapter binding'],
  ['callback-write-fault','rejected startup stays failed after its first failure-receipt write is refused'],
  ['empty-callback-write-fault','an empty callback rejection cannot become completed after a receipt-write failure'],
  ['output-fault','a real child output error retains bounded bytes and allows a successful follow-up'],
  ['unverified','a failed launch cannot claim completion or removal authority for a child still alive'],
  ['unverified-output','one-shot cleanup cannot terminalize a live child after an output failure'],
 ])test(name!,{timeout:30000,skip:mode==='long-cwd'&&process.platform!=='win32'},async t=>{
  const root=await mkdtemp(join(tmpdir(),'t135-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const owner=spawn(process.execPath,[fileURLToPath(import.meta.url),'--startup-owner',mode!,root],{cwd:root,stdio:['ignore','pipe','pipe'],windowsHide:true});
  let output='',errors='';owner.stdout.on('data',b=>output+=b);owner.stderr.on('data',b=>errors+=b);
  const closed=new Promise<number|null>((ok,bad)=>{owner.once('error',bad);owner.once('close',ok);});
  t.after(async()=>{if(owner.exitCode===null&&owner.signalCode===null)owner.kill('SIGKILL');await closed;});
  assert.equal(await closed,0,errors+'\n'+output);assert.equal(owner.signalCode,null);
  const report=JSON.parse(output);assert.equal(report.mode,mode);assert.equal(report.pid,owner.pid);
 });
}
