// Fault proof for the exact installed runner, real LLDB and an owned bounded fixture.
import assert from 'node:assert/strict';import {spawn,execFile,execFileSync} from 'node:child_process';import {promisify} from 'node:util';import {mkdir,readFile,writeFile,readdir} from 'node:fs/promises';import {join,resolve} from 'node:path';import {pathToFileURL} from 'node:url';import {setTimeout as delay} from 'node:timers/promises';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');const [packageRoot,output,archive,fixture]=process.argv.slice(2);assert.ok(fixture);const toolRoot=join(resolve(output),'native');await mkdir(toolRoot,{recursive:true,mode:0o700});execFileSync('tar',['-xzf',archive,'--strip-components=1','-C',toolRoot]);const execute=promisify(execFile),helper=join(packageRoot,'runtime/native/deadline-exec-darwin-arm64');
const isAlive=pid=>{try{process.kill(pid,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}};
await mkdir(output,{recursive:true,mode:0o700});const results=[];
for(const fault of ['SIGTERM','SIGKILL','owner_loss','timeout','output_limit','native_error']){
 const directory=join(resolve(output),fault);await mkdir(directory);const commands=['settings set target.detach-on-error false','breakpoint set --one-shot true --name quote_total','process launch --shell-expand-args false --',...(fault==='native_error'?['register read unreal_register']:['continue'])];
 const source=`import{runTool}from ${JSON.stringify(pathToFileURL(join(packageRoot,'dist/src/tool-runtime/run.js')).href)};try{await runTool({appArguments:{AppDataDirectory:process.env.FAULT_ROOT},signal:new AbortController().signal,environment:{PATH:process.env.PATH}},{tool:'lldb',role:'fault',executable:${JSON.stringify(join(toolRoot,'bin/lldb'))},arguments:${JSON.stringify(['--no-lldbinit','--batch',...commands.flatMap(c=>['-o',c]),'--',resolve(fixture)])},environment:{LLDB_DEBUGSERVER_PATH:${JSON.stringify(join(toolRoot,'bin/debugserver'))}},timeoutMs:4000,maxOutputBytes:${fault==='output_limit'?128:1048576},nativeDeadline:true});}catch(e){console.log(JSON.stringify({code:e.code}));}`;
 const owner=spawn(process.execPath,['--input-type=module','-e',source],{env:{...process.env,FAULT_ROOT:directory},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';owner.stdout.on('data',b=>stdout+=b);owner.stderr.on('data',b=>stderr+=b);const closed=new Promise(ok=>owner.once('close',ok));let record,inferior,debugserver;
 try{
  for(let n=0;n<100;n++){
   const names=await readdir(join(directory,'runtime/processes')).catch(()=>[]);if(names[0])record=JSON.parse(await readFile(join(directory,'runtime/processes',names[0]),'utf8'));
   const table=(await execute('/bin/ps',['-axo','pid=,ppid=,command='])).stdout.split('\n').map(l=>l.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean);
   inferior=table.find(r=>r[3]===resolve(fixture))?.[1];debugserver=table.find(r=>Number(r[2])===record?.pid&&r[3].startsWith(join(toolRoot,'bin/debugserver')))?.[1];
   if(inferior||owner.exitCode!==null||owner.signalCode!==null)break;await delay(50);
  }
  if(['SIGTERM','SIGKILL','owner_loss','timeout'].includes(fault)){assert.ok(inferior,'Owned inferior origin must be visible');assert.ok(record?.pid);assert.equal(record.metadata.nativeDeadlineSeconds,4);}
  let recoveredBefore;
  if(fault==='owner_loss'){
   owner.kill('SIGKILL');await closed;const {processStatus}=await import(pathToFileURL(join(packageRoot,'dist/src/tool-runtime/supervisor.js')).href);recoveredBefore=await processStatus(directory,record.id);assert.equal(recoveredBefore.state,'unverified');assert.equal(recoveredBefore.phase,'tool_identity_required');
  }else if(fault==='SIGTERM'||fault==='SIGKILL')process.kill(-record.pid,fault);
  await Promise.race([closed,delay(7000).then(()=>{throw Error('Owner deadline exceeded');})]);await delay(4500);
  if(inferior)assert.equal(isAlive(Number(inferior)),false,'Inferior must exit after '+fault);if(debugserver)assert.equal(isAlive(Number(debugserver)),false,'Private debugserver must exit');if(record?.pid)assert.equal(isAlive(record.pid),false);
  const {processStatus}=await import(pathToFileURL(join(packageRoot,'dist/src/tool-runtime/supervisor.js')).href),after=await processStatus(directory,record.id);assert.ok(['failed','exited'].includes(after.state));if(fault==='owner_loss'){assert.equal(after.outcome,'unknown');assert.equal(after.phase,'observed_exit');}else if(fault==='timeout')assert.equal(after.outcome,'timeout');else if(fault==='output_limit')assert.equal(after.outcome,'output_limit');
  results.push({fault,debuggerAbsent:true,inferiorAbsent:!inferior||!isAlive(Number(inferior)),debugserverObserved:Boolean(debugserver),debugserverAbsent:!debugserver||!isAlive(Number(debugserver)),recoveredBefore:recoveredBefore?.state,state:after.state,outcome:after.outcome});
 }finally{if(owner.exitCode===null&&owner.signalCode===null)owner.kill('SIGKILL');await closed;}
}
// Direct kernel contract, independent of Node's timer or LLDB's signal handling.
const alarm=spawn(helper,['1','--','/bin/sleep','20'],{stdio:'ignore'});await new Promise(ok=>alarm.once('close',ok));assert.equal(alarm.signalCode,'SIGALRM');
await writeFile(join(output,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Installed runner and real native debugger; no model inference',checks:{kernelAlarmAcrossExec:true,debuggerAndInferiorCleanup:true,ownerReplacementUnknownResult:true,outputLimitAndNativeFailure:true},cleanupComplete:true,results},null,2)+'\n');console.log('LLDB native fault proof PASS:',output);
