// Owned macOS debugger fixture: isolated Ghidra, immutable input, native execution and retained traces.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
const options={};for(let i=2;i<process.argv.length;i++){const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;
  else if(arg.startsWith('--')&&process.argv[i+1])options[arg.slice(2)]=process.argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const sourceFiles=['src/debugger.ts','src/debugger-supervisor.ts','src/debugger-results.ts','references/native/InsightTraceState.java','references/native/InsightTraceInspect.java','references/native/InsightStopDebugger.java','references/native/InsightStartDebugger.java','references/native/InsightPythonWheels.java','src/ui.ts','src/ui-results.ts','src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let loseInterrupt=false,interruptCalls=0,launchCalls=0;
let context,native,fixtureWorkspace;const completed=[];let receipt,opened;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(new URL(args[0]).pathname==='/debugger/launch')launchCalls++;
  if(new URL(args[0]).pathname==='/debugger/interrupt'){interruptCalls++;if(loseInterrupt&&value?.status==='interrupted'){loseInterrupt=false;await response.arrayBuffer();throw Error('Synthetic lost interrupt response');}}
  if(new URL(args[0]).pathname.startsWith('/debugger/'))await writeFile(join(f.root,'debugger-'+new URL(args[0]).pathname.split('/').pop()+'.json'),JSON.stringify(value),{mode:0o600});
  if(['/get_ui_cursor','/tool/running_tools'].includes(new URL(args[0]).pathname))await writeFile(join(f.root,new URL(args[0]).pathname.endsWith('running_tools')?'tools-response.json':'cursor-response.json'),JSON.stringify(value),{mode:0o600});
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),exe=join(dir,'native-fixture');
await writeFile(c,'#include <stdio.h>\n#include <unistd.h>\n__attribute__((used)) volatile unsigned long fixture_magic=0x1122334455667788UL; volatile unsigned long fixture_counter=0; __attribute__((noinline)) int fixture_step(int x){return x+7;} int main(void){FILE *f=fopen("debuggee.pid","w");if(!f)return 2;fprintf(f,"%d\\n",getpid());fclose(f);for(;;) fixture_counter+=fixture_step(1);}\n');
await exec('/usr/bin/clang',['-O0','-g',c,'-o',exe]);
const nm=(await exec('/usr/bin/nm',['-n',exe])).stdout;
const symbol=name=>{const m=new RegExp('^([a-fA-F0-9]+) [A-Za-z] '+name+'$','m').exec(nm);assert.ok(m,name);return m[1].replace(/^0+(?=.)/,'');};
const main=symbol('_main'),step=symbol('_fixture_step'),magic=symbol('_fixture_magic');
const checks=new Set();let navigation;
const debugCwd=join(f.root,"cwd spaces ' literal");await mkdir(debugCwd);
const debuggeeIdentities=[];
async function identity(pid){try{const values=await Promise.all(['lstart=','stat=','args='].map(field=>exec('/bin/ps',['-p',String(pid),'-o',field])));const [start,state,args]=values.map(value=>value.stdout.trim());return start&&args?{signature:start+'|'+args,state,args}:undefined;}catch(error){if(error.code===1)return undefined;throw error;}}
async function releaseDebuggee(){for(const debuggeeIdentity of debuggeeIdentities){const current=await identity(debuggeeIdentity.pid);if(current&&current.signature===debuggeeIdentity.signature&&!current.state.startsWith('Z'))process.kill(debuggeeIdentity.pid,'SIGKILL');}}
try {
  const a=opened=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select(a),'--address',main,'--kind','eol','--text','Private before debugger crash']);
  await f.json(app,['ghidra','comments','set',...select(b),'--address',main,'--kind','eol','--text','Independent live debugger B']);
  const launched=await f.json(app,['ghidra','debugger','launch',...select(a),'--request-id','launch','--timeout-seconds','90','--cwd',debugCwd]);
  await f.json(app,['ghidra','debugger','interrupt',...select(a)]);await f.json(app,['ghidra','debugger','resume',...select(a)]);
  const savedContext=fixtureWorkspace.context(a),binding=JSON.parse(await readFile(join(fixtureWorkspace.directory,'ghidra-native','context',savedContext.id,'current.json'),'utf8'));
  const staged=JSON.parse(await readFile(join(binding.root,'debugger-run','current.json'),'utf8'));assert.equal(staged.target,a.target);assert.equal(staged.context,savedContext.id);
  let pid;for(let attempt=0;attempt<100;attempt++){try{pid=Number((await readFile(join(debugCwd,'debuggee.pid'),'utf8')).trim());if(Number.isSafeInteger(pid)&&pid>1)break;}catch{}await delay(100);}assert.ok(pid>1,'Owned fixture did not publish its own PID');
  const observed=await identity(pid);assert.equal(observed?.args,staged.executable);const debuggeeIdentity={pid,signature:observed.signature};debuggeeIdentities.push(debuggeeIdentity);
  const bCwd=join(f.root,'debuggee-b');await mkdir(bCwd);
  const launchedB=await f.json(app,['ghidra','debugger','launch',...select(b),'--request-id','launch-b','--timeout-seconds','90','--cwd',bCwd]);
  await f.json(app,['ghidra','debugger','interrupt',...select(b)]);await f.json(app,['ghidra','debugger','resume',...select(b)]);
  const contextB=fixtureWorkspace.context(b),bindingB=JSON.parse(await readFile(join(fixtureWorkspace.directory,'ghidra-native','context',contextB.id,'current.json'),'utf8')),
    stagedB=JSON.parse(await readFile(join(bindingB.root,'debugger-run','current.json'),'utf8'));
  let pidB;for(let attempt=0;attempt<100;attempt++){try{pidB=Number((await readFile(join(bCwd,'debuggee.pid'),'utf8')).trim());if(Number.isSafeInteger(pidB)&&pidB>1)break;}catch{}await delay(100);}assert.ok(pidB>1);
  const observedB=await identity(pidB);assert.equal(observedB?.args,stagedB.executable);debuggeeIdentities.push({pid:pidB,signature:observedB.signature});
  await f.json(app,['ghidra','debugger','interrupt',...select(b)]);
  const dynamicB=(await f.json(app,['ghidra','debugger','static-to-dynamic',...select(b),'--address',magic])).value.dynamic_address;
  assert.equal((await f.json(app,['ghidra','debugger','read-memory',...select(b),'--address',dynamicB,'--size','8'])).value.hex,'8877665544332211');
  assert.notEqual(bindingB.pid,binding.pid);assert.notEqual(pidB,pid);console.log('Two independent GUI/LLDB contexts verified');
  const beforeLostInterrupt=interruptCalls;loseInterrupt=true;const uncertain=['ghidra','debugger','interrupt',...select(a),'--request-id','lost-stop'];assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(interruptCalls,beforeLostInterrupt+1);
  const request=fixtureWorkspace.unresolved(a).find(request=>request.callerId==='lost-stop'),retained=request.result.savedDebugger;assert.ok(retained?.traces.length);
  const record=native.running.get(binding.root);assert.equal(record.child.pid,binding.pid);assert.equal((await native.debuggerCall(a,'status')).target_connected,true);
  await writeFile(join(f.root,'debuggee-identity.json'),JSON.stringify({...debuggeeIdentity,executable:staged.executable,target:a.target,context:savedContext.id}),{mode:0o600});record.child.ref();const exited=new Promise(resolve=>record.child.once('exit',resolve));assert.equal(record.child.kill('SIGKILL'),true);await exited;console.log('Owned GUI child SIGKILL observed');
  let stopped=false;for(let attempt=0;attempt<100;attempt++){const after=await identity(pid);if(!after||after.state.startsWith('Z')){stopped=true;break;}await delay(100);}
  if(!stopped)await releaseDebuggee();assert.equal(stopped,true,'Owned debuggee survived its GUI/PTY owner crash');
  const bStatus=await f.json(app,['ghidra','debugger','status',...select(b)]);assert.equal(bStatus.connectionState,'connected');assert.equal(bStatus.trace,launchedB.trace);
  assert.equal((await identity(pidB))?.signature,observedB.signature);
  assert.equal((await f.json(app,['ghidra','debugger','read-memory',...select(b),'--address',dynamicB,'--size','8'])).value.hex,'8877665544332211');
  await f.json(app,['ghidra','open',...select(a)]);const restored=fixtureWorkspace.context(a).debugger;assert.equal(restored.connected,false);assert.equal(restored.active,launched.trace);assert.equal(restored.traces.find(trace=>trace.id===restored.active).snap,retained.traces.find(trace=>trace.id===retained.active).snap);
  const status=await f.json(app,['ghidra','debugger','status',...select(a)]);assert.equal(status.connectionState,'disconnected');assert.equal(status.value.target_connected,false);assert.equal(launchCalls,2);
  assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(interruptCalls,beforeLostInterrupt+1);assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address',main,'--kind','eol'])).text,'Private before debugger crash');assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address',main,'--kind','eol'])).text,'Independent live debugger B');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native debugger backend crash',twoSimultaneousGuiDebuggees:true,otherLiveDebuggerSurvives:true,originalGuiChildKilled:true,ownedDebuggeeTerminatesWithPty:true,explicitQuotedWorkingDirectoryHonored:true,uncertainTraceCandidateRetained:true,privateWorkAndOtherSessionPreserved:true,traceRestoredDisconnected:true,noExecutionResurrection:true,noLostActionReplay:true,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,limitations:['source Factory fixture and synthetic credentials','final installed owner matrix remains separate']};
}catch(error){console.error('Owned debugger crash diagnostics:',f.root);throw error;}
finally{try{await releaseDebuggee();await app.dispose();}finally{if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
