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
const options={};for(let i=2;i<process.argv.length;i++){const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;
  else if(arg.startsWith('--')&&process.argv[i+1])options[arg.slice(2)]=process.argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const sourceFiles=['src/debugger.ts','src/debugger-results.ts','references/native/InsightTraceState.java','references/native/InsightTraceInspect.java','references/native/InsightStopDebugger.java','references/native/InsightStartDebugger.java','references/native/InsightPythonWheels.java','src/ui.ts','src/ui-results.ts','src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let dropStep=false,stepCalls=0,launchCalls=0;
let context,native,fixtureWorkspace;const completed=[];let receipt,opened;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(new URL(args[0]).pathname==='/debugger/launch')launchCalls++;
  if(new URL(args[0]).pathname==='/debugger/step'){stepCalls++;if(dropStep&&value?.status==='stepped'){dropStep=false;await response.arrayBuffer();throw Error('Synthetic lost CPU step response');}}
  if(new URL(args[0]).pathname.startsWith('/debugger/'))await writeFile(join(f.root,'debugger-'+new URL(args[0]).pathname.split('/').pop()+'.json'),JSON.stringify(value),{mode:0o600});
  if(['/get_ui_cursor','/tool/running_tools'].includes(new URL(args[0]).pathname))await writeFile(join(f.root,new URL(args[0]).pathname.endsWith('running_tools')?'tools-response.json':'cursor-response.json'),JSON.stringify(value),{mode:0o600});
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),exe=join(dir,'native-fixture');
await writeFile(c,'__attribute__((used)) volatile unsigned long fixture_magic=0x1122334455667788UL; volatile unsigned long fixture_counter=0; __attribute__((noinline)) int fixture_step(int x){return x+7;} int main(void){for(;;) fixture_counter+=fixture_step(1);}\n');
await exec('/usr/bin/clang',['-O0','-g',c,'-o',exe]);
const nm=(await exec('/usr/bin/nm',['-n',exe])).stdout;
const symbol=name=>{const m=new RegExp('^([a-fA-F0-9]+) [A-Za-z] '+name+'$','m').exec(nm);assert.ok(m,name);return m[1].replace(/^0+(?=.)/,'');};
const main=symbol('_main'),step=symbol('_fixture_step'),magic=symbol('_fixture_magic');
const checks=new Set();let navigation;
try {
  const a=opened=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target];
  const invoke=async(name,args=[])=>{const value=await f.json(app,['ghidra','debugger',name,...select(a),...args]);checks.add(name);console.log('Debugger PASS:',name);return value;};
  await f.json(app,['ghidra','comments','set',...select(a),'--address',main,'--kind','eol','--text','private debug fixture']);
  const offers=await invoke('launch-offers');assert.ok(offers.value.items.some(offer=>offer.title==='lldb'));
  assert.equal((await invoke('status')).connectionState,'idle');
  const launchArgs=['--request-id','launch','--timeout-seconds','90'];const launch=await invoke('launch',launchArgs);assert.deepEqual(await invoke('launch',launchArgs),launch);assert.ok(launch.trace);
  await invoke('interrupt');
  const registers=await invoke('registers');assert.ok(Object.keys(registers.value).some(name=>/^(pc|rip|eip)$/i.test(name)));
  assert.ok((await invoke('stack-trace')).value.items.length);
  const modules=await invoke('modules');assert.ok(modules.value.items.some(module=>module.name==='native-fixture'));
  const translated=await invoke('static-to-dynamic',['--address',magic]),dynamic=translated.value.dynamic_address;
  const reverse=await invoke('dynamic-to-static',['--address',dynamic]);assert.equal(reverse.value.module,'native-fixture');
  const memory=await invoke('read-memory',['--address',dynamic,'--size','8']);assert.equal(memory.value.hex,'8877665544332211');
  const dynamicStep=(await invoke('static-to-dynamic',['--address',step])).value.dynamic_address;
  await invoke('set-breakpoint',['--address',dynamicStep,'--request-id','set-bp']);assert.ok((await invoke('list-breakpoints')).value.items.some(bp=>bp.address===dynamicStep));
  await invoke('resume',['--request-id','to-breakpoint']);
  await invoke('step',['--kind','into','--request-id','into']);await invoke('step',['--kind','over','--request-id','over']);await invoke('step',['--kind','out','--request-id','out']);
  await invoke('remove-breakpoint',['--address',dynamicStep,'--request-id','remove-bp']);
  await invoke('resume',['--request-id','run']);await invoke('interrupt',['--request-id','stop']);
  const traces=await invoke('traces');assert.ok(traces.value.items.some(trace=>trace.trace===launch.trace&&trace.thread_count>0));
  assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address',main,'--kind','eol'])).text,null);
  dropStep=true;const uncertain=['ghidra','debugger','step',...select(a),'--request-id','uncertain-step'];
  assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(stepCalls,4);assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(stepCalls,4);assert.equal((await invoke('status')).connectionState,'connected');
  assert.equal((await invoke('read-memory',['--address',dynamic,'--size','8'])).value.hex,'8877665544332211');
  await f.json(app,['ghidra','close',...select(a)]);await f.json(app,['ghidra','open',...select(a)]);
  const restored=await invoke('status');assert.equal(restored.connectionState,'disconnected');assert.equal(restored.value.target_connected,false);assert.equal(restored.trace,launch.trace);
  const reread=await invoke('read-memory',['--address',dynamic,'--size','8']);assert.equal(reread.value.hex,'8877665544332211');
  assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address',main,'--kind','eol'])).text,'private debug fixture');
  assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(stepCalls,4);assert.equal(launchCalls,1);
  assert.equal(checks.size,16);
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native debugger response recovery',operations:[...checks].sort(),stepKinds:['into','over','out'],lostStepNeverReplayed:true,uncertainContextClosedIndependently:true,executionNeverResurrected:true,exactMemoryVerified:true,requestRetryRecorded:true,independentSessionPreserved:true,traceSnapshotIndependentlyVerified:true,traceRestoredDisconnected:true,privateProgramRetained:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:true,
    limitations:['source Factory fixture and synthetic credentials','backend/owner crash and final installed matrix require acceptance']};
}catch(error){console.error('Owned debugger diagnostics:',f.root);throw error;}
finally{if(opened)try{await native.debuggerStop(opened);}catch(error){console.error('Owned debugger cleanup status:',error.message);}await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
