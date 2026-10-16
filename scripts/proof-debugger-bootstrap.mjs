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
const sourceFiles=['references/native/InsightStartDebugger.java','references/native/InsightPythonWheels.java','src/ui.ts','src/ui-results.ts','src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let context,native,fixtureWorkspace;const completed=[];let receipt,opened;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(['/get_ui_cursor','/tool/running_tools'].includes(new URL(args[0]).pathname))await writeFile(join(f.root,new URL(args[0]).pathname.endsWith('running_tools')?'tools-response.json':'cursor-response.json'),JSON.stringify(value),{mode:0o600});
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),exe=join(dir,'native-fixture');
await writeFile(c,'volatile unsigned long fixture_counter=0x1122334455667788UL; __attribute__((noinline)) int fixture_step(int x){return x+7;} int main(void){for(;;) fixture_counter+=fixture_step(1);}\n');
await exec('/usr/bin/clang',['-O0','-g',c,'-o',exe]);
console.log('Owned debugger fixture prepared');
try {
  const a=opened=await f.json(app,['ghidra','open',exe,'--session','new']),select=['--session',a.session,'--target',a.target];console.log('Static native program opened');
  await f.json(app,['ghidra','ui','tools',...select]);console.log('Owned GUI ready');
  await native.debuggerStart(a);console.log('Debugger services ready');
  const offers=await native.debuggerCall(a,'launch_offers');await writeFile(join(f.root,'offers.json'),JSON.stringify(offers,null,2),{mode:0o600});assert.ok(Array.isArray(offers)&&offers.length);console.log('Launch offers verified');
  const launched=await native.debuggerCall(a,'launch',{executable_path:exe,offer:'lldb',args:'',cwd:dir,timeout_seconds:90});await writeFile(join(f.root,'launch.json'),JSON.stringify(launched,null,2),{mode:0o600});console.log('Launch result:',JSON.stringify(launched));
  const status=await native.debuggerCall(a,'status');await writeFile(join(f.root,'status.json'),JSON.stringify(status,null,2),{mode:0o600});assert.equal(status.target_connected,true);console.log('Connected trace verified');
  await native.debuggerCall(a,'interrupt');const saved=await native.debuggerSaved(a);assert.ok(saved.traces.length);const current=fixtureWorkspace.context(a);fixtureWorkspace.saveContext(a,current.generation,{debugger:saved});console.log('Immutable owned trace checkpoint verified');
  await native.close(a);await f.json(app,['ghidra','open',...select,'--mode','gui']);await native.debuggerStart(a);const restored=await native.debuggerCall(a,'status');assert.equal(restored.trace_active,true);assert.equal(restored.target_connected,false);console.log('Trace restored without CPU-state resurrection');
}catch(error){console.error('Owned debugger diagnostics:',f.root);throw error;}
finally{if(opened)try{await native.debuggerStop(opened);}catch(error){console.error('Owned debugger cleanup status:',error.message);}await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
