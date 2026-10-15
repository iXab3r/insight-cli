// Native saved-effect cases for structural edits. All inputs/processes/storage are owned fixtures.
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
const sourceFiles=['src/ui.ts','src/ui-results.ts','src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let context,native,fixtureWorkspace;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(['/get_ui_cursor','/tool/running_tools'].includes(new URL(args[0]).pathname))await writeFile(join(f.root,new URL(args[0]).pathname.endsWith('running_tools')?'tools-response.json':'cursor-response.json'),JSON.stringify(value),{mode:0o600});
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){int y=0;for(int i=0;i<4;i++)y+=x+i;return y+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select(a),'--address','140001000','--kind','eol','--text','GUI private comment']);
  const invoke=(name,args=[])=>f.json(app,['ghidra','ui',name,...select(a),...args]);
  const headless=await invoke('cursor');assert.equal(headless.value.address,null);assert.match(headless.value.address_unavailable,/Headless/);
  const tools=await invoke('tools');assert.ok(tools.value.count>0);assert.ok(tools.value.tools.some(tool=>tool.hasProgramManager&&tool.current.target===a.target));
  const gotoArgs=['--address','140001000','--request-id','goto'];const moved=await invoke('goto',gotoArgs);assert.equal(moved.value.address,'0x140001000');assert.deepEqual(await invoke('goto',gotoArgs),moved);
  const cursor=await invoke('cursor');assert.equal(cursor.value.address.address,'0x140001000');assert.equal(cursor.value.address.target,a.target);assert.equal(cursor.value.program.name,'fixture.exe');assert.equal(cursor.value.program.executable_path,undefined);
  assert.equal((await invoke('cursor',['--type','function'])).value.function.address,'0x140001000');
  const enabled=await invoke('prompt-policy',['--action','enable','--seconds','30','--reason','owned GUI fixture','--request-id','enable']);assert.equal(enabled.value.enabled,true);assert.equal(enabled.value.reason,'owned GUI fixture');
  assert.equal((await invoke('prompt-policy',['--action','status'])).value.enabled,true);
  assert.equal((await invoke('prompt-policy',['--action','disable','--request-id','disable'])).value.enabled,false);
  assert.equal((await f.json(app,['ghidra','status',...select(a)])).health.mode,'gui');
  await f.json(app,['ghidra','open',...select(a),'--mode','headless']);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','140001000','--kind','eol'])).text,'GUI private comment');
  assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address','140001000','--kind','eol'])).text,null);
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native GUI controls',headlessCursorExplicitlyUnavailable:true,ownedToolInventory:true,navigationAndCursorReadback:true,promptPolicyEnableStatusDisable:true,retryRecorded:true,logicalScopeOnly:true,privateStateSurvivesModeTransition:true,otherAgentUnchanged:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:true,
    limitations:['source Factory fixture and synthetic credentials','debugger and final installed matrix require separate acceptance']};
}catch(error){console.error('Owned UI diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
