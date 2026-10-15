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
const sourceFiles=['src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let loseBatch=false,batchCalls=0;
let context,native,fixtureWorkspace;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(new URL(args[0]).pathname==='/batch_set_comments'){batchCalls++;if(loseBatch&&response.ok&&!value?.error&&value?.success!==false){loseBatch=false;await response.arrayBuffer();throw Error('Synthetic lost batch response');}}
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){int y=0;for(int i=0;i<4;i++)y+=x+i;return y+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target],at='140001000';
  const comment=(who,text)=>f.json(app,['ghidra','comments','set',...select(who),'--address',at,'--kind','eol','--text',text]);
  await comment(a,'Initial scalar');
  const batch=(text,request)=>['ghidra','comments','set-batch',...select(a),'--address',at,'--disassembly-comments',JSON.stringify([{address:'0x'+at,comment:text}]),'--request-id',request];
  await f.json(app,batch('Complex value','batch'));assert.equal(fixtureWorkspace.context(a).scalars[0].local,'Complex value');
  loseBatch=true;const lost=batch('Recovered complex value','lost-batch');assert.notEqual((await f.run(app,lost)).exitCode,0);assert.equal(batchCalls,2);assert.notEqual((await f.run(app,lost)).exitCode,0);assert.equal(batchCalls,2);
  await f.json(app,['ghidra','open',...select(a)]);assert.equal((await f.json(app,lost)).state,'applied');assert.equal(batchCalls,2);assert.equal(fixtureWorkspace.context(a).scalars[0].local,'Recovered complex value');
  await comment(b,'Shared value');await f.json(app,['ghidra','merge',...select(b)]);const refreshed=await f.json(app,['ghidra','refresh',...select(a)]);assert.equal(refreshed.state,'conflict');assert.ok(refreshed.conflicts.some(conflict=>conflict.local==='Recovered complex value'));assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address',at,'--kind','eol'])).text,'Recovered complex value');assert.notEqual((await f.run(app,['ghidra','merge',...select(a)])).exitCode,0);
  const untracked=await f.json(app,['ghidra','open',exe,'--session','new']);await f.json(app,['ghidra','functions','delete',...select(untracked),'--function','0x'+at]);
  await f.json(app,['ghidra','functions','rename',...select(b),'--address',at,'--name','shared_renamed']);assert.equal((await f.json(app,['ghidra','merge',...select(b)])).sharedRevision,'R3');
  const deletedIncoming=await f.json(app,['ghidra','refresh',...select(untracked)]);assert.equal(deletedIncoming.state,'conflict');assert.ok(deletedIncoming.conflicts.some(conflict=>conflict.field==='function.name'&&conflict.local===null));assert.equal(fixtureWorkspace.context(untracked).scalars.find(change=>change.field==='function.name').removed,true);
  const c=await f.json(app,['ghidra','open',exe,'--session','new']);await f.json(app,['ghidra','functions','rename',...select(c),'--address',at,'--name','removed_later']);
  const remove=['ghidra','functions','delete',...select(c),'--function','0x'+at,'--request-id','delete'];const deleted=await f.json(app,remove);assert.equal(deleted.state,'applied');assert.deepEqual(await f.json(app,remove),deleted);const pending=fixtureWorkspace.context(c).scalars.find(change=>change.field==='function.name');assert.equal(pending.removed,true);assert.equal(pending.local,null);
  assert.equal((await f.json(app,['ghidra','merge',...select(c)])).sharedRevision,'R4');await f.json(app,['ghidra','refresh',...select(b)]);assert.notEqual((await f.run(app,['ghidra','functions','get',...select(b),'--address',at])).exitCode,0);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address',at,'--kind','eol'])).text,'Recovered complex value');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native scalar projection after complex edits',actualBatchValueTracked:true,lostBatchCandidateReconciledWithoutReplay:true,refreshRetainsActualLocalConflict:true,divergedComplexMergePublishesNothing:true,removedFunctionFieldRetained:true,untrackedDeletionConflictsWithIncomingRename:true,deletedRenamedFunctionPublishesFullState:true,independentRefreshDoesNotResurrectName:true,privateConflictingViewPreserved:true,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,limitations:['source Factory fixture and synthetic credentials','final installed combined acceptance remains open']};
}catch(error){console.error('Owned scalar projection diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
