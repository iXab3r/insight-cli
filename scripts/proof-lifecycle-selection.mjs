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
let loseDiscard=false,discardCloses=0;
let context,native,fixtureWorkspace;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;const complete=workspace.completeSavedRequest.bind(workspace);workspace.completeSavedRequest=(...args)=>{if(loseDiscard&&workspace.request(args[1]).operation==='ghidra.changes.discard'){loseDiscard=false;throw Error('Synthetic local discard acknowledgement loss');}return complete(...args);};context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);const fork=native.fork.bind(native);native.fork=c=>{const scoped=fork(c),close=scoped.close.bind(scoped);scoped.close=async selected=>{discardCloses++;return close(selected);};return scoped;};return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){int y=0;for(int i=0;i<4;i++)y+=x+i;return y+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target];
  const second=join(dir,'helper.exe'),helperObj=join(dir,'helper.obj');await writeFile(c,'__declspec(noinline) int first(int x){return x+23;} int main(void){return first(2); }');await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',helperObj]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+second,helperObj]);
  const helper=await f.json(app,['ghidra','open',second,'--session',a.session]);
  const comment=(who,text)=>f.json(app,['ghidra','comments','set',...select(who),'--address','140001000','--kind','eol','--text',text]);
  await comment(a,'Discarded private A');await comment(helper,'Kept private helper');
  await f.json(app,['ghidra','types','create-struct',...select(a),'--name','DiscardedType','--fields','[{"name":"field","type":"uint"}]']);
  const allArgs=['ghidra','save-all','--session',a.session,'--request-id','all'];const all=await f.json(app,allArgs);assert.equal(all.saved,2);assert.ok(all.items.every(item=>item.session===a.session));assert.deepEqual(await f.json(app,allArgs),all);
  await comment(b,'Published B');await f.json(app,['ghidra','merge',...select(b)]);
  const discardArgs=['ghidra','changes','discard',...select(a),'--request-id','discard'];const discarded=await f.json(app,discardArgs);assert.equal(discarded.state,'discarded');assert.equal(discarded.discardedChanges,2);assert.equal(discarded.pendingChanges,0);assert.equal(discarded.baseRevision,'R1');assert.deepEqual(await f.json(app,discardArgs),discarded);assert.equal(discardCloses,1);
  const fields=await native.fields(discarded.discardedSnapshot,[{address:'140001000',field:'comment.eol'}]);assert.equal(Object.values(fields)[0].value,'Discarded private A');
  await f.json(app,['ghidra','open',...select(a)]);assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','140001000','--kind','eol'])).text,null);
  assert.notEqual((await f.run(app,['ghidra','types','get-struct-layout',...select(a),'--struct-name','DiscardedType'])).exitCode,0);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(helper),'--address','140001000','--kind','eol'])).text,'Kept private helper');assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address','140001000','--kind','eol'])).text,'Published B');
  await comment(a,'Discard retry A');loseDiscard=true;const uncertain=['ghidra','changes','discard',...select(a),'--request-id','lost-discard'];assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(discardCloses,2);await f.json(app,['ghidra','open',...select(a)]);assert.equal((await f.json(app,uncertain)).state,'discarded');assert.equal(discardCloses,2);
  await f.json(app,['ghidra','refresh',...select(a)]);assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','140001000','--kind','eol'])).text,'Published B');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native session save and local discard',sessionOnlySave:true,twoInputsIndependent:true,scalarAndComplexDiscard:true,priorSnapshotRetainedAndRead:true,discardRestoresOwnBase:true,otherAgentAndSharedUnchanged:true,requestRetryNoRelease:true,lostLocalSwitchReconciled:true,explicitRefreshAfterDiscard:true,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,limitations:['source Factory fixture and synthetic credentials','final installed combined acceptance remains open']};
}catch(error){console.error('Owned lifecycle selection diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
