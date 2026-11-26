import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname,delimiter} from 'node:path';
import {randomUUID} from 'node:crypto';
import {spawnSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import type {CommandContext} from '@eyeauras/cli-factory';
import {Workspace,type GhidraContext,type NativeCheckout} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import type {NativeInputs} from '../src/native-inputs.js';
import {nativeHelpers,moduleJars,packagedMcpJar,nativeJvmDirectories} from '../src/native-inputs.js';
import {javaClasspathArguments} from '../src/tool-runtime/java-arguments.js';
import type {Artifact} from '../src/artifacts.js';
import {Research} from '../src/research.js';
import {fail} from '../src/model.js';

const base='a'.repeat(64),opened='b'.repeat(64),privateWork='c'.repeat(64);
const receiptHome=process.env.INSIGHT_TEST_RECEIPTS_GHIDRA_HOME,receiptJava=process.env.INSIGHT_TEST_RECEIPTS_JAVA;
test('pure native release/backup receipt controls compile against the SDK without starting Ghidra',{
 skip:!receiptHome||!receiptJava?'Optional SDK-only receipt controls: INSIGHT_TEST_RECEIPTS_GHIDRA_HOME and INSIGHT_TEST_RECEIPTS_JAVA':false,timeout:120000
},async t=>{
 const directory=await mkdtemp(join(tmpdir(),'insight receipt controls '));t.after(()=>rm(directory,{recursive:true,force:true}));
 const jars=[packagedMcpJar,...await moduleJars(receiptHome!)],run=promisify(execFile);
 const inputs:NativeInputs={java:receiptJava!,ghidraHome:receiptHome!,mcpJar:packagedMcpJar,jars,classpath:jars.join(delimiter),ghidraVersion:'12.1.2',fingerprint:'pure-disposal-receipts',debuggerWheels:[]};
 const classes=await nativeHelpers(directory,inputs),cp=classes+delimiter+inputs.classpath;
 const javac=join(dirname(receiptJava!),'javac'+(process.platform==='win32'?'.exe':''));
 const source=fileURLToPath(new URL('../../tests/fixtures/native-merge/NativeDisposalFixture.java',import.meta.url));
 const compileCall=join(directory,'compile'),receiptCall=join(directory,'receipts');await mkdir(compileCall);await mkdir(receiptCall);
 await run(javac,await javaClasspathArguments(compileCall,'ghidra',javac,['-proc:none','-cp',cp,'-d',directory,source]),{windowsHide:true,timeout:60000});
 // The receipts branch returns before Application.initializeApplication, server connection or project access.
 const result=await run(receiptJava!,await javaClasspathArguments(receiptCall,'ghidra',receiptJava!,[
  '-Djava.awt.headless=true',...nativeJvmDirectories(directory),'-cp',directory+delimiter+cp,'NativeDisposalFixture','receipts'
 ]),{windowsHide:true,timeout:30000});
 assert.match(result.stdout,/RELEASE_RECEIPTS_VERIFIED/);assert.match(result.stdout,/BACKUP_RECEIPTS_VERIFIED controls=\d+/);t.diagnostic(result.stdout.trim());
});

for(const fault of ['none','missing journal','missing result','intent marker only','wrong root','wrong owner','wrong file','wrong prior checkout','missing inventory','changed saved bytes'] as const)
test('completed discard recovery '+fault+' uses proof/readback without dispatching discard',async t=>{
 const f=await fixture(t),original=f.checkout,request='q_'+randomUUID(),keep=f.context.target+'.bin.keep';
 const result={state:'discarded',checkoutId:4,baseVersion:1,modified:false,saved:{fileId:'file',version:1,fingerprint:base},retainedKeepFile:keep};
 const journal:any={request:{operation:'discard',request,root:original.root,fileId:original.fileId,checkoutId:original.checkoutId,owner:{}},checkoutId:3,baseVersion:1,result};
 if(fault==='missing result')delete journal.result;
 if(fault==='intent marker only'){delete journal.result;journal.retainedKeepFile=keep;}
 if(fault==='wrong root')journal.request.root=join(f.directory,'foreign');
 if(fault==='wrong owner')journal.request.owner={context:'foreign'};
 if(fault==='wrong file')journal.request.fileId='foreign';
 if(fault==='wrong prior checkout')journal.request.checkoutId=9;
 const operations=join(original.root,'operations'),path=join(operations,request+'-discard.json');await mkdir(operations);
 if(fault!=='missing journal')await writeFile(path,JSON.stringify(journal));
 const bytes=fault==='missing journal'?undefined:await readFile(path,'utf8');
 f.state.files.push(keep);f.state.status={checkoutId:4,checkouts:[{id:4,version:1}],...(fault==='missing inventory'?{projectFiles:undefined}:{}),
  ...(fault==='changed saved bytes'?{saved:{...result.saved,fingerprint:privateWork}}:{})};
 let readbacks=0;
 Object.assign(f.backend,{serverView:async()=>{readbacks++;return {revision:1,snapshot:f.workspace.context(f.context).baseSnapshot!,value:result.saved};}});
 const recovered=await f.backend.recoverDiscardNative(f.context,request,original);
 assert.equal(recovered.state,fault==='none'?'verified':'unknown');
 assert.equal(f.workspace.context(f.context).nativeCheckout!.checkoutId,fault==='none'?4:3);
 assert.equal(readbacks,Number(fault==='none'));assert.ok(f.calls.every(call=>call.operation==='status'));
 if(bytes!==undefined)assert.equal(await readFile(path,'utf8'),bytes);
 assert.equal(await readFile(join(original.root,'view.rep','database'),'utf8'),'saved private database');
});
async function fixture(t:test.TestContext){
 const directory=await mkdtemp(join(tmpdir(),'native-disposal-')),workspace=new Workspace(join(directory,'workspace'),'default');
 t.after(async()=>{workspace.close();await rm(directory,{recursive:true,force:true});});
 const input=join(directory,'input.bin');await writeFile(input,'disposable offline fixture');const target=await workspace.importTarget(input);
 const reservation=workspace.reserveOpen(target.id,'new',{autoAnalyze:false});workspace.recordRequest(reservation.request.id,'failed',{});
 const c=reservation.context,root=join(workspace.directory,'ghidra-native','context',c.id,'w-owned');await mkdir(join(root,'view.rep'),{recursive:true});
 await writeFile(join(root,'view.rep','database'),'saved private database');
 await writeFile(join(root,'native-owner.json'),'{}');
 const checkout:NativeCheckout={schema:1,context:c.id,root,fileId:'file',checkoutId:3,baseVersion:1,origin:'ghidra://127.0.0.1:1',repository:'owned',path:'/'+target.id+'.bin',runtimeFingerprint:'d'.repeat(64),state:'active'};
 const receipt=async(value:unknown)=>{const path=join(directory,randomUUID()+'.json');await writeFile(path,JSON.stringify(value));return workspace.captureNative(path);};
 const shared=await receipt({schema:1,engine:'native-checkout-v1',source:'server',version:1,fileId:'file',fingerprint:base,origin:checkout.origin,repository:checkout.repository});
 workspace.establishModel(target.id,1,shared);
 const context=workspace.saveContext(c,c.generation,{state:'stopped',nativeCheckout:checkout,baseRevision:1,baseSnapshot:shared,
  workingSnapshot:await receipt({source:'checkout',checkout,version:1,fileId:'file',fingerprint:base})});
 const backend=new GhidraContexts(workspace,{fingerprint:checkout.runtimeFingerprint} as NativeInputs,{profile:{values:{}}} as CommandContext);
 const calls:{operation:string;parameters:Record<string,unknown>}[]=[],events:string[]=[];
 const state={fingerprint:base,modified:false,recoverable:false,files:[target.id+'.bin'],release:'released',drop:'dropped',launchFailure:'',status:{} as Record<string,unknown>};
 const saved=()=>({fingerprint:state.fingerprint,fileId:'file',version:1});
 const observed=()=>({state:'ready',checkedOut:true,modified:state.modified,recoverable:state.recoverable,fileId:'file',checkoutId:3,baseVersion:1,saved:saved(),projectFiles:state.files,...state.status});
 const nativeReceipt=(b:NativeCheckout,v:Record<string,unknown>)=>(backend as unknown as {nativeReceipt(b:NativeCheckout,v:Record<string,unknown>):Promise<Artifact>}).nativeReceipt(b,v);
 let record:unknown;
 Object.assign(backend,{
  nativeOwner:async()=>({owner:{}}),inventory:async()=>{},lastWorker:async()=>({unfinished:false}),
  closed:async()=>true,neverStartedOrClosed:async()=>true,verified:async()=>record,stopRecord:async()=>{},selected:async()=>record,
  nativeOperation:async(_checkout:NativeCheckout,operation:string,parameters:Record<string,unknown>={})=>{
   calls.push({operation,parameters});events.push(operation);
   if(operation==='status')return observed();
   if(operation==='fields')return {state:'ready',value:{'1000@comment.eol':{value:'private comment',exists:true,dependency:'owned'}}};
   return {state:operation==='release'?state.release:state.drop};
  },
  capture:async()=>{events.push('capture');return nativeReceipt(workspace.context(context).nativeCheckout!,saved());},
  launch:async()=>{
   events.push('launch');const binding={pid:2147483647,endpoint:'http://127.0.0.1:1',root,context:c.id,target:target.id,program:checkout.path,kind:'context',mode:'headless',tokenSecret:'fixture',runtimeFingerprint:checkout.runtimeFingerprint};
   await writeFile(join(root,'process.json'),JSON.stringify(binding));
   record={binding,http:{call:async(operation:string)=>{
    events.push(operation);if(state.launchFailure===operation)throw Error('Interrupted first launch');
    if(operation==='/open_program'){
     if(state.fingerprint===base){state.fingerprint=opened;state.modified=true;}
     return {path:checkout.path,read_only:false};
    }
    return {success:true};
   }}};
   return record;
  }
 });
 const references=join(workspace.directory,'ghidra-native','shared-views',target.id,'opened');
 const refs=()=>readdir(references).catch(error=>{if(error.code==='ENOENT')return [];throw error;});
 const fingerprint=async()=>JSON.parse(await readFile(await workspace.artifacts.verify(workspace.context(c).workingSnapshot!),'utf8')).fingerprint;
 const patch=(value:Partial<GhidraContext>)=>workspace.saveContext(c,workspace.context(c).generation,value);
 const updateJournal=async(request:string,fingerprint=state.fingerprint)=>{
  const operations=join(root,'operations');await mkdir(operations,{recursive:true});
  await writeFile(join(operations,request+'-update.json'),JSON.stringify({request:{operation:'update',request,root,fileId:checkout.fileId,checkoutId:checkout.checkoutId,owner:{}},baseVersion:1,
   result:{state:'updated',modified:fingerprint!==base,checkoutId:checkout.checkoutId,baseVersion:1,saved:{fileId:checkout.fileId,version:1,fingerprint}}}));
 };
 return {directory,workspace,context,checkout,backend,receipt,patch,calls,events,state,refs,references,fingerprint,saved,nativeReceipt,updateJournal};
}

test('first open records only the rewrite of independently proved base buffers, and normal reopen creates no new proof',async t=>{
 const f=await fixture(t);await f.backend.open(f.context);
 assert.ok(f.events.indexOf('status')<f.events.indexOf('launch'));assert.equal(await f.fingerprint(),opened);
 const names=await f.refs();assert.equal(names.length,1);
 const proof=JSON.parse(await readFile(join(f.references,names[0]!),'utf8'));
 assert.equal(proof.schema,2);assert.deepEqual(proof.preOpen,{fingerprint:base,fileId:'file',checkoutId:3,baseVersion:1});
 assert.equal(f.workspace.unchangedNative(f.workspace.context(f.context)),true);
 f.events.length=0;await f.backend.open(f.context);assert.ok(!f.events.includes('status'));assert.ok(!f.events.includes('capture'));assert.deepEqual(await f.refs(),names);
 await f.backend.close(f.context);assert.equal(await f.backend.releaseUnchanged(f.context),true);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'dropped');
});

test('restored base-only control records cannot bless saved private work when process/current receipts are missing',async t=>{
 const f=await fixture(t);f.state.fingerprint=privateWork;f.state.modified=true;
 await f.backend.open(f.context);assert.deepEqual(await f.refs(),[]);assert.equal(f.events.includes('capture'),false);
 assert.equal(await f.backend.releaseUnchanged(f.context),false);await f.backend.close(f.context);
 assert.equal(await f.fingerprint(),privateWork);assert.equal(await f.backend.releaseUnchanged(f.context),false);
 const collected=await f.backend.collect(true);assert.equal(collected.categories['native-checkouts'],undefined);
 assert.ok(!f.calls.some(c=>c.operation==='release'||c.operation==='drop'));
 assert.equal(await readFile(join(f.checkout.root,'view.rep','database'),'utf8'),'saved private database');
 await f.backend.open(f.context);assert.equal(await f.fingerprint(),privateWork);assert.deepEqual(await f.refs(),[]);
});

for(const [name,change] of Object.entries({
 'unproved status':{state:'unknown'},'changed checkout':{checkoutId:4},'changed file':{fileId:'other'},'stale base':{baseVersion:2},
 'missing recovery evidence':{recoverable:undefined},'recovery data':{recoverable:true},'modified base':{modified:true},
 'additional nested file':{projectFiles:['nested/private']},'missing file inventory':{projectFiles:undefined},
 'stale saved bytes':{saved:{fileId:'file',version:1,fingerprint:privateWork}},'missing saved identity':{saved:{fingerprint:base}},
}))test('first open cannot create a no-work reference with '+name,async t=>{
 const f=await fixture(t);f.state.status=change;await f.backend.open(f.context);assert.deepEqual(await f.refs(),[]);assert.ok(!f.events.includes('capture'));
});

for(const absent of ['baseSnapshot','workingSnapshot'] as const)test('missing '+absent+' does not authorize a pristine reference',async t=>{
 const f=await fixture(t);f.patch({[absent]:undefined});await assert.rejects(f.backend.open(f.context),/requires durable private and base snapshots/);assert.deepEqual(await f.refs(),[]);assert.ok(!f.events.includes('capture'));
});

test('stale saved receipt and interrupted first launch both retain the opened project on retry',async t=>{
 const f=await fixture(t);f.patch({workingSnapshot:await f.receipt({source:'checkout',fingerprint:privateWork})});
 await f.backend.open(f.context);assert.deepEqual(await f.refs(),[]);
 const g=await fixture(t);g.state.launchFailure='/open_program';await assert.rejects(g.backend.open(g.context),/Interrupted/);
 assert.deepEqual(await g.refs(),[]);g.state.launchFailure='';g.events.length=0;await g.backend.open(g.context);
 assert.ok(!g.events.includes('status'));assert.deepEqual(await g.refs(),[]);await g.backend.close(g.context);assert.equal(await g.backend.releaseUnchanged(g.context),false);
});

test('changed bytes after authorization cause refusal, restore the same active saved view and permit inspection/reopen',async t=>{
 const f=await fixture(t);await f.backend.open(f.context);await f.backend.close(f.context);
 const prior=f.workspace.context(f.context),diagnostic='q_'+randomUUID();f.patch({complexChanges:[diagnostic]});
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';
 await assert.rejects(f.backend.finishEmptyNative(f.context),(error:unknown)=>{
  const result=(error as {result:Record<string,any>}).result;assert.equal(result.state,'retained');assert.equal(result.retention.source,'native-release-status');
  assert.equal(result.retention.checkout.checkoutId,f.checkout.checkoutId);return true;
 });
 const retained=f.workspace.context(f.context);assert.equal(retained.nativeCheckout!.state,'active');assert.equal(retained.nativeCheckout!.root,prior.nativeCheckout!.root);
 assert.equal(retained.nativeCheckout!.opened,undefined);assert.deepEqual(retained.complexChanges,[diagnostic]);assert.equal(await f.fingerprint(),privateWork);
 assert.equal((await f.backend.fields(retained.workingSnapshot!,[{address:'1000',field:'comment.eol'}]))['1000@comment.eol']!.value,'private comment');
 const releases=f.calls.filter(c=>c.operation==='release').length;await f.backend.open(f.context);
 assert.equal(f.calls.filter(c=>c.operation==='release').length,releases);assert.equal(await f.backend.releaseUnchanged(f.context),false);
 await assert.rejects(f.backend.finishEmptyNative(f.context),/differs from its shared base/);assert.ok(!f.calls.some(c=>c.operation==='drop'));
});

test('extra-file refusal retains diagnostics and retries only after independent verification of a new disposal',async t=>{
 const f=await fixture(t);await f.backend.open(f.context);await f.backend.close(f.context);
 f.state.files.push('nested/private');f.state.release='unknown';await assert.rejects(f.backend.finishEmptyNative(f.context),/private work is retained/);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'active');assert.equal(await f.fingerprint(),opened);
 await f.backend.open(f.context);assert.equal(await f.backend.releaseUnchanged(f.context),false);
 f.state.files.splice(1);f.state.release='released';await f.backend.close(f.context);assert.equal(await f.backend.releaseUnchanged(f.context),true);
 const release=f.calls.filter(c=>c.operation==='release').at(-1)!;assert.equal(release.parameters.opened,opened);assert.equal(release.parameters.openedVerified,true);
});

for(const status of [{state:'unknown'},{checkedOut:false},{checkoutId:9},{baseVersion:2},{fileId:'other'},{saved:{fingerprint:base}}])test('unproved refusal keeps disposal frozen: '+JSON.stringify(status),async t=>{
 const f=await fixture(t);f.state.release='unknown';f.state.status=status;
 const prior=f.workspace.context(f.context);await assert.rejects(f.backend.finishEmptyNative(f.context),/release remains unproved/);
 const current=f.workspace.context(f.context);assert.equal(current.nativeCheckout!.state,'verified');assert.deepEqual(current.workingSnapshot,prior.workingSnapshot);
 assert.ok(!f.calls.some(c=>c.operation==='drop'||c.operation==='checkin'));
});

test('lost release/drop acknowledgments keep the authorized view and resume without a new working launch',async t=>{
 const f=await fixture(t);await f.backend.open(f.context);await f.backend.close(f.context);
 f.state.release='unknown';f.state.status={checkedOut:false};await assert.rejects(f.backend.finishEmptyNative(f.context),/release remains unproved/);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'verified');assert.equal(await f.fingerprint(),opened);
 f.state.release='released';f.state.drop='unknown';await assert.rejects(f.backend.dropNative(f.context),/deletion remains unproved/);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'verified');f.state.drop='dropped';await f.backend.dropNative(f.context);
 const attempts=f.calls.filter(c=>['release','drop'].includes(c.operation));assert.ok(attempts.every(c=>c.parameters.opened===opened&&c.parameters.fingerprint===base));
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'dropped');
});

test('pre-upgrade verified disposal with a replaced base receipt becomes usable only after proving the checkout survived',async t=>{
 const f=await fixture(t),c=f.workspace.context(f.context);f.patch({nativeCheckout:{...f.checkout,state:'verified',opened},workingSnapshot:c.baseSnapshot});
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';await assert.rejects(f.backend.dropNative(f.context),/private work is retained/);
 assert.equal(f.calls[0]!.parameters.opened,opened);assert.equal(f.calls[0]!.parameters.openedVerified,false);
 assert.equal(await f.fingerprint(),privateWork);assert.equal(f.workspace.context(c).nativeCheckout!.state,'active');await f.backend.open(c);
});

for(const ownership of ['proved','unknown'] as const)test('empty merge refusal after saved bytes change is '+ownership+' and its original request never replays',async t=>{
 const f=await fixture(t);await f.backend.open(f.context);let updates=0;
 const research=new Research(f.workspace,async()=>f.backend);
 f.backend.updateNative=async(_scope,request)=>{
  updates++;await f.backend.close(f.context);const c=f.workspace.context(f.context);
  await f.updateJournal(request,await f.fingerprint());
  // The native Update completed. The later final-release inspection encounters a changed saved project.
  f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';if(ownership==='unknown')f.state.status={checkedOut:false};
  return {state:'empty',revision:1,snapshot:c.workingSnapshot!,sharedSnapshot:c.baseSnapshot!,receivedChanges:0,nativeMergeInvocations:0};
 };
 await assert.rejects(research.merge(f.context,'refused-empty'));
 const request=f.workspace.scopedRequest(f.context,'refused-empty')!;
 assert.equal(request.state,ownership==='proved'?'failed':'unknown');assert.equal((request.result as {state:string}).state,ownership==='proved'?'retained':'unknown');
 await assert.rejects(research.merge(f.context,'refused-empty'),(error:unknown)=>{
  if(ownership==='proved')assert.deepEqual((error as {result:unknown}).result,request.result);
  else assert.equal((error as {code:string}).code,'coordinator.unknown');
  return true;
 });assert.equal(updates,1);assert.deepEqual(f.workspace.request(request.id),request);
 if(ownership==='proved'){
  const c=f.workspace.context(f.context);assert.equal(c.nativeCheckout!.state,'active');assert.equal(await f.fingerprint(),privateWork);
  assert.equal((await research.open(c.target,c.session,{autoAnalyze:false},'inspect-retained') as {state:string}).state,'ready');
  assert.equal((await f.backend.fields(f.workspace.context(c).workingSnapshot!,[{address:'1000',field:'comment.eol'}]))['1000@comment.eol']!.value,'private comment');
 }else{
  assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'verified');
  await assert.rejects(research.open(f.context.target,f.context.session,{autoAnalyze:false},'unknown-retained'));assert.equal(updates,1);
 }
 assert.ok(!f.calls.some(c=>c.operation==='drop'||c.operation==='checkin'));
});

for(const invalid of ['missing proof','wrong source','wrong checkout','inactive checkout','publication exists'] as const)test('a retained error cannot bypass unknown safety with '+invalid,async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend);let updates=0;
 f.backend.updateNative=async()=>{updates++;const c=f.workspace.context(f.context);return {state:invalid==='publication exists'?'ready':'empty',revision:1,snapshot:c.workingSnapshot!,sharedSnapshot:c.baseSnapshot!,receivedChanges:0,nativeMergeInvocations:0};};
 const refuse=async()=>{
  const checkout=f.workspace.context(f.context).nativeCheckout!;
  if(invalid==='inactive checkout')f.patch({nativeCheckout:{...checkout,state:'verified'}});
  fail('conflict','Final native release was refused; saved private work is retained.',{state:'retained',
   ...(invalid==='missing proof'?{}:{retention:{schema:1,source:invalid==='wrong source'?'unverified':'native-release-status',checkout:{...checkout,checkoutId:invalid==='wrong checkout'?9:checkout.checkoutId}}})});
 };
 f.backend.finishEmptyNative=refuse;f.backend.publishNative=refuse;
 await assert.rejects(research.merge(f.context,'unproved-empty'));assert.equal(f.workspace.scopedRequest(f.context,'unproved-empty')!.state,'unknown');
 if(invalid==='publication exists')assert.equal(f.workspace.activePublication(f.context.target)!.state,'unknown');
 await assert.rejects(research.merge(f.context,'unproved-empty'));assert.equal(updates,1);
});

for(const refusal of [null,undefined,'unstructured refusal'])test('an unstructured disposal failure preserves unknown safety: '+String(refusal),async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend);let updates=0;
 f.backend.updateNative=async()=>{updates++;const c=f.workspace.context(f.context);return {state:'empty',revision:1,snapshot:c.workingSnapshot!,sharedSnapshot:c.baseSnapshot!,receivedChanges:0,nativeMergeInvocations:0};};
 f.backend.finishEmptyNative=async()=>{throw refusal;};
 await assert.rejects(research.merge(f.context,'unstructured-refusal'),error=>error===refusal);
 assert.equal(f.workspace.scopedRequest(f.context,'unstructured-refusal')!.state,'unknown');
 await assert.rejects(research.merge(f.context,'unstructured-refusal'));assert.equal(updates,1);
});

for(const savedFingerprint of [base,opened])for(const ownership of ['proved','unknown'] as const)test('interrupted pre-upgrade empty disposal reconciles a '+ownership+' refusal from '+(savedFingerprint===base?'base':'legacy opened')+' buffers without Update/check-in replay',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend),request=f.workspace.reserveRequest(f.context,'ghidra.merge',{},'legacy-empty').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});f.workspace.recordRequest(request.id,'unknown',{state:'unknown'});
 const c=f.workspace.context(f.context);f.patch({nativeCheckout:{...f.checkout,state:'verified',...(savedFingerprint===opened?{opened}:{})},workingSnapshot:c.baseSnapshot});
 await f.updateJournal(request.id,savedFingerprint);
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';if(ownership==='unknown')f.state.status={checkedOut:false};
 await assert.rejects(research.merge(f.context,'legacy-empty'));
 assert.equal(f.workspace.request(request.id).state,ownership==='proved'?'failed':'unknown');
 if(ownership==='proved'){
  assert.equal(await f.fingerprint(),privateWork);assert.equal(f.workspace.context(c).nativeCheckout!.state,'active');
  await research.open(c.target,c.session,{autoAnalyze:false},'legacy-inspect');assert.equal(await f.fingerprint(),privateWork);
 }
 assert.ok(!f.calls.some(c=>['update','checkin','drop'].includes(c.operation)));
});

test('an already released legacy opened checkout completes its old empty-merge request without trusting an active opened proof',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend),request=f.workspace.reserveRequest(f.context,'ghidra.merge',{},'legacy-released').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});f.workspace.recordRequest(request.id,'unknown',{state:'unknown'});
 const c=f.workspace.context(f.context);f.patch({nativeCheckout:{...f.checkout,state:'verified',opened},workingSnapshot:c.baseSnapshot});
 await f.updateJournal(request.id,opened);
 // The native boundary represents an independently established completed release receipt.
 f.state.status={checkedOut:false};
 const result=await research.merge(f.context,'legacy-released');assert.equal((result as {state:string}).state,'empty');
 assert.equal(f.workspace.request(request.id).state,'applied');assert.equal(f.workspace.context(c).nativeCheckout!.state,'dropped');
 const release=f.calls.find(call=>call.operation==='release')!;assert.equal(release.parameters.openedVerified,false);
 assert.deepEqual(await research.merge(f.context,'legacy-released'),result);
 assert.ok(!f.calls.some(call=>['update','checkin'].includes(call.operation)));
});

for(const phase of ['before','after'] as const)test('process exit '+phase+' retained-disposal commit never exposes active private work with an unfinished request',async t=>{
 const f=await fixture(t),request=f.workspace.reserveRequest(f.context,'ghidra.merge',{},'interrupted-retention').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});await f.updateJournal(request.id,base);
 f.patch({nativeCheckout:{...f.checkout,state:'verified'},complexChanges:['q_'+randomUUID()]});const prior=f.workspace.context(f.context);
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';
 const privateSnapshot=await f.nativeReceipt({...f.checkout,state:'active'},f.saved());
 const child=fileURLToPath(new URL('./native-retention-child.js',import.meta.url));
 const exit=spawnSync(process.execPath,[child,f.workspace.directory,request.id,JSON.stringify(privateSnapshot),phase],{windowsHide:true,encoding:'utf8'});
 assert.equal(exit.status,phase==='before'?81:82,exit.stderr);
 const restarted=new Workspace(f.workspace.directory,'default');
 try{
  const context=restarted.context(f.context),pending=restarted.request(request.id);
  assert.equal(context.nativeCheckout!.state,phase==='before'?'verified':'active');assert.equal(pending.state,phase==='before'?'running':'failed');
  assert.equal(context.workingSnapshot!.id,phase==='before'?prior.workingSnapshot!.id:privateSnapshot.id);
  assert.equal(context.generation,prior.generation+Number(phase==='after'));assert.deepEqual(context.complexChanges,prior.complexChanges);
  if(phase==='after'){
   const result=pending.result as {state:string;retention:{request:string;snapshot:Artifact}};
   assert.equal(result.state,'retained');assert.equal(result.retention.request,request.id);assert.equal(result.retention.snapshot.id,privateSnapshot.id);
  }
 }finally{restarted.close();}
 const research=new Research(f.workspace,async()=>f.backend);
 if(phase==='before'){
  // The old verified context plus its completed owned Update is enough to retry only release readback, never Update/check-in.
  await research.open(f.context.target,f.context.session,{autoAnalyze:false},'resume-retention');
 }else await research.open(f.context.target,f.context.session,{autoAnalyze:false},'inspect-retention');
 assert.equal(f.workspace.request(request.id).state,'failed');assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'active');assert.equal(await f.fingerprint(),privateWork);
 const outcome=f.workspace.request(request.id).result;
 await assert.rejects(research.merge(f.context,'interrupted-retention'),error=>{assert.deepEqual((error as {result:unknown}).result,outcome);return true;});
 assert.equal((await f.backend.fields(f.workspace.context(f.context).workingSnapshot!,[{address:'1000',field:'comment.eol'}]))['1000@comment.eol']!.value,'private comment');
 assert.ok(!f.calls.some(c=>['update','checkin','drop'].includes(c.operation)));
});

test('requestless retention cannot create the old active-context/unfinished-merge crash window',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend),request=f.workspace.reserveRequest(f.context,'ghidra.merge',{},'unbound-retention').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});await f.updateJournal(request.id,base);
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';
 await assert.rejects(f.backend.finishEmptyNative(f.context),/release remains unproved/);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'verified');assert.equal(f.workspace.request(request.id).state,'running');
 await assert.rejects(research.merge(f.context,'unbound-retention'));
 assert.equal(f.workspace.request(request.id).state,'failed');assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'active');assert.equal(await f.fingerprint(),privateWork);
 await research.open(f.context.target,f.context.session,{autoAnalyze:false},'unbound-inspection');
});

test('retaining private bytes after verified publication never changes its applied request or verified history',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend),request=f.workspace.reserveRequest(f.context,'ghidra.merge',{},'published-retention').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});
 const publication=f.workspace.beginPublication(f.context,request.id,1,f.workspace.context(f.context).workingSnapshot!);f.workspace.publicationIntent(publication.id);
 const shared=await f.receipt({schema:1,engine:'native-checkout-v1',source:'server',version:2,fileId:'file',fingerprint:'e'.repeat(64),origin:f.checkout.origin,repository:f.checkout.repository});
 const published={session:f.context.session,target:f.context.target,state:'merged',sharedRevision:'R2',applied:0,pendingChanges:0};
 f.workspace.finishPublication(publication.id,2,published,shared);
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.release='unknown';f.state.status={baseVersion:2,saved:{fileId:'file',version:2,fingerprint:privateWork}};
 await assert.rejects(f.backend.dropNative(f.context),/private work is retained/);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.state,'active');assert.equal(await f.fingerprint(),privateWork);
 assert.equal(f.workspace.request(request.id).state,'applied');assert.deepEqual(f.workspace.request(request.id).result,published);assert.equal(f.workspace.publication(publication.id).state,'verified');
 assert.deepEqual(await research.merge(f.context,'published-retention'),published);assert.ok(!f.calls.some(c=>['update','checkin','drop'].includes(c.operation)));
});

for(const invalid of ['wrong request context','wrong operation','missing Update','wrong Update identity','check-in journal','publication exists'] as const)test('atomic retention refuses '+invalid+' before changing context or request',async t=>{
 const f=await fixture(t),request=f.workspace.reserveRequest(f.context,invalid==='wrong operation'?'ghidra.refresh':'ghidra.merge',{},'bound-retention').request;
 f.workspace.startRequest(request.id,{kind:'native-merge'});await f.updateJournal(request.id,base);
 f.patch({nativeCheckout:{...f.checkout,state:'verified'}});
 const snapshot=await f.nativeReceipt({...f.checkout,state:'active'},{fileId:f.checkout.fileId,version:1,fingerprint:privateWork});
 let selected=f.context;
 if(invalid==='wrong request context'){
  const other=f.workspace.reserveOpen(f.context.target,'new',{autoAnalyze:false});f.workspace.recordRequest(other.request.id,'failed',{});
  selected=other.context;
 }else if(invalid==='missing Update')await rm(join(f.checkout.root,'operations',request.id+'-update.json'));
 else if(invalid==='wrong Update identity'){
  const path=join(f.checkout.root,'operations',request.id+'-update.json'),journal=JSON.parse(await readFile(path,'utf8'));journal.request.checkoutId=9;await writeFile(path,JSON.stringify(journal));
 }else if(invalid==='check-in journal')await writeFile(join(f.checkout.root,'operations',request.id+'-checkin.json'),'{}');
 else if(invalid==='publication exists')f.workspace.beginPublication(f.context,request.id,1,f.workspace.context(f.context).workingSnapshot!);
 const before=f.workspace.context(f.context),pending=f.workspace.request(request.id);
 assert.throws(()=>f.workspace.retainNativeDisposal(selected,f.workspace.context(selected).generation,before.nativeCheckout!,snapshot,request.id));
 assert.deepEqual(f.workspace.context(f.context),before);assert.deepEqual(f.workspace.request(request.id),pending);
});

for(const operation of ['refresh','merge'] as const)for(const lostReply of [false,true])test(operation+' retains a proved pre-call backup refusal'+(lostReply?' after a lost reply':'')+' without replay',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend);
 f.state.fingerprint=privateWork;f.state.modified=true;f.state.files.push(f.context.target+'.bin.keep');
 const diagnostic='q_'+randomUUID();f.patch({complexChanges:[diagnostic],workingSnapshot:await f.nativeReceipt(f.checkout,f.saved())});
 const original=(f.backend as any).nativeOperation.bind(f.backend);
 let updates=0;
 (f.backend as any).nativeOperation=async(checkout:NativeCheckout,kind:string,parameters:Record<string,unknown>={})=>{
  if(kind!=='update')return original(checkout,kind,parameters);
  updates++;f.calls.push({operation:kind,parameters});
  const request=String(parameters.request);await f.updateJournal(request,privateWork);
  const path=join(f.checkout.root,'operations',request+'-update.json'),journal=JSON.parse(await readFile(path,'utf8'));
  journal.result={state:'conflict',conflict:'Existing native backup is not proved disposable; retain and inspect this project before Update',
   preCallRefusal:{schema:1,operation:'update',invoked:false,reason:'protected_existing_backup',fileId:'private-backup'},
   saved:f.saved(),checkoutId:f.checkout.checkoutId,baseVersion:1,modified:true,nativeMergeInvocations:0};
  await writeFile(path,JSON.stringify(journal));
  if(lostReply)throw Error('Lost completed pre-call refusal reply');
  return journal.result;
 };
 await assert.rejects(research[operation](f.context,'protected-backup'));
 const request=f.workspace.unresolved(f.context)[0]??f.workspace.request(f.calls.find(c=>c.operation==='update')!.parameters.request as string);
 assert.equal(request.state,lostReply?'unknown':'failed');
 if(lostReply)await research.open(f.context.target,f.context.session,{autoAnalyze:false},'recover-backup-refusal');
 assert.equal(f.workspace.request(request.id).state,'failed');
 const result=f.workspace.request(request.id).result;
 await assert.rejects(research[operation](f.context,'protected-backup'),error=>{assert.deepEqual((error as {result:unknown}).result,result);return true;});
 await research.open(f.context.target,f.context.session,{autoAnalyze:false},'inspect-backup-refusal');
 assert.equal(updates,1);assert.equal(f.workspace.context(f.context).nativeCheckout!.checkoutId,3);
 assert.equal(f.workspace.context(f.context).nativeCheckout!.baseVersion,1);assert.equal(await f.fingerprint(),privateWork);
 assert.deepEqual(f.workspace.context(f.context).complexChanges,[diagnostic]);
 assert.equal((await f.backend.fields(f.workspace.context(f.context).workingSnapshot!,[{address:'1000',field:'comment.eol'}]))['1000@comment.eol']!.value,'private comment');
 assert.ok(!f.calls.some(c=>['checkin','discard','release','drop'].includes(c.operation)));
 const journal=JSON.parse(await readFile(join(f.checkout.root,'operations',request.id+'-update.json'),'utf8'));
 assert.equal(journal.result.preCallRefusal.invoked,false);assert.equal(journal.result.nativeMergeInvocations,0);
});

for(const legacy of ['missing result','exception text','incomplete pre-call marker','changed readback'] as const)test('backup protection recovery keeps '+legacy+' unknown without replay',async t=>{
 const f=await fixture(t),research=new Research(f.workspace,async()=>f.backend),request=f.workspace.reserveRequest(f.context,'ghidra.refresh',{},'uncertain-backup').request;
 f.state.fingerprint=privateWork;f.state.modified=true;f.patch({complexChanges:['q_'+randomUUID()]});
 f.workspace.startRequest(request.id,{kind:'native-update'});f.workspace.recordRequest(request.id,'unknown',{state:'unknown'});
 await f.updateJournal(request.id,privateWork);
 const path=join(f.checkout.root,'operations',request.id+'-update.json'),journal=JSON.parse(await readFile(path,'utf8'));
 if(legacy==='changed readback')journal.result={...journal.result,state:'conflict',saved:{...f.saved(),fingerprint:base},preCallRefusal:{schema:1,operation:'update',invoked:false}};
 else{
  delete journal.result;
  if(legacy==='exception text')journal.reason='Existing native backup is not proved disposable; retain and inspect this project before Update';
  if(legacy==='incomplete pre-call marker')journal.preCallRefusal={schema:1,operation:'update',invoked:false};
 }
 await writeFile(path,JSON.stringify(journal));const original=await readFile(path,'utf8');
 assert.deepEqual(await f.backend.recoverUpdate(f.context,request.id),{state:'unknown'});
 await assert.rejects(research.refresh(f.context,'uncertain-backup'));
 assert.equal(f.workspace.request(request.id).state,'unknown');assert.equal(await readFile(path,'utf8'),original);
 assert.equal(await readFile(join(f.checkout.root,'view.rep','database'),'utf8'),'saved private database');
 assert.equal(f.workspace.context(f.context).nativeCheckout!.checkoutId,3);
 assert.ok(!f.calls.some(c=>['update','checkin','discard','release','drop'].includes(c.operation)));
});
