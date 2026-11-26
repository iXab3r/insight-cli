import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {createInsightCli} from '../src/cli.js';
import {GhidraContexts} from '../src/contexts.js';
import type {ResearchBackend} from '../src/research.js';
import type {Workspace,Scope,NativeCheckout,Publication} from '../src/workspace.js';

const base='a'.repeat(64),opened='b'.repeat(64),edited='c'.repeat(64),incoming='d'.repeat(64);
const origin='ghidra://127.0.0.1:12345',repository='owned',fileId='owned-file';
type Updated=Awaited<ReturnType<NonNullable<ResearchBackend['updateNative']>>>;
// Exercise the production classification, receipts, disposal and recovery with a synthetic native boundary.
// Ghidra's actual Update/check-in and its open-time rewrite still require disposable native acceptance.
const applyUpdate=(GhidraContexts.prototype as unknown as {
 applyNativeUpdate(scope:Scope,request:string,value:Record<string,unknown>,previousBase:number):Promise<Updated>;
}).applyNativeUpdate;
async function fixture(t:test.TestContext){
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
 let workspace!:Workspace,backend!:GhidraContexts,checkoutId=0;
 const state={fingerprint:opened,modified:true,checkedOut:true,revision:1,updateState:'updated',updates:0,publications:0,saves:0,opens:0,releases:0,drops:0,failCleanup:''};
 const bases=new Map([[1,base]]),beforePublication:NativeCheckout[]=[],releaseParameters:Record<string,unknown>[]=[];
 const receipt=async(value:unknown)=>{const path=join(f.root,randomUUID()+'.json');await writeFile(path,JSON.stringify(value));return workspace.captureNative(path);};
 const owner=(checkout:NativeCheckout)=>({context:checkout.context,origin,repository,path:checkout.path});
 const saved=(checkout:NativeCheckout)=>({fileId,version:checkout.baseVersion,fingerprint:state.fingerprint});
 const reference=async(target:string,version=1,fingerprint=opened,patch:Record<string,unknown>={})=>{
  const root=join(workspace.directory,'ghidra-native','shared-views',target,'opened');await mkdir(root,{recursive:true});
  const path=join(root,'v'+version+'-'+fingerprint+'.json');
  await writeFile(path,JSON.stringify({schema:2,target,origin,repository,version,fileId,base:bases.get(version),opened:fingerprint,
   preOpen:{fingerprint:bases.get(version),fileId,checkoutId,baseVersion:version},...patch}));return path;
 };
 const serverView=async(target:string,version=state.revision)=>{
  assert.ok(bases.has(version),'The exact native server version must exist');
  const value={source:'server',target,origin,repository,version,fileId,fingerprint:bases.get(version)};
  return {revision:version,snapshot:await receipt(value),value};
 };
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{
  workspace=w;
  backend=Object.create(GhidraContexts.prototype) as GhidraContexts;
  Object.assign(backend,{workspace,nativeEngine:'native-checkout-v1',fork:()=>backend,serverView,nativeOwner:async(checkout:NativeCheckout)=>({owner:owner(checkout)}),
   open:async(scope:Scope,request?:string)=>{
    if(workspace.unresolved(scope).some(q=>q.id!==request))throw Error('Unresolved native fixture intent');
    let c=workspace.context(scope);if(c.nativeCheckout?.state==='active')return c;
    state.opens++;state.checkedOut=true;
    const checkout:NativeCheckout={schema:1,context:c.id,root:join(workspace.directory,'ghidra-native','context',c.id,'owned-'+(++checkoutId)),fileId,checkoutId,
     baseVersion:state.revision,origin,repository,path:'/'+scope.target+'.bin',runtimeFingerprint:'e'.repeat(64),state:'active'};
    await mkdir(checkout.root,{recursive:true});const shared=await serverView(scope.target);
    if(!workspace.model(scope.target).sharedSnapshot)workspace.establishModel(scope.target,shared.revision,shared.snapshot);
    const snapshot=await receipt({engine:'native-checkout-v1',source:'checkout',checkout,...saved(checkout)});
    await reference(scope.target,state.revision,state.fingerprint);
    return workspace.saveContext(c,c.generation,{nativeCheckout:checkout,state:'ready',baseRevision:checkout.baseVersion,baseSnapshot:shared.snapshot,workingSnapshot:snapshot});
   },
   saved:async(scope:Scope)=>{state.saves++;const checkout=workspace.context(scope).nativeCheckout!;
    return receipt({engine:'native-checkout-v1',source:'checkout',checkout,...saved(checkout)});},
   updateNative:async(scope:Scope,request:string)=>{
    state.updates++;const checkout=workspace.context(scope).nativeCheckout!;
    const result={state:state.updateState,checkoutId:checkout.checkoutId,baseVersion:state.revision,modified:state.modified,
     saved:{...saved(checkout),version:state.revision},nativeMergeInvocations:Number(state.revision!==checkout.baseVersion),conflict:'Native decision required'};
    const operations=join(checkout.root,'operations');await mkdir(operations,{recursive:true});
    await writeFile(join(operations,request+'-update.json'),JSON.stringify({request:{request,root:checkout.root,fileId,checkoutId:checkout.checkoutId,owner:owner(checkout)},result}));
    return applyUpdate.call(backend,scope,request,result,checkout.baseVersion);
   },
   nativeOperation:async(checkout:NativeCheckout,operation:string,parameters:Record<string,unknown>)=>{
    if(operation==='status')return {state:'ready',checkedOut:state.checkedOut,modified:state.modified,recoverable:false,fileId,checkoutId:checkout.checkoutId,baseVersion:state.revision,
     saved:{...saved(checkout),version:state.revision},projectFiles:[checkout.path.slice(1)]};
    assert.ok(['release','drop'].includes(operation),'No native check-in may bypass the publication boundary');
    if(operation==='release'){state.releases++;releaseParameters.push(parameters);state.checkedOut=false;}else state.drops++;
    if(state.failCleanup===operation){state.failCleanup='';throw Error('Lost native '+operation+' acknowledgment');}
    return {state:operation==='release'?'released':'dropped'};
   },
   publishNative:async(publication:Publication)=>{
    state.publications++;beforePublication.push(workspace.context(publication).nativeCheckout!);
    const revision=publication.expectedRevision+1;bases.set(revision,state.fingerprint);state.revision=revision;state.modified=false;
    return {state:'published',revision,snapshot:(await serverView(publication.target,revision)).snapshot};
   },
   closed:async()=>true,mode:async()=>{},close:async()=>{},dispose:async()=>{}
  });
  return backend;
 }}));
 const input=join(f.root,'owned.bin');await writeFile(input,'native empty merge offline fixture');
 const who=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,selected={session:who.session,target:who.target};
 const scope=['--session',selected.session,'--target',selected.target];
 return {f,app,workspace,backend,selected,scope,state,bases,reference,beforePublication,releaseParameters};
}

for(const policy of ['manual','after-save','after-edit'])test('pristine native open/save avoids check-in and keeps its revision: '+policy,async t=>{
 const {f,app,workspace,selected,scope,state,releaseParameters}=await fixture(t);
 await f.json(app,['ghidra','sync-policy','set',...scope,'--publish',policy,'--refresh','manual']);
 const args=policy==='manual'?['ghidra','merge',...scope,'--request-id','untouched-merge']:['ghidra','save',...scope,'--request-id','untouched-save'];
 if(policy==='manual')await f.json(app,['ghidra','save',...scope]);
 const result=await f.json(app,args) as any,publication=policy==='manual'?result:result.automatic.publication;
 assert.deepEqual(publication,{...selected,state:'empty',applied:0,pendingChanges:0,sharedRevision:'R1',engine:'ghidra-native'});
 assert.equal(state.publications,0);assert.equal(state.updates,1);assert.equal(state.drops,1);
 assert.equal(workspace.model(selected.target).sharedRevision,1);assert.equal(workspace.context(selected).nativeCheckout!.state,'dropped');
 assert.equal(releaseParameters[0]!.fingerprint,base);assert.equal(releaseParameters[0]!.opened,opened);
 const saves=state.saves;assert.deepEqual(await f.json(app,args),result);assert.equal(state.updates,1);assert.equal(state.saves,saves);
 const again=await f.json(app,['ghidra','open',...scope]) as any;
 assert.equal(again.session,selected.session);assert.equal(again.target,selected.target);assert.equal(again.baseRevision,'R1');assert.equal(again.sharedRevision,'R1');
 assert.equal(state.opens,2);assert.equal(state.publications,0);
});

for(const policy of ['manual','after-save'])test('real saved native edits publish with zero CLI diagnostic changes: '+policy,async t=>{
 const {f,app,workspace,selected,scope,state,beforePublication}=await fixture(t);
 await f.json(app,['ghidra','sync-policy','set',...scope,'--publish',policy,'--refresh','manual']);
 const checkout=workspace.context(selected).nativeCheckout!;state.fingerprint=edited;
 assert.equal(workspace.context(selected).scalars.length+workspace.context(selected).complexChanges.length,0);
 const result=await f.json(app,[...['ghidra',policy==='manual'?'merge':'save'],...scope]) as any;
 const publication=policy==='manual'?result:result.automatic.publication;
 assert.equal(publication.state,'merged');assert.equal(publication.applied,0);assert.equal(publication.sharedRevision,'R2');
 assert.equal(state.publications,1);assert.equal(beforePublication[0]!.checkoutId,checkout.checkoutId);assert.equal(state.drops,1);
});

for(const patch of [{fileId:'another-file'},{origin:'ghidra://127.0.0.1:9999'},{repository:'another-repository'},{version:2},{base:edited},{target:'t_another'}])
 test('unbound pristine-open proof cannot suppress native publication: '+JSON.stringify(patch),async t=>{
  const {f,app,selected,scope,state,reference}=await fixture(t);await reference(selected.target,1,opened,patch);
  const result=await f.json(app,['ghidra','merge',...scope]) as any;
  assert.equal(result.state,'merged');assert.equal(result.sharedRevision,'R2');assert.equal(state.publications,1);
 });

test('native Update ancestry and incoming work survive a proof that only names the old base',async t=>{
 const {f,app,workspace,selected,scope,state,bases,beforePublication}=await fixture(t),original=workspace.context(selected).nativeCheckout!;
 bases.set(2,incoming);state.revision=2;
 const result=await f.json(app,['ghidra','merge',...scope]) as any;
 assert.equal(result.state,'merged');assert.equal(result.sharedRevision,'R3');assert.equal(state.publications,1);
 assert.equal(beforePublication[0]!.checkoutId,original.checkoutId);assert.equal(beforePublication[0]!.baseVersion,2);
});

test('an incoming native Update that exactly matches its new base creates no further version',async t=>{
 const {f,app,workspace,selected,scope,state,bases}=await fixture(t);
 bases.set(2,incoming);state.revision=2;state.fingerprint=incoming;state.modified=false;
 const result=await f.json(app,['ghidra','merge',...scope]) as any;
 assert.equal(result.state,'empty');assert.equal(result.sharedRevision,'R2');assert.equal(state.publications,0);
 assert.equal(workspace.context(selected).nativeCheckout!.baseVersion,2);assert.equal(workspace.model(selected.target).sharedRevision,2);
});

test('native Update can be empty against a proved pristine-open state of its new base',async t=>{
 const {f,app,workspace,selected,scope,state,bases,reference}=await fixture(t),checkout=workspace.context(selected).nativeCheckout!;
 bases.set(2,incoming);state.revision=2;state.fingerprint='f'.repeat(64);await reference(selected.target,2,state.fingerprint);
 const result=await f.json(app,['ghidra','merge',...scope]) as any;
 assert.equal(result.state,'empty');assert.equal(result.sharedRevision,'R2');assert.equal(state.publications,0);
 assert.equal(workspace.context(selected).nativeCheckout!.checkoutId,checkout.checkoutId);assert.equal(workspace.context(selected).nativeCheckout!.baseVersion,2);
});

for(const automatic of [false,true])for(const phase of ['release','drop','result'])
 test(`interrupted pristine empty cleanup retrieves its request without native replay (${automatic?'after-save':'merge'}, ${phase})`,async t=>{
  const {f,app,workspace,backend,selected,scope,state}=await fixture(t);
  if(automatic)await f.json(app,['ghidra','sync-policy','set',...scope,'--publish','after-save','--refresh','manual']);
  if(phase==='result'){
   const finish=backend.finishEmptyNative.bind(backend);let once=true;
   backend.finishEmptyNative=async s=>{await finish(s);if(once){once=false;throw Error('Lost empty result acknowledgment');}};
  }else state.failCleanup=phase;
  const args=['ghidra',automatic?'save':'merge',...scope,'--request-id','empty-interrupted'];
  assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);
  assert.equal(workspace.context(selected).nativeCheckout!.state,phase==='result'?'dropped':'verified');
  const saves=state.saves,result=await f.json(app,args) as any;
  const publication=automatic?result.automatic.publication:result;
  assert.equal(publication.state,'empty');assert.equal(publication.sharedRevision,'R1');assert.equal(state.publications,0);
  assert.equal(state.updates,1);assert.equal(state.saves,saves);assert.equal(workspace.context(selected).nativeCheckout!.state,'dropped');
  assert.deepEqual(await f.json(app,args),result);assert.equal(state.updates,1);
 });

for(const patch of [{saved:{fileId,version:1,fingerprint:edited}},{baseVersion:2},{checkoutId:999},{state:'unknown'},{modified:undefined}])
 test('unproved empty completion stays unknown without a check-in: '+JSON.stringify(patch),async t=>{
  const {f,app,workspace,selected,scope,state}=await fixture(t);state.failCleanup='drop';
  const args=['ghidra','merge',...scope,'--request-id','unproved-empty'];
  assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);
  const checkout=workspace.context(selected).nativeCheckout!,request=workspace.scopedRequest(selected,'unproved-empty')!;
  const path=join(checkout.root,'operations',request.id+'-update.json'),journal=JSON.parse(await readFile(path,'utf8'));
  journal.result={...journal.result,...patch};await writeFile(path,JSON.stringify(journal));
  assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);
  assert.equal(workspace.request(request.id).state,'unknown');assert.equal(state.updates,1);assert.equal(state.publications,0);assert.equal(state.drops,1);
 });

for(const outcome of ['conflict','unknown'])test('native '+outcome+' never becomes an empty publication',async t=>{
 const {f,app,workspace,selected,scope,state}=await fixture(t),before=workspace.context(selected);state.updateState=outcome;
 const args=['ghidra','merge',...scope,'--request-id','native-'+outcome,'--json'];
 for(let i=0;i<2;i++)assert.notEqual((await f.run(app,args)).exitCode,0);
 const after=workspace.context(selected);
 assert.equal(after.workingSnapshot!.id,before.workingSnapshot!.id);assert.equal(after.nativeCheckout!.checkoutId,before.nativeCheckout!.checkoutId);
 assert.equal(after.nativeCheckout!.baseVersion,1);assert.equal(state.publications,0);assert.equal(state.releases,0);assert.equal(state.drops,0);assert.equal(state.updates,1);
});
