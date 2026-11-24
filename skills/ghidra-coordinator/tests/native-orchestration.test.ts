import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {readFile,writeFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import type {Scope} from '../src/workspace.js';

async function fixture(t:test.TestContext){
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let backend!:SessionBackend;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
 const input=join(f.root,'owned.bin');await writeFile(input,'offline native orchestration');
 const selected=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,scope=['--session',selected.session,'--target',selected.target];
 await f.json(app,['ghidra','comments','set',...scope,'--address','1000','--kind','eol','--text','private']);
 return {f,app,backend,selected,scope};
}
test('primary CLI import closure excludes the legacy scalar merger and legacy coordinator entry',async()=>{
 const visited=new Set<string>();
 async function visit(path:string):Promise<void>{
  if(visited.has(path))return;visited.add(path);const text=await readFile(path,'utf8');
  for(const m of text.matchAll(/(?:from\s*|import\s*\()\s*['"](\.[^'"]+\.js)['"]/g))await visit(resolve(dirname(path),m[1]!));
 }
 await visit(fileURLToPath(new URL('../src/cli.js',import.meta.url)));
 for(const file of ['merge.js','prototype-cli.js','coordinator.js','ghidra.js'])assert.ok(![...visited].some(p=>p.endsWith('/'+file)||p.endsWith('\\'+file)),file);
 const server=await readFile(new URL('../src/server.js',import.meta.url),'utf8');assert.ok(!server.includes('InsightSnapshotPublisher'));assert.ok(server.includes('InsightNativeCheckout'));assert.ok(server.includes('InsightNativeRead'));
});
test('legacy backend capabilities cannot become a scalar fallback in the primary merge',async t=>{
 const {f,app,backend,scope}=await fixture(t);Object.defineProperty(backend,'nativeEngine',{value:undefined});
 const result=await f.run(app,['ghidra','merge',...scope,'--json']);assert.notEqual(result.exitCode,0);assert.match(result.stderr,/scalar fallback is disabled/);
 assert.equal(backend.publications,0);assert.equal(backend.nativeUpdates,0);assert.equal(backend.disposals,0);
});
test('native conflict is terminal for that request, preserves the saved view and never publishes or disposes',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),before=backend.workspace.context(selected);let updates=0;
 backend.updateNative=async()=>{updates++;return {state:'conflict',revision:1,conflict:'Native type decision required'};};
 const args=['ghidra','merge',...scope,'--request-id','native-conflict','--json'];
 for(let i=0;i<2;i++){const result=await f.run(app,args);assert.notEqual(result.exitCode,0);assert.equal(JSON.parse(result.stdout).state,'conflict');}
 assert.equal(updates,1);assert.equal(backend.publications,0);assert.equal(backend.disposals,0);assert.deepEqual(backend.workspace.context(selected),before);
});
test('unknown native Update is never retried and never declared not_updated by snapshot reconciliation',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),before=backend.workspace.context(selected);let updates=0;
 backend.updateNative=async()=>{updates++;throw Error('Lost native Update response');};
 const args=['ghidra','refresh',...scope,'--request-id','unknown-update','--json'];
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.notEqual((await f.run(app,args)).exitCode,0);
 assert.notEqual((await f.run(app,['ghidra','open',...scope,'--json'])).exitCode,0);
 assert.equal(updates,1);assert.equal(backend.publications,0);assert.equal(backend.disposals,0);assert.deepEqual(backend.workspace.context(selected),before);
 assert.equal(backend.workspace.scopedRequest(selected,'unknown-update')!.state,'unknown');
});
test('lost native check-in acknowledgment freezes publication until independent verification, then disposes without another check-in',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t);backend.losePublication=true;backend.cannotVerify=true;
 const args=['ghidra','merge',...scope,'--request-id','lost-checkin','--json'];assert.notEqual((await f.run(app,args)).exitCode,0);
 assert.equal(backend.publications,1);assert.equal(backend.disposals,0);assert.equal(backend.workspace.activePublication(selected.target)!.state,'unknown');
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(backend.publications,1);
 backend.cannotVerify=false;await f.json(app,['ghidra','open',...scope]);assert.equal(backend.disposals,1);
 assert.equal((await f.json(app,args) as {state:string}).state,'merged');assert.equal(backend.publications,1);assert.equal(backend.workspace.activePublication(selected.target),undefined);
});
test('disposal failure cannot erase verified publication or cause the check-in to replay',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t);backend.dropNative=async()=>{throw Error('Lost project deletion acknowledgment');};
 const args=['ghidra','merge',...scope,'--request-id','drop-failed','--json'];assert.notEqual((await f.run(app,args)).exitCode,0);
 assert.equal(backend.publications,1);assert.equal(backend.workspace.scopedRequest(selected,'drop-failed')!.state,'applied');assert.equal(backend.workspace.model(selected.target).state,'ready');
 assert.equal((await f.json(app,args) as {state:string}).state,'merged');assert.equal(backend.publications,1);
});
test('an exact prepared base older than another observed server version cannot be published',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),context=backend.workspace.context(selected);
 backend.workspace.observeShared(selected.target,2,context.baseSnapshot!);
 backend.updateNative=async()=>({state:'ready',revision:1,snapshot:context.workingSnapshot!,sharedSnapshot:context.baseSnapshot!,receivedChanges:0,nativeMergeInvocations:0});
 const result=await f.run(app,['ghidra','merge',...scope,'--json']);assert.notEqual(result.exitCode,0);assert.equal(JSON.parse(result.stdout).reason,'shared_changed');
 assert.equal(backend.publications,0);assert.equal(backend.workspace.activePublication(selected.target),undefined);
});
test('close after verified native disposal acknowledges closed without allocating another checkout',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),context=backend.workspace.context(selected);
 backend.workspace.saveContext(selected,context.generation,{nativeCheckout:{schema:1,context:context.id,root:join(backend.workspace.directory,'disposed'),fileId:'owned-file',checkoutId:1,baseVersion:1,
  origin:'ghidra://127.0.0.1:12345',repository:'owned',path:'/'+selected.target+'.bin',runtimeFingerprint:'a'.repeat(64),state:'dropped'},state:'stopped',scalars:[],complexChanges:[]});
 backend.open=async()=>{throw Error('Close must not allocate a new native project');};
 const args=['ghidra','close',...scope,'--request-id','close-disposed'];assert.equal((await f.json(app,args) as {state:string}).state,'closed');assert.equal((await f.json(app,args) as {state:string}).state,'closed');
 assert.equal(backend.nativeUpdates,0);assert.equal(backend.publications,0);assert.equal(backend.disposals,0);
});
test('explicit program export materializes packed bytes without replacing the working receipt',async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),view=await backend.saved(selected),packed=join(f.root,'materialized.gzf');
 await writeFile(packed,'owned synthetic packed bytes');Object.assign(backend,{snapshotFile:async()=>packed});
 const output=join(f.root,'export.gzf'),result=await f.json(app,['ghidra','program','export',...scope,'--output',output]) as {state:string;sha256:string};
 assert.equal(result.state,'exported');assert.equal(await readFile(output,'utf8'),'owned synthetic packed bytes');
 assert.equal(backend.workspace.context(selected).workingSnapshot!.id,view.id);assert.notEqual(view.sha256,result.sha256);assert.equal(backend.publications,0);
});

for(const savedContext of [false,true])test(`lost native discard acknowledgment recovers without rediscarding (context saved: ${savedContext})`,async t=>{
 const {f,app,backend,selected,scope}=await fixture(t),c=backend.workspace.context(selected);
 const original={schema:1 as const,context:c.id,root:join(backend.workspace.directory,'owned'),fileId:'owned-file',checkoutId:1,baseVersion:1,
  origin:'ghidra://127.0.0.1:12345',repository:'owned',path:'/'+selected.target+'.bin',runtimeFingerprint:'a'.repeat(64),state:'active' as const};
 backend.workspace.saveContext(selected,c.generation,{nativeCheckout:original});let discards=0,recovered=0,verified=false;
 Object.assign(backend,{
  discardNative:async()=>{discards++;if(savedContext){const current=backend.workspace.context(selected);backend.workspace.saveContext(selected,current.generation,{nativeCheckout:{...original,checkoutId:2},scalars:[],complexChanges:[]});}throw Error('Lost discard acknowledgment');},
  recoverDiscardNative:async(_s:Scope,_q:string,checkout:unknown)=>{assert.deepEqual(checkout,original);recovered++;if(!verified)return {state:'unknown'};
   const current=backend.workspace.context(selected);backend.workspace.saveContext(selected,current.generation,{nativeCheckout:{...original,checkoutId:2},scalars:[],complexChanges:[]});
   return {state:'verified',baseRevision:1,retainedKeepFile:'owned.keep'};}
 });
 const args=['ghidra','changes','discard',...scope,'--request-id','lost-discard','--json'];
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(discards,1);
 assert.equal(backend.workspace.scopedRequest(selected,'lost-discard')!.state,'unknown');
 verified=true;const result=await f.json(app,args) as any;assert.equal(result.state,'discarded');assert.equal(result.discardedChanges,1);assert.equal(result.retainedKeepFile,'owned.keep');
 assert.equal(backend.workspace.context(selected).nativeCheckout!.checkoutId,2);assert.deepEqual(await f.json(app,args),result);assert.equal(discards,1);assert.ok(recovered>=2);
});
