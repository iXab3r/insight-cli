import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {Research} from '../src/research.js';
import {fail} from '../src/model.js';
import {recoveryFixture} from './scoped-recovery-fixture.js';

async function refusalFixture(t:test.TestContext){
  const f=await recoveryFixture(t),w=f.workspace,q=w.reserveRequest(f.scope,'ghidra.merge',{},'lost-refusal').request;
  w.startRequest(q.id,{kind:'native-merge'});w.beginPublication(f.scope,q.id,1,f.local);w.publicationIntent(q.id);
  w.recordRequest(q.id,'unknown',{state:'unknown'});w.unknownPublication(q.id,{state:'unknown'});
  const request={root:f.checkout.root,owner:f.owner,operation:'checkin',fileId:f.checkout.fileId,checkoutId:f.checkout.checkoutId,
    request:q.id,fingerprint:f.saved.fingerprint,expectedVersion:1};
  const journal:any={request,before:f.saved,checkoutId:3,baseVersion:1,headVersion:2,backupAbsent:true,backupBeforeFileId:null,backupExpected:false,
    result:{state:'conflict',conflict:'Shared head changed before native check-in',saved:f.saved,checkoutId:3,baseVersion:1,modified:true,nativeMergeInvocations:0,nativePhases:[]}};
  const path=join(f.checkout.root,'operations',q.id+'-checkin.json'),write=()=>writeFile(path,JSON.stringify(journal));await write();
  return {...f,get workspace(){return f.workspace;},q,journal,path,write};
}

test('lost pre-call refusal settles request/publication/model after restart and retrieval without replay or disposal',async t=>{
  const f=await refusalFixture(t),before=f.workspace.context(f.scope),original=await readFile(f.path,'utf8');f.restart();
  const w=f.workspace,backend=f.backend(),research=new Research(w,async()=>backend);let opened=0;
  Object.assign(backend,{open:async()=>{opened++;return w.context(f.scope);},dropNative:async()=>{throw Error('Refused work must not be disposed');}});
  await assert.rejects(research.merge(f.scope,'lost-refusal'),(error:any)=>error.code==='coordinator.conflict'&&error.result.state==='conflict');
  assert.equal(w.request(f.q.id).state,'failed');assert.equal(w.publication(f.q.id).state,'conflict');assert.equal(w.model(f.scope.target).state,'ready');
  assert.equal(w.model(f.scope.target).sharedRevision,2);assert.equal(w.activePublication(f.scope.target),undefined);assert.deepEqual(w.context(f.scope),before);
  const result:any=w.request(f.q.id).result;assert.equal(result.applied,0);assert.equal(result.pendingChanges,1);assert.equal(result.reason,'shared_changed');
  assert.equal(result.reconciled,true);assert.equal(opened,0);assert.equal(await readFile(f.path,'utf8'),original);
  assert.equal(await readFile(f.bytes,'utf8'),'synthetic saved local program bytes');assert.ok(f.calls.every(q=>['verify','latest','status','history'].includes(String(q.operation))));
  const calls=f.calls.length;
  await assert.rejects(research.merge(f.scope,'lost-refusal'),(e:any)=>e.code==='coordinator.conflict');assert.equal(f.calls.length,calls);
  await research.open(f.scope.target,f.scope.session,{autoAnalyze:false});assert.equal(opened,1);assert.deepEqual(w.context(f.scope).nativeCheckout,before.nativeCheckout);
  // A different intentional request is admitted to Update; this boundary creates no native work.
  Object.assign(backend,{updateNative:async()=>({state:'conflict',revision:1,conflict:'Fresh Update admitted'})});
  await assert.rejects(research.merge(f.scope,'fresh-intent'),/Native conflict/);assert.equal(w.scopedRequest(f.scope,'fresh-intent')!.state,'failed');
});

test('lost refusal recovers when the native reader throws its missing-marker error',async t=>{
  const f=await refusalFixture(t),before=f.workspace.context(f.scope),journal=await readFile(f.path,'utf8');
  const read=f.server.nativeRead.bind(f.server);
  f.server.nativeRead=async(binding,request)=>{
    const value=await read(binding,request);
    // InsightNativeRead emits unknown + reason; GhidraServer.run transports it as this CliError.
    if(request.operation==='verify')fail('unknown','Native history marker is unresolved',{diagnostic:'IllegalStateException'});
    return value;
  };
  const backend=f.backend();await new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend);
  assert.equal(f.workspace.request(f.q.id).state,'failed');assert.equal(f.workspace.publication(f.q.id).state,'conflict');
  assert.equal(f.workspace.model(f.scope.target).state,'ready');assert.deepEqual(f.workspace.context(f.scope),before);
  assert.equal(await readFile(f.path,'utf8'),journal);assert.ok(f.calls.every(q=>!['checkin','discard','release','drop'].includes(String(q.operation))));
});

for(const control of [
  {name:'unrelated unknown reason',code:'unknown',message:'Native item is absent or busy',diagnostic:'IllegalStateException'},
  {name:'different native diagnostic',code:'unknown',message:'Native history marker is unresolved',diagnostic:'SecurityException'},
  {name:'missing native diagnostic',code:'unknown',message:'Native history marker is unresolved',diagnostic:undefined},
  {name:'transport failure',code:'transport',message:'Native history marker is unresolved',diagnostic:'IllegalStateException'},
  {name:'migration requirement',code:'migration',message:'Native history marker is unresolved',diagnostic:'IllegalStateException'},
])test('refusal recovery preserves '+control.name+' as unknown',async t=>{
  const f=await refusalFixture(t),before=f.workspace.context(f.scope),read=f.server.nativeRead.bind(f.server);
  f.server.nativeRead=async(binding,request)=>{
    const value=await read(binding,request);
    if(request.operation==='verify')fail(control.code,control.message,{diagnostic:control.diagnostic});
    return value;
  };
  const backend=f.backend();await assert.rejects(new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend),
    (error:any)=>error.code==='coordinator.'+control.code&&error.message===control.message);
  assert.equal(f.workspace.request(f.q.id).state,'unknown');assert.equal(f.workspace.publication(f.q.id).state,'unknown');
  assert.equal(f.workspace.model(f.scope.target).state,'unknown');assert.deepEqual(f.workspace.context(f.scope),before);
  assert.deepEqual(f.calls.map(q=>q.operation),['verify']);
});

const journalControls:Record<string,(j:any)=>void>={
  'incomplete result':j=>{delete j.result.saved;},
  'early minimal refusal receipt':j=>{j.result={state:'conflict',conflict:j.result.conflict};},
  'missing result':j=>{delete j.result;},
  'foreign owner':j=>{j.request.owner={...j.request.owner,context:'foreign'};},
  'foreign request':j=>{j.request.request='q_foreign';},
  'different root':j=>{j.request.root+='-other';},
  'different operation':j=>{j.request.operation='update';},
  'different file ID':j=>{j.request.fileId='foreign';},
  'different checkout':j=>{j.request.checkoutId=4;},
  'different expected head':j=>{j.request.expectedVersion=2;},
  'different candidate bytes':j=>{j.request.fingerprint='e'.repeat(64);},
  'no actual head race':j=>{j.headVersion=1;},
  'fractional head':j=>{j.headVersion=2.1;},
  'changed before bytes':j=>{j.before={...j.before,fingerprint:'e'.repeat(64)};},
  'changed result bytes':j=>{j.result.saved={...j.result.saved,fingerprint:'e'.repeat(64)};},
  'changed result base':j=>{j.result.baseVersion=2;},
  'missing modified state':j=>{delete j.result.modified;},
  'check-in barrier entered':j=>{j.marker='insight native '+j.request.request;},
  'merge invoked':j=>{j.result.nativeMergeInvocations=1;},
  'native phase recorded':j=>{j.result.nativePhases=['merge'];},
  'unchecked refusal string':j=>{j.result.conflict='timeout';},
};
for(const [name,change]of Object.entries(journalControls))test(`refusal recovery keeps ${name} unknown`,async t=>{
  const f=await refusalFixture(t);change(f.journal);await f.write();const original=await readFile(f.path,'utf8'),before=f.workspace.context(f.scope),backend=f.backend();
  await new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend);
  assert.equal(f.workspace.request(f.q.id).state,'unknown');assert.equal(f.workspace.publication(f.q.id).state,'unknown');assert.equal(f.workspace.model(f.scope.target).state,'unknown');
  assert.deepEqual(f.workspace.context(f.scope),before);assert.equal(await readFile(f.path,'utf8'),original);assert.ok(f.calls.every(q=>q.operation!=='checkin'));
});

const statusControls:Record<string,(f:Awaited<ReturnType<typeof refusalFixture>>)=>void>={
  'local saved bytes changed':f=>{f.state.status={...f.state.status,saved:{...f.saved,fingerprint:'e'.repeat(64)}};},
  'local source metadata changed':f=>{f.state.status={...f.state.status,saved:{...f.saved,language:'foreign'}};},
  'local checkout changed':f=>{f.state.status={...f.state.status,checkoutId:4};},
  'local recoverable buffers':f=>{f.state.status={...f.state.status,recoverable:true};},
  'local checkin active':f=>{f.state.status={...f.state.status,checkinActive:true};},
  'reader checkin active':f=>{f.state.history.checkinActive=true;},
  'reader repository changed':f=>{f.state.history.repository='foreign';},
  'reader program changed':f=>{f.state.history.path='/other.bin';},
  'reader checkout disappeared':f=>{f.state.history.checkouts=[];},
  'reader history missing':f=>{delete f.state.history.versions;},
  'reader head regressed':f=>{f.state.history.version=1;},
  'reader success marker exists':f=>{f.state.history.versions=[{version:1,comment:'initial'},{version:2,comment:'insight native '+f.q.id}];},
  'independent readback unknown':f=>{f.state.shared={state:'unknown'};},
  'independent file ID changed':f=>{f.state.shared.fileId='foreign';},
};
for(const [name,change]of Object.entries(statusControls))test(`refusal recovery preserves freeze when ${name}`,async t=>{
  const f=await refusalFixture(t);change(f);const backend=f.backend();
  try{await new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend);}catch(e){assert.match(String(e),/unverified/);}
  assert.equal(f.workspace.request(f.q.id).state,'unknown');assert.equal(f.workspace.publication(f.q.id).state,'unknown');assert.equal(f.workspace.model(f.scope.target).state,'unknown');
  assert.ok(f.calls.every(q=>q.operation!=='checkin'));
});

test('a live first-start worker freezes refusal recovery and preserves its launch evidence',async t=>{
  const f=await refusalFixture(t),binding=f.processBinding(process.pid),path=join(f.checkout.root,'process.json');await writeFile(path,JSON.stringify(binding));
  assert.deepEqual(await f.backend().recover(f.workspace.publication(f.q.id)),{state:'unknown'});
  assert.equal(await readFile(path,'utf8'),JSON.stringify(binding));assert.equal(f.workspace.request(f.q.id).state,'unknown');
});

test('successful native publication recovery retains independent marker and exact-buffer readback',async t=>{
  const f=await refusalFixture(t);f.state.verify={state:'verified',version:2};f.state.shared.fingerprint=f.saved.fingerprint;
  const backend=f.backend();let dropped=0;Object.assign(backend,{dropNative:async()=>{dropped++;}});
  await new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend);
  assert.equal(f.workspace.request(f.q.id).state,'applied');assert.equal(f.workspace.publication(f.q.id).state,'verified');assert.equal(dropped,1);
  assert.deepEqual(f.calls.map(q=>q.operation),['verify','latest']);
});

test('generic rejection cannot thaw unknown publication and refusal commit is atomic on stale context',async t=>{
  const f=await refusalFixture(t),w=f.workspace;
  assert.throws(()=>w.rejectPublication(f.q.id,{}),/without proof/);
  const current=w.context(f.scope);w.saveContext(f.scope,current.generation,{state:'needs_recovery'});
  assert.throws(()=>w.finishRefusedPublication(f.q.id,2,f.shared,{}),/retained intent/);
  assert.equal(w.request(f.q.id).state,'unknown');assert.equal(w.publication(f.q.id).state,'unknown');assert.equal(w.model(f.scope.target).state,'unknown');
});

for(const drift of ['history','checkout','journal'])test(`refusal remains unknown if ${drift} changes during independent readback`,async t=>{
  const f=await refusalFixture(t),read=f.server.nativeRead.bind(f.server),operation=f.server.nativeCheckout.bind(f.server);let statuses=0;
  if(drift==='checkout')f.server.nativeCheckout=async(b,q)=>{
    const result=await operation(b,q);return ++statuses===1?result:{...result,saved:{...f.saved,fingerprint:'e'.repeat(64)}};
  };
  f.server.nativeRead=async(b,q)=>{
    const result=await read(b,q);
    if(q.operation==='latest'){
      if(drift==='history')f.state.history={...f.state.history,version:3,versions:[...(f.state.history.versions as object[]),{version:3,comment:'later writer'}]};
      if(drift==='journal')await writeFile(f.path,JSON.stringify({...f.journal,marker:'uncertain check-in barrier'}));
    }return result;
  };
  const backend=f.backend();await new Research(f.workspace,async()=>backend).reconcileRequests(f.scope,backend);
  assert.equal(f.workspace.request(f.q.id).state,'unknown');assert.equal(f.workspace.publication(f.q.id).state,'unknown');assert.equal(f.workspace.model(f.scope.target).state,'unknown');
  assert.ok(f.calls.every(q=>q.operation!=='checkin'));
});
