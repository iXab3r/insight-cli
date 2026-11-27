import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile,readFile} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {randomUUID} from 'node:crypto';
import {recoveryFixture} from './scoped-recovery-fixture.js';

for(const suffix of ['.keep','.keep.1','.keep.12','.keep.0','.keep.01','.keep.-1','.keep.1x','.keep.1/extra','.keep.1.gzf'])
test(`completed discard recovery accepts only exact native backup names: ${suffix}`,async t=>{
  const f=await recoveryFixture(t),request='q_'+randomUUID(),name=basename(f.checkout.path)+suffix;
  const saved={...f.saved,version:2,fingerprint:String(f.state.shared.fingerprint)},value={state:'discarded',checkoutId:4,baseVersion:2,modified:false,saved,retainedKeepFile:name};
  const q={root:f.checkout.root,owner:f.owner,operation:'discard',request,fileId:f.checkout.fileId,checkoutId:3};
  const journal=join(f.checkout.root,'operations',request+'-discard.json');await writeFile(journal,JSON.stringify({request:q,result:value}));
  f.state.status={...f.state.status,checkoutId:4,baseVersion:2,modified:false,saved,checkouts:[{id:4,version:2}],projectFiles:[basename(f.checkout.path),name]};
  const before=f.workspace.context(f.scope),result=await f.backend().recoverDiscardNative(f.scope,request,f.checkout);
  if(['.keep','.keep.1','.keep.12'].includes(suffix)){
    assert.deepEqual(result,{state:'verified',baseRevision:2,retainedKeepFile:name});assert.equal(f.workspace.context(f.scope).nativeCheckout!.checkoutId,4);
  }else{assert.deepEqual(result,{state:'unknown'});assert.deepEqual(f.workspace.context(f.scope),before);}
  assert.ok(f.calls.every(q=>q.operation==='status'||q.operation==='latest'));assert.equal(await readFile(f.bytes,'utf8'),'synthetic saved local program bytes');
});

for(const problem of ['foreign basename','missing inventory','old checkout remains','saved bytes changed','independent bytes changed'])
test(`numbered discard backup preserves independent gates: ${problem}`,async t=>{
  const f=await recoveryFixture(t),request='q_'+randomUUID(),name=(problem==='foreign basename'?'foreign.bin':basename(f.checkout.path))+'.keep.1';
  const saved={...f.saved,version:2,fingerprint:String(f.state.shared.fingerprint)},value={state:'discarded',checkoutId:4,baseVersion:2,modified:false,saved,retainedKeepFile:name};
  const q={root:f.checkout.root,owner:f.owner,operation:'discard',request,fileId:f.checkout.fileId,checkoutId:3};
  await writeFile(join(f.checkout.root,'operations',request+'-discard.json'),JSON.stringify({request:q,result:value}));
  f.state.status={...f.state.status,checkoutId:4,baseVersion:2,modified:false,saved,checkouts:[{id:4,version:2}],projectFiles:[basename(f.checkout.path),name]};
  if(problem==='missing inventory')f.state.status.projectFiles=[basename(f.checkout.path)];
  if(problem==='old checkout remains')f.state.status.checkouts=[{id:3,version:1},{id:4,version:2}];
  if(problem==='saved bytes changed')f.state.status.saved={...saved,fingerprint:'e'.repeat(64)};
  if(problem==='independent bytes changed')f.state.shared.fingerprint='e'.repeat(64);
  const before=f.workspace.context(f.scope);
  try{assert.deepEqual(await f.backend().recoverDiscardNative(f.scope,request,f.checkout),{state:'unknown'});}
  catch(e){assert.equal(problem,'independent bytes changed');assert.match(String(e),/differs from independent server/);}
  assert.deepEqual(f.workspace.context(f.scope),before);assert.ok(f.calls.every(q=>q.operation==='status'||q.operation==='latest'));
});
