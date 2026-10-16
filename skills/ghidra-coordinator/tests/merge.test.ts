import test from 'node:test';
import assert from 'node:assert/strict';
import {scalarMerge,scalarRefresh,fieldKey} from '../src/merge.js';
import type {ScalarChange} from '../src/workspace.js';
const change=(address:string,original:string|null,local:string|null):ScalarChange=>({address,field:'comment.eol',original,local});
test('merge compares original/local/shared, preserves null, and any conflict suppresses all publication',()=>{
  const a=change('1000',null,'A'),b=change('1100','old','B');
  const safe=scalarMerge([a,b],false,1,2,{[fieldKey(a)]:{value:null,compatible:true},[fieldKey(b)]:{value:'B',compatible:true}});
  assert.equal(safe.state,'publish');assert.deepEqual(safe.apply,[a]);assert.equal(safe.fullSnapshot,false);
  const conflict=scalarMerge([a,b],false,1,2,{[fieldKey(a)]:{value:null,compatible:true},[fieldKey(b)]:{value:'other',compatible:true}});
  assert.equal(conflict.state,'conflict');assert.deepEqual(conflict.apply,[]);assert.equal(conflict.conflicts[0]?.original,'old');
  assert.equal(scalarMerge([a],false,1,2,{[fieldKey(a)]:{value:'A',compatible:true}}).state,'already_shared');
  assert.equal(scalarMerge([change('1000','A',null)],false,1,2,{'1000@comment.eol':{value:'A',compatible:true}}).state,'publish');
});
test('unchanged base permits full saved state; diverged complex changes and changed dependencies are conflicts',()=>{
  const a=change('1000',null,'A');
  assert.equal(scalarMerge([a],true,1,1,{[fieldKey(a)]:{value:null,compatible:true}}).fullSnapshot,true);
  const locallyRestructured=scalarMerge([a],true,1,1,{[fieldKey(a)]:{value:'before local script',compatible:false}});
  assert.equal(locallyRestructured.state,'publish','Local structural edits are included in the complete unchanged-base result');
  const unresolved={...a,conflict:{shared:'A shared'}};
  assert.equal(scalarMerge([unresolved],true,2,2,{[fieldKey(a)]:{value:'A shared',compatible:true}}).state,'conflict',
    'Adding a structural edit must not bypass a retained refresh conflict');
  const complex=scalarMerge([a],true,1,2,{[fieldKey(a)]:{value:null,compatible:true}});
  assert.equal(complex.state,'conflict');assert.deepEqual(complex.apply,[]);
  const changed=scalarMerge([a],false,1,2,{[fieldKey(a)]:{value:null,compatible:false}});
  assert.equal(changed.conflicts[0]?.reason,'dependency_changed');
  assert.throws(()=>scalarMerge([a],false,2,1,{}),/regressed/);
  assert.throws(()=>scalarMerge([a],false,1,2,{}),/omitted/);
});
test('refresh receives safe incoming fields while preserving local and shared conflict values',()=>{
  const local=change('1000','old','B'),incoming=change('1000','old','A'),other=change('1100',null,'incoming');
  const result=scalarRefresh([local],[incoming,other],{[fieldKey(incoming)]:{value:'A',compatible:true},[fieldKey(other)]:{value:'incoming',compatible:true}});
  assert.deepEqual(result.receive,[other]);assert.equal(result.preserve[0]?.local,'B');assert.equal(result.preserve[0]?.conflict?.shared,'A');
  assert.equal(result.conflicts[0]?.original,'old');
  const same=scalarRefresh([local],[incoming],{[fieldKey(incoming)]:{value:'B',compatible:true}});
  assert.deepEqual(same.preserve,[]);assert.deepEqual(same.conflicts,[]);
});
