import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyMutation} from '../src/mutation-effects.js';
import type {ResearchBackend} from '../src/research.js';
import type {Artifact} from '../src/artifacts.js';
const snapshot={sha256:'a'.repeat(64),kind:'snapshot',size:1} as Artifact;
test('a successful mutation acknowledgment cannot replace immutable saved effect checks',async()=>{
  const backend={inspect:async(actual:Artifact)=>{assert.equal(actual,snapshot);return {exists:false};}} as unknown as ResearchBackend;
  await assert.rejects(verifyMutation(backend,snapshot,'/create_property_map',{name:'Map'},{success:true}),/presence/);
  const volatile={inspect:async()=>({exists:true,name:'Memory',read:true,volatile:false})} as unknown as ResearchBackend;
  await assert.rejects(verifyMutation(volatile,snapshot,'/set_memory_block',{block:'Memory',volatile:true},{success:true}),/volatile/);
  const exact={inspect:async()=>({exists:true,hasValue:true,value:'9223372036854775807'})} as unknown as ResearchBackend;
  assert.equal((await verifyMutation(exact,snapshot,'/set_property',{map:'Map',address:'1000',value:'9223372036854775807'},{})).value,'9223372036854775807');
});
