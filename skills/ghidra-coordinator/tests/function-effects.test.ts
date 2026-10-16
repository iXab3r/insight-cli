import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyFunctionMutation} from '../src/function-effects.js';
import type {ResearchBackend} from '../src/research.js';
import type {Artifact} from '../src/artifacts.js';
const snapshot={sha256:'a'.repeat(64),kind:'snapshot',size:1} as Artifact;
test('function batch verification rejects an omitted member and rounded/missing saved effects',async()=>{
  const backend={inspect:async(_snapshot:Artifact,p:Record<string,unknown>)=>p.kind==='resolve_type'?{exists:true,type:{name:'uint'}}:
    {exists:true,name:'first',noReturn:false,variables:[{name:'count',type:'int',storage:'ECX:4'}],tags:[{name:'reviewed',comment:''}]}} as unknown as ResearchBackend;
  await assert.rejects(verifyFunctionMutation(backend,snapshot,'/set_variables',{function:'first',variables:'{"param_1":{"name":"count","type":"uint"}}'},{}),/type/);
  await assert.rejects(verifyFunctionMutation(backend,snapshot,'/add_function_tag',{function:'first',tags:'reviewed,missing'},{}),/missing/);
  await assert.rejects(verifyFunctionMutation(backend,snapshot,'/set_function_no_return',{function_address:'1000',no_return:true},{}),/no-return/);
  await verifyFunctionMutation(backend,snapshot,'/set_variable_storage',{function:'first',variable_name:'count',storage:'ECX'},{});
  await assert.rejects(verifyFunctionMutation(backend,snapshot,'/set_variable_storage',{function:'first',variable_name:'count',storage:'EDX:4'},{}),/storage/);
});
