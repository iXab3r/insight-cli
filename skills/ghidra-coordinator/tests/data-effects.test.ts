import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyDataMutation} from '../src/data-effects.js';
import {verifyDocumentation} from '../src/documentation-effects.js';
import {mutationInputs} from '../src/mutation-inputs.js';
import type {ResearchBackend} from '../src/research.js';
import type {Artifact} from '../src/artifacts.js';
const snapshot={kind:'snapshot',sha256:'a'.repeat(64),size:1} as Artifact;
test('successful import/array acknowledgments cannot hide incomplete saved types',async()=>{
  const backend={inspect:async(_snapshot:Artifact,p:Record<string,unknown>)=>p.kind==='import_check'?{types:[{name:'Missing',matches:false}]}:
    p.kind==='resolve_type'?{exists:true,type:{name:'uint'}}:{exists:true,details:{elementType:'uint',elementCount:1}}} as unknown as ResearchBackend;
  await assert.rejects(verifyDataMutation(backend,snapshot,'/import_data_types',{source:'struct Missing {int a;};'},{parse_succeeded:true}),/Missing/);
  await assert.rejects(verifyDataMutation(backend,snapshot,'/apply_data_classification',{address:'1000',classification:'ARRAY',type_definition:{element_type:'uint',count:4}},{success:true}),/length/);
});
test('nested edit inputs reject skipped classifications, invalid arrays and ambiguous documentation before dispatch',()=>{
  assert.throws(()=>mutationInputs('/apply_data_classification',{classification:'UNKNOWN',type_definition:{}}),/Classification/);
  assert.throws(()=>mutationInputs('/apply_data_classification',{classification:'ARRAY',type_definition:{element_type:'uint',count:-1}}),/count/);
  assert.throws(()=>mutationInputs('/apply_function_documentation',{json_body:{target_address:'1000',parameters:[{ordinal:0,name:'a'},{ordinal:0,name:'b'}]}}),/unique/);
  mutationInputs('/apply_function_documentation',{json_body:{target_address:'1000',plate_comment:'Quoted "fixture"\nSecond line',parameters:[{ordinal:0,name:'count',type:'uint'}]}});
});
test('documentation verifies quoted/newline text and every parameter rather than accepting skipped items',async()=>{
  const backend={inspect:async(_snapshot:Artifact,p:Record<string,unknown>)=>p.kind==='function'?{exists:true,name:'first',parameters:[{name:'count',type:'int'}]}:
    {plate:'Quoted "fixture"\nSecond line'}} as unknown as ResearchBackend;
  await verifyDocumentation(backend,snapshot,{json_body:{target_address:'1000',plate_comment:'Quoted "fixture"\nSecond line'}});
  await assert.rejects(verifyDocumentation(backend,snapshot,{json_body:{target_address:'1000',parameters:[{ordinal:0,name:'missing'}]}}),/name/);
});
