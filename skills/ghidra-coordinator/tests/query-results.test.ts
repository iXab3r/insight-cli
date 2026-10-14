import test from 'node:test';
import assert from 'node:assert/strict';
import {queryResult} from '../src/query-results.js';
test('operation-specific read contracts reject false or incomplete data while accepting result variants',()=>{
 assert.throws(()=>queryResult('/get_struct_layout',{}, {name:'Record',size:8,alignment:1,fields:[{offset:0,size:4,name:'count'}]}),/type/);
 assert.throws(()=>queryResult('/get_enum_values',{}, {name:'Choice',size:4,values:[{name:'One'}]}),/value/);
 assert.throws(()=>queryResult('/emulate_function',{}, {success:true}),/steps_executed/);
 assert.throws(()=>queryResult('/get_assembly_context',{xref_sources:['1000','1100']},{'1000':{}}),/requested address/);
 assert.deepEqual(queryResult('/get_function_hash',{function:'first'}, {hash:'known',function_name:'first',instruction_count:8}),
  {hash:'known',function_name:'first',instruction_count:8});
 assert.deepEqual(queryResult('/get_function_hash',{}, {functions:[]}),{functions:[]});
 assert.equal(queryResult('/list_data_items_by_xrefs',{format:'text'},'address label type'),'address label type');
 assert.deepEqual(queryResult('/get_program_options',{group:'Program Information'},{options:[]}),{options:[]});
});
