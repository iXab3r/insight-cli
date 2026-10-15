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
 assert.deepEqual(queryResult('/list_data_items_by_xrefs',{format:'text'},{data_items:[],count:0,total:0}),{data_items:[],count:0,total:0});
 assert.throws(()=>queryResult('/list_data_items_by_xrefs',{format:'text'},'address label type'),/object/);
 assert.deepEqual(queryResult('/get_program_options',{group:'Program Information'},{options:[]}),{options:[]});
});

test('pinned bulk comments and address-based call graphs accept their actual JSON variants and reject incomplete rows',()=>{
 const row={address:'1000',has_comment:true,comment:'owned',plate:null,pre:null,eol:'owned',post:null,repeatable:''};
 const bulk={requested:2,returned:1,with_comments:1,results:[row]};
 assert.deepEqual(queryResult('/get_comment',{addresses:'1000,1100',only_with_comments:true},bulk),bulk);
 assert.throws(()=>queryResult('/get_comment',{addresses:'1000,1100'},{...bulk,returned:2}),/count/);
 assert.throws(()=>queryResult('/get_comment',{addresses:'1000'},{...bulk,results:[{...row,eol:123}]}),/comment/);
 const graph={edges:[{caller_addr:'1000',callee_addr:'1100',caller_name:'main',callee_name:'first'}],edge_count:1,caller_count:1};
 assert.deepEqual(queryResult('/get_full_call_graph',{format:'json_edges'},graph),graph);
 assert.throws(()=>queryResult('/get_full_call_graph',{format:'json_edges'},{...graph,edges:[{caller_addr:'1000'}]}),/callee_addr/);
 assert.throws(()=>queryResult('/get_full_call_graph',{format:'dot'},{format:'dot'}),/diagram/);
});
