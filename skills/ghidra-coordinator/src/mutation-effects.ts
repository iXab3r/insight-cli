import type {ResearchBackend} from './research.js';
import {address} from './research.js';
import type {Artifact} from './artifacts.js';
import {object,fail} from './model.js';
import {verifyFunctionMutation} from './function-effects.js';
import {verifyComments} from './comment-effects.js';

const equal=(actual:unknown,expected:unknown,label:string)=>{if(actual!==expected)fail('partial',`Saved ${label} does not match the requested effect.`);};
const normalized=(value:unknown)=>address(String(value));
const category=(value:unknown)=>'/'+String(value).replace(/^\/+|\/+$/g,'');
/** Effect assertions run against an immutable saved program, not the response's success flag. */
export async function verifyMutation(backend:ResearchBackend,snapshot:Artifact,path:string,p:Record<string,unknown>,response:Record<string,unknown>) {
  if(['/batch_set_comments','/clear_function_comments'].includes(path))return verifyComments(backend,snapshot,path,p);
  if(path==='/batch_apply_documentation') {
    if(!Array.isArray(response.errors)||response.errors.length)fail('partial','Documentation batch has incomplete steps.');
    const comments=await verifyComments(backend,snapshot,path,p);
    if(!backend.inspect)fail('configuration','Documentation requires saved-state inspection.');
    const functionState=await backend.inspect(snapshot,{kind:'function',address:p.address,...(p.prototype?{prototype:p.prototype}:{})});
    equal(functionState.exists,true,'documented function presence');if(p.name)equal(functionState.name,p.name,'documented function name');
    const variables=functionState.variables;if(!Array.isArray(variables))fail('partial','Saved documented variables are absent.');
    const renames=object(p.variable_renames??{}),types=object(p.variable_types??{});
    for(const [oldName,newName]of Object.entries(renames))if(!variables.some(v=>object(v).name===newName))fail('partial','Saved variable rename is absent.');
    for(const [name,typeName]of Object.entries(types)) {
      const saved=variables.find(v=>object(v).name===(renames[name]??name));if(!saved)fail('partial','Saved documented variable is absent.');
      const wanted=await backend.inspect(snapshot,{kind:'resolve_type',name:typeName});equal(wanted.exists,true,'documented variable type');
      equal(object(saved).type,object(wanted.type).name,'documented variable type');
    }
    if(p.prototype) {
      const expected=object(functionState.expectedPrototype);equal(functionState.returnType,expected.returnType,'documented return type');
      const actual=functionState.parameters;if(!Array.isArray(actual)||!Array.isArray(expected.parameters))fail('partial','Saved signature parameters are absent.');
      equal(actual.length,expected.parameters.length,'documented parameter count');
      for(let i=0;i<actual.length;i++)equal(object(actual[i]).type,object(expected.parameters[i]).type,'documented parameter type');
    }
    if(p.calling_convention)equal(functionState.callingConvention,p.calling_convention,'documented calling convention');
    return {function:functionState,...comments};
  }
  if(path==='/run_script_inline'||path==='/run_ghidra_script') {
    // Output describes execution, while the snapshot captures the resulting complete program state.
    // Scripts can have external effects, so an unknown response cannot be reconciled from DB state alone.
    if(response.success!==true||typeof response.console_output!=='string'&&response.output_captured!==false)
      fail('partial','Script execution lacks a complete successful outcome.');
    if(!backend.inspect)fail('configuration','Script execution requires saved-state inspection.');
    const metadata=await backend.inspect(snapshot,{kind:'metadata'});
    if(typeof metadata.sha256!=='string'||!metadata.sha256)fail('partial','Saved script state lacks its input identity.');
    return {success:true,...(typeof response.console_output==='string'?{output:response.console_output}:{}),
      outputCaptured:response.output_captured!==false,...(path==='/run_ghidra_script'?{script:p.script_name}:{})};
  }
  if(['/create_function','/delete_function','/clear_instruction_flow_override','/disassemble_bytes','/add_function_tag','/remove_function_tag',
    '/delete_function_tag','/set_function_tag_comment','/set_function_no_return','/set_variable_type','/set_variable_storage',
    '/rename_variables','/batch_rename_function_components','/set_variables'].includes(path))
    return verifyFunctionMutation(backend,snapshot,path,p,response);
  if(!backend.inspect)fail('configuration','Structural operations require saved-state inspection.');
  const inspect=(kind:string,parameters:Record<string,unknown>={})=>backend.inspect!(snapshot,{kind,...parameters});
  if(path==='/run_analysis'||path==='/reanalyze') {
    const value=await inspect('metadata');equal(value.analyzed,true,'completed analysis flag');
    if(response.success!==true)fail('partial','Analysis completion was not established.');
    if(response.total_functions!==undefined)equal(value.functionCount,response.total_functions,'analyzed function count');return value;
  }
  if(path==='/configure_analyzer') {
    const value=await inspect('option',{name:p.name,group:'Analyzers'});equal(value.exists,true,'analyzer option presence');
    if(p.enabled!==undefined)equal(value.value,String(p.enabled),'analyzer enabled flag');return value;
  }
  const type=async(name:unknown)=>{const value=await inspect('type',{name});equal(value.exists,true,'type presence');return object(value.type);};
  const structure=async(name:unknown)=>{const value=await type(name);if(!Array.isArray(value.fields))fail('partial','Saved composite layout is absent.');return value;};
  if(['/clone_data_type','/create_derived_type','/rename_data_type'].includes(path)) {
    const name=p.new_name??p.name??response.name;
    const value=await type(name);equal(value.name,name,'type name');
    if(path==='/clone_data_type'&&p.source_type!==p.new_name) {
      const original=await type(p.source_type);equal(original.size,value.size,'copied type size');
      if(original.fields!==undefined)equal(JSON.stringify(original.fields),JSON.stringify(value.fields),'copied layout');
    }
    return value;
  }
  if(path==='/create_function_signature') {
    const value=await type(p.name);equal(value.name,p.name,'signature type name');
    const parameters=typeof p.parameters==='string'?JSON.parse(p.parameters):p.parameters;
    if(!Array.isArray(parameters)||!Array.isArray(value.arguments))fail('partial','Saved function signature arguments are absent.');
    equal(value.arguments.length,parameters.length,'signature argument count');
    for(let i=0;i<parameters.length;i++){const resolved=await inspect('resolve_type',{name:object(parameters[i]).type});
      equal(resolved.exists,true,'signature argument type');equal(value.arguments[i],object(resolved.type).name,'signature argument type');}
    const result=await inspect('resolve_type',{name:p.return_type});equal(result.exists,true,'signature return type');
    equal(value.returnType,object(result.type).name,'signature return type');return value;
  }
  if(path==='/create_data_type_category') {const value=await inspect('category',{name:category(p.category_path)});equal(value.exists,true,'category presence');return value;}
  if(path==='/delete_data_type') {const value=await inspect('type',{name:p.type_name});equal(value.exists,false,'deleted type absence');return value;}
  if(path==='/move_data_type_to_category') {const value=await type(p.type_name);equal(value.category,category(p.category_path),'type category');return value;}
  if(path==='/create_enum') {
    const value=await type(p.name),members=object(value.values),expected=object(p.values);
    equal(value.size,p.size??4,'enum size');equal(Object.keys(members).length,Object.keys(expected).length,'enum member count');
    for(const [name,item]of Object.entries(expected)) {
      let wanted;try{wanted=BigInt(String(item)).toString();}catch{fail('invalid','Enum values must be exact integers.');}
      equal(members[name],wanted,'enum member '+name);
    }
    return value;
  }
  if(path==='/create_union'||path==='/recreate_struct') {
    const value=await structure(p.name),fields=value.fields as Record<string,unknown>[];
    if(!Array.isArray(p.fields))fail('invalid','Composite fields must be an array.');equal(fields.length,p.fields.length,'composite field count');
    for(let i=0;i<fields.length;i++){const wanted=object(p.fields[i]);equal(fields[i]!.name,wanted.name,'composite field name');
      if(wanted.offset!==undefined&&path==='/recreate_struct')equal(fields[i]!.offset,wanted.offset,'composite field offset');}
    if(path==='/recreate_struct'&&Number(p.size??-1)>0)equal(value.size,p.size,'structure size');return value;
  }
  if(['/add_struct_field','/modify_struct_field','/remove_struct_field'].includes(path)) {
    const value=await structure(p.struct_name),fields=value.fields as Record<string,unknown>[];
    const selector=String(p.field_name??''),byOffset=selector.startsWith('offset:')?Number(selector.slice(7)):undefined;
    const target=fields.find(f=>byOffset===undefined?f.name===(p.new_name||selector):f.offset===byOffset);
    if(path==='/remove_struct_field') {if(fields.some(f=>f.name===selector))fail('partial','Removed field remains in the saved structure.');}
    else {if(!target)fail('partial','Edited field is absent from the saved structure.');
      if(path==='/add_struct_field'&&Number(p.offset??-1)>=0)equal(target.offset,p.offset,'field offset');
      if(p.new_name)equal(target.name,p.new_name,'field name');
      const expected=p.new_type??p.field_type;if(expected){const resolved=await inspect('resolve_type',{name:expected});equal(resolved.exists,true,'resolved field type');
        equal(String(target.type).replace(/\s+/g,''),String(object(resolved.type).name).replace(/\s+/g,''),'field type');}}
    return value;
  }
  if(path==='/resize_struct') {const value=await structure(p.name);equal(value.size,p.new_size,'structure size');return value;}
  if(path==='/resolve_duplicate_type') {const value=await type(p.type_name);if(Number(value.size)<=1)fail('partial','Canonical type is still a placeholder.');return value;}
  if(path==='/apply_data_type') {
    // The acknowledgment carries the resolved type; the saved type must exist with that size.
    const resolved=await inspect('resolve_type',{name:p.type_name});equal(resolved.exists,true,'resolved applied type');
    const value=object(resolved.type);if(Number(value.size)<=0)fail('partial','Applied type has no defined size.');
    const observed=await inspect('data',{address:p.address});equal(observed.exists,true,'defined data presence');
    equal(observed.type,value.name,'applied data type');return observed;
  }
  if(['/create_property_map','/delete_property_map','/set_property','/remove_property'].includes(path)) {
    const value=await inspect('property',{name:p.name??p.map,...(p.address?{address:p.address}:{})});
    equal(value.exists,path!=='/delete_property_map','property map presence');
    if(path==='/set_property') {equal(value.hasValue,true,'property presence');if(value.value!==null)equal(value.value,String(p.value??''),'property value');}
    if(path==='/remove_property')equal(value.hasValue,false,'removed property absence');return value;
  }
  if(path==='/set_program_option'||path==='/remove_program_option') {
    const value=await inspect('option',{name:p.name,group:p.group});equal(value.exists,path==='/set_program_option','program option presence');
    if(path==='/set_program_option')equal(value.value,String(p.value),'program option value');return value;
  }
  if(path==='/set_image_base') {const value=await inspect('metadata');equal(normalized(value.imageBase),normalized(p.address),'image base');return value;}
  if(path==='/set_memory_block') {
    const value=await inspect('memory',{name:p.block??'',address:p.address??''});equal(value.exists,true,'memory block presence');
    for(const flag of ['read','write','execute','volatile'])if(p[flag]!==undefined)equal(value[flag],p[flag],'memory '+flag);return value;
  }
  if(path==='/set_bookmark'||path==='/delete_bookmark') {
    const value=await inspect('bookmarks',{address:p.address}),marks=value.bookmarks;
    if(!Array.isArray(marks))fail('partial','Saved bookmark inventory is absent.');
    const selected=marks.filter(mark=>object(mark).category===String(p.category??''));
    if(path==='/set_bookmark'){if(!selected.some(mark=>object(mark).comment===String(p.comment??'')))fail('partial','Saved bookmark does not contain the requested comment.');}
    else if(p.category?selected.length:marks.length)fail('partial','Deleted bookmark remains in saved state.');return value;
  }
  if(path==='/create_label'||path==='/delete_label') {
    const edits=Array.isArray(p.labels)&&p.labels.length?p.labels:[{address:p.address,name:p.name}];
    const verified=[];
    for(const item of edits){const label=object(item),value=await inspect('symbols',{address:label.address});
      if(!Array.isArray(value.symbols))fail('partial','Saved symbol inventory is absent.');
      equal(value.symbols.some(s=>object(s).name===label.name),path==='/create_label','label presence');verified.push(value);}
    return {labels:verified};
  }
  if(path==='/rename_symbol') {
    const value=await inspect('symbols',{name:p.new_name});if(!Array.isArray(value.symbols)||!value.symbols.length)fail('partial','Renamed symbol is absent from saved state.');return value;
  }
  if(path==='/add_memory_reference'||path==='/remove_reference') {
    const value=await inspect('references',{address:p.from_address});if(!Array.isArray(value.references))fail('partial','Saved reference inventory is absent.');
    const found=value.references.filter(ref=>normalized(object(ref).to)===normalized(p.to_address)&&object(ref).operand===(p.operand_index??-1));
    equal(found.length>0,path==='/add_memory_reference','reference presence');return value;
  }
  fail('schema','Mutation lacks its saved effect contract.');
}
