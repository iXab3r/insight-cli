import type {ResearchBackend} from './research.js';
import {address} from './research.js';
import type {Artifact} from './artifacts.js';
import {object,fail} from './model.js';
const equal=(actual:unknown,expected:unknown,label:string)=>{if(actual!==expected)fail('partial',`Saved ${label} differs from the requested effect.`);};
export async function verifyDataMutation(backend:ResearchBackend,snapshot:Artifact,path:string,p:Record<string,unknown>,response:Record<string,unknown>) {
  if(!backend.inspect)fail('configuration','Data edits require saved-state inspection.');
  const inspect=(kind:string,parameters:Record<string,unknown>={})=>backend.inspect!(snapshot,{kind,...parameters});
  const resolve=async(name:unknown)=>{const value=await inspect('resolve_type',{name});equal(value.exists,true,'type presence');return object(value.type);};
  if(path==='/import_data_types') {
    if(response.parse_succeeded!==true)fail('partial','Type import did not complete parsing.');
    const value=await inspect('import_check',{source:p.source});if(!Array.isArray(value.types)||!value.types.length)fail('partial','Imported type inventory is absent.');
    for(const type of value.types)equal(object(type).matches,true,'imported type '+object(type).name);return value;
  }
  if(path==='/set_function_this_type') {
    const value=await inspect('function',{address:p.function_address});equal(value.exists,true,'member function presence');
    let name=String(p.this_type).trim();if(!name.endsWith('*'))name+=' *';const pointer=await resolve(name);
    const parameters=value.parameters;if(!Array.isArray(parameters))fail('partial','Saved member parameters are absent.');
    const self=parameters.find(param=>object(param).auto===true&&object(param).name==='this');if(!self)fail('partial','Saved implicit this parameter is absent.');
    equal(object(self).type,pointer.name,'implicit this type');equal(String(value.namespace).split('::').at(-1),pointer.pointerBase,'owning class');return value;
  }
  if(path==='/clear_flow_and_repair') {
    if(response.success!==true||response.repair!==true)fail('partial','Flow repair lacks a completed outcome.');
    const range=object(response.seed_range);equal(address(String(range.start_address)),address(p.start_address),'repair seed start');
    if(p.end_address)equal(address(String(range.end_address_exclusive)),address(p.end_address),'repair seed end');
    const value=await inspect('instruction_range',{address:p.start_address,end_address:range.end_address_exclusive});
    equal(value.count,object(response.observations).instructions_in_seed_after,'repaired instruction count');return value;
  }
  const data=await inspect('data',{address:p.address});
  if(path==='/set_global'&&p.type_name) {
    equal(data.exists,true,'defined global presence');const type=await resolve(p.type_name);
    if(Number(p.array_length??0)>0){const details=object(data.details);equal(details.elementType,type.name,'global array element');equal(details.elementCount,p.array_length,'global array length');}
    else equal(data.type,type.name,'global type');
  }
  if(path==='/apply_data_classification') {
    equal(data.exists,true,'classified data presence');const definition=object(p.type_definition);
    if(p.classification==='PRIMITIVE'){const type=await resolve(definition.type);equal(data.type,type.name,'classified primitive type');}
    if(p.classification==='STRUCTURE') {
      equal(data.type,definition.name,'classified structure type');const type=await resolve(definition.name);
      const fields=type.fields;if(!Array.isArray(fields)||!Array.isArray(definition.fields))fail('partial','Classified structure layout is absent.');
      equal(fields.length,definition.fields.length,'classified field count');
      for(let i=0;i<fields.length;i++){const requested=object(definition.fields[i]),expected=await resolve(requested.type);
        equal(object(fields[i]).name,requested.name,'classified field name');equal(object(fields[i]).type,expected.name,'classified field type');}
    }
    if(p.classification==='ARRAY') {const type=await resolve(definition.element_type??definition.element_struct),details=object(data.details);
      equal(details.elementType,type.name,'classified array element');equal(details.elementCount,Number(definition.count),'classified array length');}
    if(p.classification==='STRING')equal(data.isString,true,'classified string value');
    if(p.comment){const comment=await inspect('comments',{address:p.address});
      equal(comment.pre,String(p.comment).replaceAll('\\n','\n').replaceAll('\\t','\t').replaceAll('\\r','\r'),'classified comment');}
  }
  let symbols:Record<string,unknown>|undefined,comments:Record<string,unknown>|undefined;
  if(p.name){symbols=await inspect('symbols',{address:p.address});if(!Array.isArray(symbols.symbols)||!symbols.symbols.some(symbol=>object(symbol).name===p.name))fail('partial','Saved global label is absent.');}
  if(path==='/set_global'&&p.plate_comment){comments=await inspect('comments',{address:p.address});equal(comments.plate,p.plate_comment,'global plate comment');}
  return {data,...(symbols?{symbols}:{}),...(comments?{comments}:{})};
}
