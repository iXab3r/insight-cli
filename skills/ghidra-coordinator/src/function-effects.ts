import type {ResearchBackend} from './research.js';
import {address} from './research.js';
import type {Artifact} from './artifacts.js';
import {object,fail} from './model.js';
import {parseDomainJson} from './json.js';

const equal=(actual:unknown,expected:unknown,label:string)=>{if(actual!==expected)fail('partial',`Saved ${label} does not match the requested effect.`);};
const list=(value:unknown,label:string):Record<string,unknown>[]=>{if(!Array.isArray(value))fail('partial',`Saved ${label} is absent.`);return value.map(object);};
const json=(value:unknown)=>typeof value==='string'?parseDomainJson(value):value;
/** Function edits are verified in the saved private database, including each batch member. */
export async function verifyFunctionMutation(backend:ResearchBackend,snapshot:Artifact,path:string,p:Record<string,unknown>,response:Record<string,unknown>) {
  if(!backend.inspect)fail('configuration','Function edits require saved-state inspection.');
  const inspect=(kind:string,parameters:Record<string,unknown>={})=>backend.inspect!(snapshot,{kind,...parameters});
  const functionAt=async(ref:unknown,exists=true)=>{
    if(typeof ref!=='string'||!ref)fail('invalid','A function reference is required.');
    let selector;try{selector={address:address(ref)};}catch{selector={name:ref};}
    const value=await inspect('function',selector);equal(value.exists,exists,'function presence');return value;
  };
  const checkType=async(actual:unknown,wanted:unknown)=>{const resolved=await inspect('resolve_type',{name:wanted});
    equal(resolved.exists,true,'variable type presence');equal(actual,object(resolved.type).name,'variable type');};
  if(path==='/create_function'||path==='/delete_function') {
    const value=await functionAt(p.address??p.function,path==='/create_function');
    if(path==='/create_function'&&p.name)equal(value.name,p.name,'function name');return value;
  }
  if(path==='/clear_instruction_flow_override'||path==='/disassemble_bytes') {
    const value=await inspect('instructions',{address:p.address??p.start_address});equal(value.exists,true,'instruction presence');
    if(path==='/clear_instruction_flow_override')equal(value.flowOverride,'NONE','instruction flow override');return value;
  }
  if(['/add_function_tag','/remove_function_tag'].includes(path)) {
    const assignments=Array.isArray(p.assignments)&&p.assignments.length?p.assignments:[{function:p.function,tags:p.tags}];
    const results=[];
    for(const assignment of assignments) {
      const requested=object(assignment),value=await functionAt(requested.function),tags=list(value.tags,'function tags');
      const names=String(requested.tags??'').split(',').map(name=>name.trim()).filter(Boolean);
      if(!names.length)fail('invalid','At least one tag name is required.');
      for(const name of names)equal(tags.some(tag=>tag.name===name),path==='/add_function_tag','function tag '+name);
      results.push(value);
    }
    return {functions:results};
  }
  if(path==='/delete_function_tag'||path==='/set_function_tag_comment') {
    const value=await inspect('function_tags'),tags=list(value.tags,'program function tags'),tag=tags.find(tag=>tag.name===p.name);
    equal(!!tag,path==='/set_function_tag_comment','program tag presence');
    if(tag)equal(tag.comment,p.comment,'program tag comment');return value;
  }
  const value=await functionAt(p.function??p.function_address),variables=list(value.variables,'function variables');
  const variable=(name:unknown)=>{const found=variables.find(item=>item.name===name);if(!found)fail('partial','Requested variable is absent from saved state.');return found;};
  if(path==='/set_function_no_return'){equal(value.noReturn,p.no_return,'no-return flag');return value;}
  if(path==='/set_variable_type'){await checkType(variable(p.variable_name).type,p.new_type);return value;}
  if(path==='/set_variable_storage') {
    const stored=variable(p.variable_name).storage;
    const canonical=String(stored).replace(/\s+/g,'').toLowerCase(),wanted=String(p.storage).replace(/\s+/g,'').toLowerCase();
    // A size omitted by the caller is inferred from the saved variable type.
    if(canonical!==wanted&&!(!wanted.includes(':')&&canonical.startsWith(wanted+':')))
      fail('partial','Saved variable storage differs from the requested location.');
    return value;
  }
  if(path==='/rename_variables'||path==='/batch_rename_function_components') {
    const maps=path==='/rename_variables'?[p.variable_renames]:[p.parameter_renames,p.local_renames];
    for(const mapping of maps)for(const [oldName,newName]of Object.entries(object(mapping??{}))) {
      variable(newName);if(oldName!==newName&&variables.some(item=>item.name===oldName))fail('partial','Original variable name remains after renaming.');
    }
    if(p.function_name)equal(value.name,p.function_name,'function name');
    if(p.return_type)await checkType(value.returnType,p.return_type);return value;
  }
  if(path==='/set_variables') {
    for(const [oldName,raw]of Object.entries(object(json(p.variables)))) {
      const spec=typeof raw==='string'?{name:raw}:Array.isArray(raw)?{name:raw[0],type:raw[1]}:object(raw);
      const saved=variable(spec.name||oldName);if(spec.type)await checkType(saved.type,spec.type);
      if(spec.name&&spec.name!==oldName&&variables.some(item=>item.name===oldName))fail('partial','Original variable name remains after editing.');
    }
    return value;
  }
  fail('schema','Function mutation lacks its saved effect contract.');
}
