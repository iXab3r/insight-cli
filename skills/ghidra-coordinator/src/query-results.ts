import {fail} from './model.js';
import {rejectPlaceholders} from './query-policy.js';

type Shape=Record<string,'string'|'number'|'boolean'|'array'|'object'>;
const shapes:Record<string,Shape>={
 '/analyze_data_region':{start_address:'string',end_address:'string',byte_span:'number',xref_count:'number',classification_hint:'string'},
 '/detect_array_bounds':{address:'string',estimated_size:'number',stride:'number',element_count:'number',confidence:'string'},
 '/analyze_control_flow':{function_name:'string',entry_point:'string',metrics:'object',basic_block_details:'array'},
 '/analyze_dataflow':{function:'object',anchor:'object',direction:'string',chain:'array',truncated:'boolean'},
 '/analyze_for_documentation':{name:'string',address:'string',parameters:'array',locals:'array'},
 '/analyze_function_complete':{name:'string',address:'string'},
 '/analyze_function_completeness':{function_name:'string',completeness_score:'number'},
 '/find_code_gaps':{gaps:'array',total:'number',offset:'number',limit:'number'},
 '/find_next_undefined_function':{found:'boolean'},
 '/find_similar_functions':{target_function:'string',similar_functions:'array',matches_found:'number'},
 '/get_field_access_context':{struct_address:'string',field_offset:'number',examples:'array'},
 '/get_function_pcode':{name:'string',address:'string',basic_blocks:'array'},
 '/inspect_memory_content':{address:'string',bytes_read:'number',hex_dump:'string'},
 '/list_analyzers':{analyzers:'array',count:'number'},
 '/search_instructions':{matches:'array'},
 '/analyze_global_completeness':{address:'string',score:'number',issues:'array'},
 '/analyze_struct_field_usage':{struct_name:'string',struct_size:'number',field_usage:'object'},
 '/audit_global':{address:'string',issues:'array',fully_documented:'boolean'},
 '/audit_globals_in_function':{function:'object',globals:'array',summary:'object'},
 '/get_enum_values':{name:'string',size:'number',values:'array'},
 '/get_struct_layout':{name:'string',size:'number',alignment:'number',fields:'array'},
 '/get_type_size':{type_name:'string',size:'number',alignment:'number'},
 '/get_valid_data_types':{builtin_types:'array',windows_types:'array'},
 '/suggest_field_names':{struct_address:'string',suggestions:'array'},
 '/validate_data_type':{type_name:'string',valid:'boolean',warnings:'array'},
 '/validate_function_prototype':{valid:'boolean'},
 '/batch_string_anchor_report':{anchors:'array',total_anchors:'number'},
 '/find_undocumented_by_string':{undocumented_functions:'array',undocumented_count:'number'},
 '/get_function_documentation':{hash:'string',function_name:'string',parameters:'array',comments:'array',labels:'array'},
 '/emulate_function':{success:'boolean',steps_executed:'number',stop_reason:'string',registers:'object'},
 '/emulate_hash_batch':{tested:'number',matches:'array',resolved:'boolean'},
 '/disassemble_function':{instructions:'array',count:'number'},
 '/force_decompile':{address:'string',name:'string',decompiled:'string'},
 '/get_functions':{functions:'object',count:'number',requested:'number'},
 '/list_class_members':{class_name:'string',members:'array',total_members:'number'},
 '/list_function_tags':{tags:'array',total:'number'},
 '/find_functions':{functions:'array',total:'number',count:'number'},
 '/get_entry_points':{entry_points:'array',count:'number'},
 '/get_function_count':{function_count:'number'},
 '/list_calling_conventions':{calling_conventions:'array',count:'number'},
 '/list_globals':{globals:'array',count:'number',total:'number'},
 '/list_program_items':{kind:'string',items:'array',count:'number',total:'number'},
 '/list_shadowed_globals':{shadowed:'array',count:'number',total:'number'},
 '/list_strings':{strings:'array',count:'number',total:'number'},
 '/search_strings':{matches:'array',total:'number',offset:'number',limit:'number'},
 '/analyze_api_call_chains':{detected_patterns:'array',total_patterns_detected:'number'},
 '/detect_malware_behaviors':{behaviors:'array',total_behaviors_detected:'number'},
 '/extract_iocs_with_context':{iocs:'array',total_iocs:'number'},
 '/find_anti_analysis_techniques':{findings:'array',total_findings:'number'},
 '/analysis_status':{analyzing:'boolean',analyzed:'boolean',function_count:'number'},
 '/get_address_spaces':{address_spaces:'array',count:'number'},
 '/get_language_metadata':{language_id:'string',processor:'string',endian:'string',address_spaces:'array'},
 '/get_metadata':{architecture:'string',compiler:'string',language:'string',base_address:'string',function_count:'number'},
 '/get_property':{address:'string',has_value:'boolean'},
 '/list_bookmarks':{bookmarks:'array',count:'number'},
 '/list_properties':{map:'string',entries:'array',count:'number',total:'number'},
 '/read_memory':{address:'string',length:'number',data:'array',hex:'string'},
 '/can_rename_at_address':{can_rename:'boolean',type:'string'},
 '/get_function_call_graph':{edges:'array',count:'number'},
 '/get_xrefs_from':{references:'array',count:'number',total:'number'},
 '/get_xrefs_to':{references:'array',count:'number',total:'number'},
};
function checkShape(result:unknown,shape:Shape) {
 if(!result||typeof result!=='object'||Array.isArray(result))fail('partial','Query expected a result object.');
 const value=result as Record<string,unknown>;
 for(const [key,type]of Object.entries(shape)) {
  const item=value[key],valid=type==='array'?Array.isArray(item):type==='object'?Boolean(item)&&typeof item==='object'&&!Array.isArray(item):
   type==='number'?typeof item==='number'&&Number.isFinite(item):typeof item===type;
  if(!valid)fail('partial',`Query omitted or malformed ${key}.`);
 }
 return value;
}
/** Validate the pinned operation's result variant, independently of its HTTP acknowledgment. */
export function queryResult(path:string,parameters:Record<string,unknown>,result:unknown) {
 rejectPlaceholders(result);
 let shape=shapes[path];
 if(path==='/find_dead_code')shape={findings:'array',complete:'boolean',unresolved_flow:'boolean',algorithm:'string',scan:'object',truncated:'boolean'};
 if(path==='/detect_crypto_constants'||path==='/search_byte_patterns')shape={matches:'array',complete:'boolean',scanned_bytes:'number',maximum_bytes:'number',algorithm:'string',scan:'object',truncated:'boolean'};
 if(path==='/get_valid_data_types')shape={types:'array',scope:'string',scan:'object',truncated:'boolean'};
 if(path==='/validate_function_prototype')shape={valid:'boolean',diagnostics:'array',parser:'string',persisted_changes:'boolean'};
 const bulkComments=path==='/get_comment'&&Boolean(String(parameters.addresses??'').trim());
 if(path==='/get_comment')shape=bulkComments?{results:'array',requested:'number',returned:'number',with_comments:'number'}:{address:'string',has_comment:'boolean'};
 if(path==='/find_data_types')shape={...(parameters.categories?{categories:'array' as const}:{data_types:'array' as const}),count:'number'};
 if(path==='/get_function_hash')shape=parameters.function?{hash:'string',function_name:'string',instruction_count:'number'}:{functions:'array'};
 // The pinned service returns a bare bundle for function=, a map/counts for functions=.
 // Bulk selection takes precedence even when both selectors are supplied.
 if(path==='/get_functions'&&!String(parameters.functions??'').trim())shape={name:'string',size:'number'};
 if(path==='/get_program_options')shape=parameters.group?{options:'array'}:{groups:'array'};
 // The pinned implementation retains format as a deprecated no-op and always returns JSON.
 if(path==='/list_data_items_by_xrefs')shape={data_items:'array',count:'number',total:'number'};
 if(path==='/get_external_location')shape={address:'string'};
 if(path==='/get_full_call_graph')shape=parameters.format==='json_edges'?{edges:'array',edge_count:'number',caller_count:'number'}:
  parameters.format==='dot'||parameters.format==='mermaid'?{format:'string',diagram:'string',count:'number'}:
  parameters.format==='adjacency'?{format:'string',adjacency:'object',count:'number'}:{edges:'array',count:'number'};
 if(path==='/analyze_call_graph')shape=parameters.analysis_type===undefined||parameters.analysis_type==='summary'?{total_functions:'number',total_call_edges:'number'}:{analysis_type:'string'};
 if(path==='/get_assembly_context') {
  const value=checkShape(result,{}),input=parameters.xref_sources;
  const addresses=Array.isArray(input)?input:typeof input==='string'?input.split(',').map(v=>v.trim()).filter(Boolean):[];
  for(const at of addresses)if(!Object.hasOwn(value,String(at)))fail('partial','Assembly context omitted a requested address.');return result;
 }
 if(path==='/list_scripts')shape={items:'array',count:'number',total:'number',offset:'number',limit:'number',truncated:'boolean'};
 if(!shape)fail('schema','Pinned query has no result contract.');
 const value=checkShape(result,shape);
 const rowShapes:Record<string,{key:string;shape:Shape}>={
  '/list_globals':{key:'globals',shape:{address:'string',name:'string',type:'string',size:'number',xrefs:'number',named:'boolean',typed:'boolean'}},
  '/list_strings':{key:'strings',shape:{address:'string',value:'string',encoding:'string'}},
  '/search_strings':{key:'matches',shape:{address:'string',value:'string',encoding:'string'}},
  '/search_instructions':{key:'matches',shape:{address:'string',mnemonic:'string',instruction:'string',length:'number'}},
  '/get_valid_data_types':{key:'types',shape:{name:'string',path:'string',size:'number',alignment:'number',source:'string'}},
  '/find_dead_code':{key:'findings',shape:{address:'string',end:'string',size:'number',kind:'string'}},
  '/detect_crypto_constants':{key:'matches',shape:{address:'string',signature:'string',length:'number',kind:'string'}},
  '/search_byte_patterns':{key:'matches',shape:{address:'string',signature:'string',length:'number',kind:'string'}},
  '/get_function_call_graph':{key:'edges',shape:{caller:'string',callee:'string'}},
 };
 const checkedRows=rowShapes[path];
 if(checkedRows)for(const row of value[checkedRows.key] as unknown[])checkShape(row,checkedRows.shape);
 if(value.scan!==undefined){const scan=checkShape(value.scan,{visited:'number',maximum:'number',complete:'boolean',reason:'string'});
  if(!Number.isSafeInteger(scan.visited)||!Number.isSafeInteger(scan.maximum)||Number(scan.visited)<0||Number(scan.visited)>Number(scan.maximum))fail('partial','Query scan counters are inconsistent.');
  if(scan.complete===false&&value.truncated!==true)fail('partial','Incomplete query scan was reported as untruncated.');
 }
 for(const entry of [['globals','count'],['strings','count'],['matches','count'],['types','count']] as const)
  if(Array.isArray(value[entry[0]])&&value[entry[1]]!==undefined&&value[entry[1]]!==(value[entry[0]] as unknown[]).length)fail('partial','Query row count is inconsistent.');
 if(path==='/find_dead_code'&&(value.complete===false||value.unresolved_flow===true)&&(value.findings as unknown[]).length)fail('partial','Incomplete CFG analysis cannot classify unreachable blocks.');
 if(path==='/detect_crypto_constants'||path==='/search_byte_patterns'){
  if(Number(value.scanned_bytes)>Number(value.maximum_bytes)||Number(value.scanned_bytes)<0)fail('partial','Byte scan exceeded its declared budget.');
  if(value.complete===false&&typeof value.next_address!=='string')fail('partial','Partial byte scan omitted its continuation.');
  if(path==='/detect_crypto_constants'){const database=checkShape(value.database,{version:'string',signatures:'array'});
   for(const row of database.signatures as unknown[])checkShape(row,{name:'string',length:'number'});}
 }
 if(path==='/get_entry_points'){
  for(const raw of value.entry_points as unknown[]){const row=checkShape(raw,{address:'string',name:'string',kind:'string',confirmed:'boolean',provenance:'string'});
   if(row.confirmed!==true||row.kind!=='external_entry'||row.provenance!=='ghidra.symbol.external-entry-point')fail('partial','Entry-point metadata was replaced by an unconfirmed candidate.');}
  if(!Array.isArray(value.candidates))fail('partial','Entry-point result omitted its candidates.');
  for(const raw of value.candidates as unknown[]){const row=checkShape(raw,{address:'string',name:'string',kind:'string',confirmed:'boolean',provenance:'string'});if(row.confirmed!==false)fail('partial','Entry candidate was labeled confirmed.');}
 }
 if(path==='/validate_function_prototype'||path==='/validate_data_type'){
  if(!Array.isArray(value.diagnostics))fail('partial','Validation omitted parser/resolution diagnostics.');
  for(const raw of value.diagnostics)checkShape(raw,{severity:'string',code:'string',message:'string'});
  if(value.valid===true){if(path==='/validate_data_type')checkShape(value.resolved,{name:'string',path:'string',size:'number',alignment:'number'});
   else checkShape(value.signature,{name:'string',return_type:'object',parameters:'array',calling_convention:'string'});}
 }
 if(path==='/emulate_function'&&value.completed!==undefined){
  checkShape(value,{completed:'boolean',hit_return:'boolean',abi:'string',pointer_bytes:'number'});
  if(value.completed!==value.hit_return||value.completed===true&&value.stop_reason!=='return')fail('partial','Emulation termination was reported inconsistently.');
 }
 if(path==='/get_comment'){
  const rows=bulkComments?value.results as unknown[]:[value];
  if(bulkComments&&(!['requested','returned','with_comments'].every(key=>Number.isSafeInteger(value[key])&&Number(value[key])>=0)||value.returned!==rows.length||Number(value.returned)>Number(value.requested)||Number(value.with_comments)>Number(value.requested)))fail('partial','Bulk comment counts are inconsistent.');
  for(const row of rows){const comment=checkShape(row,{address:'string',has_comment:'boolean'});
   for(const kind of ['plate','pre','eol','post','repeatable'])if(comment[kind]!==null&&typeof comment[kind]!=='string')fail('partial','Query omitted or malformed comment kind.');}
 }
 if(path==='/get_full_call_graph'&&parameters.format==='json_edges'){
  const rows=value.edges as unknown[];if(value.edge_count!==rows.length||!Number.isSafeInteger(value.caller_count)||Number(value.caller_count)<0)fail('partial','Call graph counts are inconsistent.');
  for(const row of rows)checkShape(row,{caller_addr:'string',callee_addr:'string',caller_name:'string',callee_name:'string'});
 }
 if(path==='/get_struct_layout')for(const field of value.fields as unknown[])checkShape(field,{offset:'number',size:'number',type:'string',name:'string'});
 if(path==='/get_enum_values')for(const member of value.values as unknown[]) {
  const observed=checkShape(member,{name:'string'}),number=observed.value;
  if(!(typeof number==='number'&&Number.isSafeInteger(number)||typeof number==='string'&&/^-?\d+$/.test(number)))
    fail('partial','Enum result omitted its exact integer value.');
 }
 return result;
}
