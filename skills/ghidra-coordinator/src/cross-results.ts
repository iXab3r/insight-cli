import {object,fail} from './model.js';
import type {Scope} from './workspace.js';
const count=(value:unknown)=>{if(!Number.isSafeInteger(value)||Number(value)<0)fail('partial','Cross-target result has an invalid count.');return Number(value);};
const scores=(value:unknown)=>{if(typeof value!=='number'||!Number.isFinite(value)||value<0||value>1)fail('partial','Cross-target result has an invalid similarity score.');};
/** Domain contracts for the pinned comparison leaves, independent of backend acknowledgment. */
export function crossResult(path:string,parameters:Record<string,unknown>,input:unknown) {
  const value=object(input);if(JSON.stringify(value).length>1048576)fail('limit','Cross-target result exceeds one MiB; narrow its scope.');
  if(path==='/compare_programs_documentation') {
    if(!Array.isArray(value.programs)||value.programs.length!==2||value.count!==2)fail('partial','Comparison did not return both selected contexts.');
    for(const item of value.programs){const program=object(item);const total=count(program.total_functions);
      if(count(program.documented)+count(program.undocumented)!==total)fail('partial','Program documentation counts are inconsistent.');}
  }else if(path==='/diff_functions') {
    const a=object(value.function_a),b=object(value.function_b);if(typeof a.name!=='string'||typeof b.name!=='string')fail('partial','Diff omitted its function identities.');
    scores(object(value.summary).similarity_score);
    for(const key of ['body_equal','body_added','body_removed'])count(object(value.summary)[key]);
    for(const key of ['prologue_diff','body_diff','epilogue_diff'])if(!Array.isArray(value[key]))fail('partial','Diff omitted an instruction section.');
  }else if(path==='/bulk_fuzzy_match'||path==='/find_similar_functions_fuzzy') {
    if(!Array.isArray(value.matches)||value.matches.length>Number(parameters.limit??(path==='/bulk_fuzzy_match'?50:20)))fail('partial','Matching result exceeds its page.');
    if(path==='/bulk_fuzzy_match'){count(value.total_source_functions);if(value.offset!==parameters.offset||value.limit!==parameters.limit)fail('partial','Matching page changed its selectors.');}
    else count(value.total_matches);
  }else fail('schema','Cross-target query lacks a result contract.');
  return value;
}
export const transferCategories=['function_names','function_signatures','function_plate_comments','function_calling_conventions','function_no_return_flags',
  'function_tags','function_locals','data_types','data_definitions','data_plate_comments','instruction_comments','data_item_comments','labels','globals','external_locations','bookmarks','equates'] as const;
export function transferResult(input:unknown,dryRun:boolean) {
  const value=object(input);if(value.dry_run!==dryRun||count(value.errors)!==0)fail('partial','Documentation transfer reported an incomplete outcome.');
  const categories:Record<string,{planned:number;applied:number}>={};let total=0;
  for(const key of transferCategories){const item=object(value[key]),planned=count(item.planned),applied=count(item.applied);
    if(applied!==planned)fail('partial','Documentation transfer skipped part of '+key);categories[key]={planned,applied};total+=applied;}
  return {dryRun,categories,total};
}
/** Routing identities become logical scopes; arbitrary function/symbol names remain untouched. */
export function logicalPrograms(value:unknown,names:Map<string,Scope>):unknown {
  if(Array.isArray(value))return value.map(item=>logicalPrograms(item,names));
  if(!value||typeof value!=='object')return value;
  return Object.fromEntries(Object.entries(value).filter(([key])=>!['source_path','target_path'].includes(key)).map(([key,item])=>
    [key,['program','source_program','target_program'].includes(key)&&typeof item==='string'&&names.has(item)?names.get(item):logicalPrograms(item,names)]));
}
