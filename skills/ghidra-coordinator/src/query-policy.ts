import {fail,object} from './model.js';

/** These operations have facade-owned, bounded native implementations. */
export const nativeQueries=new Set(['/research_view','/decode_instructions','/find_dead_code','/detect_crypto_constants','/get_valid_data_types',
  '/validate_data_type','/validate_function_prototype','/get_entry_points','/list_globals',
  '/list_strings','/search_strings','/find_data_types','/search_byte_patterns','/search_instructions',
  '/emulate_function','/emulate_hash_batch']);

const heuristics:Record<string,{kind:string;algorithm:string;limitations:string[]}>=Object.fromEntries([
  ['/find_similar_functions_fuzzy','similarity','mcp-fuzzy-instruction-match'],
  ['/bulk_fuzzy_match','similarity','mcp-fuzzy-instruction-match'],
  ['/analyze_function_completeness','score','mcp-documentation-completeness'],
  ['/analyze_for_documentation','suggestion','mcp-documentation-suggestions'],
  ['/find_similar_functions','similarity','mcp-function-metrics'],
  ['/analyze_global_completeness','score','mcp-global-documentation-completeness'],
  ['/audit_global','score','mcp-global-documentation-audit'],
  ['/audit_globals_in_function','score','mcp-global-documentation-audit'],
  ['/suggest_field_names','suggestion','mcp-type-name-patterns'],
  ['/detect_array_bounds','estimate','mcp-reference-stride-estimator'],
  ['/analyze_api_call_chains','pattern-match','mcp-api-name-patterns'],
  ['/detect_malware_behaviors','pattern-match','mcp-api-instruction-patterns'],
  ['/find_anti_analysis_techniques','pattern-match','mcp-symbol-instruction-patterns'],
  ['/extract_iocs_with_context','pattern-match','mcp-string-patterns'],
  ['/find_undocumented_by_string','suggestion','mcp-string-reference-documentation'],
].map(([path,kind,algorithm])=>[path!,{kind:kind!,algorithm:algorithm!,limitations:[
  'A static observation, heuristic or suggestion; not a proof of runtime behavior or completeness.',
  'Scores and confidence labels are not calibrated probabilities; the agent decides what to accept.',
]}]));

export function queryDescription(path:string,fallback:string) {
  if(path==='/find_dead_code')return 'Find blocks unreachable in the bounded static CFG; unresolved flow is reported';
  if(path==='/detect_crypto_constants')return 'Match versioned constant-table signatures within an explicit byte budget';
  if(path==='/get_valid_data_types')return 'Enumerate actually resolvable program/builtin types, with provenance and scan limits';
  if(path==='/validate_function_prototype')return 'Parse a prototype and resolve its convention without persisting changes';
  if(path==='/validate_data_type')return 'Resolve a type and report layout/alignment diagnostics without changing the program';
  if(path==='/get_entry_points')return 'Read external-entry metadata; report name/image-base candidates separately';
  if(path==='/list_globals')return 'Read structured global records with bounded symbol/reference scanning';
  if(path==='/list_strings'||path==='/search_strings')return 'Search defined string data only, with bounded visited-data scan; undefined literals: analysis search-byte-patterns';
  if(path.startsWith('/emulate_'))return 'Bounded isolated x86/x64 emulation with explicit ABI and termination reason';
  return heuristics[path]?fallback+' (qualified '+heuristics[path]!.kind+'; not ground truth)':fallback;
}

/** Reject placeholder/error payloads anywhere in the returned domain value. */
export function rejectPlaceholders(value:unknown,depth=0):void {
  if(depth>64)fail('partial','Query result nesting exceeds 64 levels.');
  if(!value||typeof value!=='object')return;
  const row=value as Record<string,unknown>;
  if(typeof row.status==='string'&&/not[ _-]*(?:yet[ _-]*)?implemented|placeholder|unsupported|unavailable/i.test(row.status))
    fail('unsupported','The backend returned an unavailable analysis instead of a completed result.');
  for(const child of Object.values(row))rejectPlaceholders(child,depth+1);
}

export function qualifyQuery(path:string,value:unknown) {
  rejectPlaceholders(value);
  if(!value||typeof value!=='object'||Array.isArray(value))return value;
  const result=object(value),semantics=heuristics[path];
  if(path==='/suggest_field_names'&&Array.isArray(result.suggestions))result.suggestions=result.suggestions.map(raw=>({
    ...object(raw),confidence:null,confidence_kind:'uncalibrated',
  }));
  return {...result,...(semantics?{semantics}:{}),...(!nativeQueries.has(path)?{scanPolicy:{
    execution:'pinned-upstream',pagination:'may-follow-full-scan',workBound:'not-guaranteed',
    maximumAcceptedResultBytes:1048576,
    note:'A page/output limit does not bound backend scan cost. Use a narrow function/address/filter; heavy upstream work may continue after transport cancellation.',
  }}:{})};
}
