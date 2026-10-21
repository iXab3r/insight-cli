import {fail} from './model.js';

const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
export function functionFailure(selector:string,reason:string,diagnostic?:unknown):never {
  const nativeDiagnostic=typeof diagnostic==='string'?Array.from(diagnostic.replace(/[\u0000-\u001f\u007f-\u009f]/g,' ')).slice(0,500).join(''):undefined;
  const recovery=reason==='function_not_found'?' For a sparse interior address, use ghidra functions inspect --functions <address> --resolve-address containing-or-preceding --max-entry-distance <bytes> with the same session/target; a preceding entry is only a candidate. For known executable bytes without a function definition, use ghidra functions decode --address <hex> --max-bytes 64 --max-instructions 16 with the same session/target. Decode is read-only and does not create functions or xrefs.':
    reason==='native_function_failure'||reason==='missing_decompiler_text'?' For an existing function entry, try ghidra functions force-decompile --function <entry> with the same session/target. This refreshes decompiler output, not Listing instructions or stored xrefs; use functions decode for bounded local bytes.':'';
  fail('partial','Function inspection failed: '+reason+'.'+recovery,{selector,reason,...(nativeDiagnostic?{nativeDiagnostic}:{})});
}
export function functionResult(value:unknown,selector:string,options:{requireEntryPoint?:boolean}={}){
  if(!record(value)||!record(value.functions))functionFailure(selector,'invalid_native_shape');
  const functions=value.functions;
  if(Object.keys(functions).length!==1||!Object.hasOwn(functions,selector))functionFailure(selector,'selector_mismatch');
  const found=functions[selector];
  if(!record(found))functionFailure(selector,'invalid_native_shape');
  if(found.error!==undefined)functionFailure(selector,typeof found.error==='string'&&/^Function not found\b/i.test(found.error)?'function_not_found':'native_function_failure',found.error);
  if(typeof found.name!=='string'||!found.name)functionFailure(selector,'invalid_native_shape');
  if(options.requireEntryPoint!==false||found.entry_point!==undefined){
    if(typeof found.entry_point!=='string'||found.entry_point.length>128||!/^(?:[A-Za-z0-9_]+:)?(?:0x)?[a-fA-F0-9]+$/.test(found.entry_point))functionFailure(selector,'invalid_native_shape');
  }
  return found;
}
