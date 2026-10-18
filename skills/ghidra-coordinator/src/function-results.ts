import {fail} from './model.js';

const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
export function functionFailure(selector:string,reason:string,diagnostic?:unknown):never {
  const nativeDiagnostic=typeof diagnostic==='string'?Array.from(diagnostic.replace(/[\u0000-\u001f\u007f-\u009f]/g,' ')).slice(0,500).join(''):undefined;
  fail('partial','Function inspection failed: '+reason+'.',{selector,reason,...(nativeDiagnostic?{nativeDiagnostic}:{})});
}
export function functionResult(value:unknown,selector:string){
  if(!record(value)||!record(value.functions))functionFailure(selector,'invalid_native_shape');
  const functions=value.functions;
  if(Object.keys(functions).length!==1||!Object.hasOwn(functions,selector))functionFailure(selector,'selector_mismatch');
  const found=functions[selector];
  if(!record(found))functionFailure(selector,'invalid_native_shape');
  if(found.error!==undefined)functionFailure(selector,typeof found.error==='string'&&/^Function not found\b/i.test(found.error)?'function_not_found':'native_function_failure',found.error);
  if(typeof found.name!=='string'||!found.name||typeof found.entry_point!=='string'||!found.entry_point)functionFailure(selector,'invalid_native_shape');
  return found;
}
