import {createHash} from 'node:crypto';
const address=value=>String(value??'').toLowerCase().replace(/^0x/,'').replace(/^0+(?=.)/,'');
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const pick=(v,keys)=>Object.fromEntries(keys.map(k=>[k,v[k]]));
/** Only transport/profile/view identities and documented wrapper metadata are excluded. */
export function projection(stage,input){
 const name=stage.replace(/^(read|first)\./,''),v=input?.value??input;
 if(name==='metadata')return pick(v,['architecture','compiler','language','endian','address_size_bits','base_address','memory_blocks','total_memory_size','function_count','symbol_count']);
 if(name==='decompile'||name==='hash-decompile'){
  const fn=v.functions?Object.values(v.functions)[0]:v;
  return {signature:fn.signature,code:fn.code??fn.decompiled_code,comments:pick(v.comments??fn.comments??{},['eol','pre','post','plate','repeatable'])};
 }
 if(name==='bulk')return Object.fromEntries(Object.entries(v.functions).map(([selector,fn])=>[address(selector),pick(fn,['entry_point','signature','decompiled_code'])]));
 if(name==='memory'||name==='large-output')return {length:v.length,data:v.data,hex:v.hex};
 if(name==='paging')return pick(v,['items','count','offset','limit','total']);
 if(name==='strings'){const items=v.items??v.strings;return items.map(row=>({address:address(row.address),text:row.text??row.value??row.string})).sort((a,b)=>a.address.localeCompare(b.address));}
 if(name==='xrefs'){const items=v.items??v.references;return items.map(row=>({from:row.source==='entry-point'||/entry point/i.test(String(row.from??row.from_address??''))?'entry-point':address(row.from??row.from_address),to:address(row.to??row.to_address??v.requestedAddress),kind:row.kind??row.type})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));}
 if(name==='missing')return {reason:'function_not_found'};
 if(name==='undefined')return pick(v,['input_bytes','input_sha256','instructions','consumed_bytes','stop_reason','truncated']);
 return;
}
export function resultHash(stage,input){const value=projection(stage,input);return value===undefined?undefined:createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');}
