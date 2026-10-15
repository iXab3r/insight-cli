import {object,text,fail} from './model.js';
import {address} from './research.js';
import {parseDomainJson} from './json.js';

export function archiveOrigin(value:unknown):string {
  let url:URL;try{url=new URL(text(value,2048));}catch{fail('configuration','Configure an explicit archive URL.');}
  if(url.username||url.password||url.search||url.hash||url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(url.hostname)))
    fail('configuration','Archive URL must use HTTPS or local HTTP, without credentials, query or fragment.');
  return url.href.replace(/\/$/,'');
}
const integer=(value:unknown)=>{if(!Number.isSafeInteger(value)||Number(value)<0)fail('partial','Archive count is invalid.');return Number(value);};
export function archivePayload(raw:unknown,binary:string,version:string,run:string) {
  const p=object(raw);
  if(p.binary_name!==binary||p.version!==version||p.source_run_id!==run||p.source_tool!=='ghidra_mcp_ingest')fail('binding','Archive payload selected another input or request.');
  address(p.address);text(p.name);text(p.prototype,65536);
  if(typeof p.no_return!=='boolean'||typeof p.is_thunk!=='boolean')fail('partial','Archive function metadata is incomplete.');
  for(const key of ['function_size_bytes','instruction_count','basic_block_count'])if(p[key]!==undefined)integer(p[key]);
  if(p.opcode_hash!==undefined&&(typeof p.opcode_hash!=='string'||! /^[a-f0-9]{64}$/.test(p.opcode_hash)))fail('partial','Archive opcode hash is malformed.');
  for(const key of ['plate_comment','calling_convention'])if(p[key]!==undefined)text(p[key],65536);
  if(p.function_tags!==undefined){if(!Array.isArray(p.function_tags)||p.function_tags.length>10000)fail('partial','Archive tags are malformed.');for(const tag of p.function_tags)text(tag);}
  for(const key of ['locals','instruction_comments'])if(p[key]!==undefined){
    if(!Array.isArray(p[key])||p[key].length>10000)fail('partial','Archive documentation is malformed.');
    for(const rawRow of p[key]){const row=object(rawRow);if(key==='locals'){text(row.name);text(row.data_type);text(row.storage);text(row.source_type);}
      else{if(!Number.isSafeInteger(row.address_offset)||!['EOL','PRE','POST','REPEATABLE'].includes(String(row.type)))fail('partial','Archive instruction comment is malformed.');text(row.text,65536);}}
  }
  if(Buffer.byteLength(JSON.stringify(p))>262144)fail('limit','Archive function payload exceeds 256 KiB.');return p;
}
export async function archivePost(fetch:typeof globalThis.fetch,origin:string,payload:Record<string,unknown>,token?:string,signal?:AbortSignal) {
  let response:Response;
  try{response=await fetch(archiveOrigin(origin)+'/v1/doc_archive/upsert',{method:'POST',redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000),
    headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(payload)});}
  catch{fail('unknown','Archive response was lost; the request is retained and is not repeated.');}
  if(!response.ok){await response.body?.cancel();fail('unknown','Archive rejected the request; its external outcome is retained.');}
  const reader=response.body?.getReader();if(!reader)fail('partial','Archive response is empty.');const parts:Uint8Array[]=[];let size=0;
  try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>65536)fail('limit','Archive response exceeds 64 KiB.');parts.push(value);}}
  finally{await reader.cancel().catch(()=>{});}
  let raw;try{raw=parseDomainJson(Buffer.concat(parts).toString('utf8'));}catch{fail('partial','Archive response is not JSON.');}
  const result=object(raw);if(typeof result.created!=='boolean')fail('partial','Archive response omits its created flag.');
  const conflicts=integer(result.conflicts_enqueued);
  return {created:result.created,conflicts_enqueued:conflicts};
}
