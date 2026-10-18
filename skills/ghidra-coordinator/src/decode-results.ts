import {createHash} from 'node:crypto';
import {object,fail} from './model.js';
import {address} from './research.js';
export function decodedInstructions(raw:unknown,at:string,maxBytes:number,maxInstructions:number){
 const value=object(raw),input=value.input_bytes;
 if(typeof input!=='string'||! /^(?:[a-f0-9]{2})+$/.test(input)||input.length>maxBytes*2||value.input_sha256!==createHash('sha256').update(Buffer.from(input,'hex')).digest('hex')||address(value.address)!==at||!Array.isArray(value.instructions)||value.instructions.length>maxInstructions||typeof value.language!=='string'||typeof value.stop_reason!=='string'||!['byte_limit','instruction_limit','truncated_instruction','executable_block_end','terminal_flow','control_flow','context_unavailable','undecodable'].includes(value.stop_reason))fail('partial','Malformed bounded instruction result.');
 let consumed=0;
 for(const raw of value.instructions){const row=object(raw);
  if(!Number.isSafeInteger(row.length)||Number(row.length)<1||typeof row.bytes!=='string'||row.bytes!==input.slice(consumed*2,(consumed+Number(row.length))*2)||row.bytes.length!==Number(row.length)*2||typeof row.mnemonic!=='string'||!Array.isArray(row.operands)||row.operands.some(v=>typeof v!=='string')||!Array.isArray(row.direct_targets)||row.direct_targets.some(v=>typeof v!=='string')||typeof row.computed_flow!=='boolean'||row.computed_flow&&row.direct_targets.length)fail('partial','Decoded instruction does not match input bytes or flow.');
  const [space,offset]=at.includes(':')?at.split(':'):[undefined,at];
  if(address(row.address)!==(space?space+':':'')+(BigInt('0x'+offset)+BigInt(consumed)).toString(16))fail('partial','Decoded instruction address changed.');
  consumed+=Number(row.length);
 }
 if(value.consumed_bytes!==consumed||object(value.read_only??{}).modification_unchanged!==true)fail('partial','Decoder omitted consumed bytes or read-only proof.');
 return value;
}
