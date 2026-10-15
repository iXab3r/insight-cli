import {object,fail,text} from './model.js';
import {address,publicAddress} from './research.js';
import type {ResearchBackend} from './research.js';
import type {Artifact} from './artifacts.js';
const array=(raw:unknown)=>{if(!Array.isArray(raw))fail('partial','Debugger inventory is absent.');return raw.map(object);};
const count=(value:unknown)=>{if(!Number.isSafeInteger(value)||Number(value)<0)fail('partial','Debugger count is invalid.');};
export async function debuggerProgramMetadata(backend:Pick<ResearchBackend,'inspect'>,snapshot:Artifact){
  if(!backend.inspect)return undefined;const value=object(await backend.inspect(snapshot,{kind:'debugger_bookmarks'}));
  if(typeof value.fingerprint!=='string'||! /^[a-f0-9]{64}$/.test(value.fingerprint))fail('partial','Debugger program metadata inspection is incomplete.');count(value.count);return value.fingerprint;
}
export function debuggerResult(operation:string,p:Record<string,unknown>,raw:unknown){
  if(['launch_offers','traces','modules','list_breakpoints','stack_trace'].includes(operation)){
    const rows=array(raw);for(const row of rows){
      if(operation==='launch_offers'){text(row.title);text(row.config_name);if(typeof row.supports_image!=='boolean'||typeof row.requires_image!=='boolean'||!Array.isArray(row.parameters))fail('partial','Debugger launch offer is incomplete.');}
      if(operation==='traces'){text(row.name);if(typeof row.current!=='boolean')fail('partial','Trace selection is absent.');count(row.module_count);count(row.thread_count);}
      if(operation==='modules'){text(row.name);if(row.base!==undefined)row.base=publicAddress(row.base);if(row.size!==undefined&&!/^0x[0-9a-f]+$/i.test(String(row.size)))fail('partial','Module size is invalid.');}
      if(operation==='list_breakpoints'){row.address=publicAddress(row.address);count(row.trace_location_count);if(typeof row.name!=='string'||row.name.length>4096||row.name.includes('\0'))fail('partial','Breakpoint name is invalid.');text(row.state);if(!Array.isArray(row.kinds)||row.kinds.some(kind=>typeof kind!=='string'))fail('partial','Breakpoint kinds are absent.');}
      if(operation==='stack_trace'){count(row.level);if(row.address!==undefined)row.address=publicAddress(row.address);}
    }
    return rows;
  }
  const value=object(raw);
  if(operation==='status'){
    if(value.debugger_active!==true||typeof value.trace_active!=='boolean')fail('partial','Debugger status is incomplete.');count(value.open_traces);
    if(value.trace_active){if(typeof value.target_connected!=='boolean')fail('partial','Trace connection state is absent.');count(value.module_count);if(value.execution_state!==undefined&&!['RUNNING','STOPPED','ALIVE','TERMINATED','UNKNOWN','INACTIVE'].includes(String(value.execution_state)))fail('partial','Debugger execution state is invalid.');}
  }else if(operation==='registers'){
    for(const [name,register]of Object.entries(value)){text(name,128);if(typeof register!=='string'||!/^0x[a-f0-9]{1,16}$/i.test(register))fail('partial','Register result is not an exact hexadecimal value.');}
  }else if(operation==='read_memory'){
    if(address(value.address)!==address(p.address)||!Number.isSafeInteger(value.size)||Number(value.size)<0||Number(value.size)>Number(p.size)||typeof value.hex!=='string'||!/^(?:[a-f0-9]{2})*$/i.test(value.hex)||value.hex.length!==Number(value.size)*2||!Array.isArray(value.dwords)||value.dwords.length!==Math.floor(Number(value.size)/4))fail('partial','Debugger memory read is inconsistent.');
    value.address=publicAddress(value.address);
    for(let i=0;i<value.dwords.length;i++){const bytes=(value.hex as string).slice(i*8,i*8+8).match(/../g)!.reverse().join('');
      if(typeof value.dwords[i]!=='string'||String(value.dwords[i]).toLowerCase()!=='0x'+bytes.toLowerCase())fail('partial','Debugger DWORDs differ from its memory bytes.');}
  }else if(operation==='static_to_dynamic'){
    if(address(value.static_address)!==address(p.address))fail('binding','Static mapping selected another address.');value.static_address=publicAddress(value.static_address);value.dynamic_address=publicAddress(value.dynamic_address);
  }else if(operation==='dynamic_to_static'){
    if(address(value.dynamic_address)!==address(p.address)||typeof value.module!=='string'||!/^0x[0-9a-f]+$/i.test(String(value.offset)))fail('partial','Dynamic mapping result is incomplete.');value.dynamic_address=publicAddress(value.dynamic_address);
  }else{
    const expected:Record<string,string>={launch:'launched',resume:'resumed',interrupt:'interrupted',step:p.kind==='out'?'stepped_out':'stepped',set_breakpoint:'set',remove_breakpoint:'removed'};
    if(value.status!==expected[operation]||!expected[operation])fail('partial','Debugger action did not establish its expected result.');
    if(operation==='launch'){text(value.offer_title);text(value.trace_name);}
    if(operation==='set_breakpoint'||operation==='remove_breakpoint'){if(address(value.address)!==address(p.address))fail('binding','Breakpoint action selected another address.');value.address=publicAddress(value.address);}
  }
  return value;
}
