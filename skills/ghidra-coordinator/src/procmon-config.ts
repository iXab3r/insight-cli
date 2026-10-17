// First-party serializer of the public PMC format research, not a Python runtime dependency.
// https://github.com/eronnen/procmon-parser/blob/96080961e51745ddc6e83490c24e540553c44c71/docs/PMC%20Format.md
import {fail} from './model.js';
const u32=(value:number)=>{const bytes=Buffer.alloc(4);bytes.writeUInt32LE(value);return bytes;};
const record=(name:string,data:Buffer)=>{const key=Buffer.from(name+'\0','utf16le');return Buffer.concat([u32(16+key.length+data.length),u32(16),u32(16+key.length),u32(data.length),key,data]);};
const rule=(column:number,value:string,numeric=0)=>{const bytes=Buffer.from(value+'\0','utf16le');return Buffer.concat([u32(column),u32(0),Buffer.from([1]),u32(bytes.length),bytes,u32(numeric),u32(0)]);};
/** Must be verified with the pinned ProcMon before an adapter admits active capture. */
export function procmonConfiguration(pid:number,path?:string){
 if(!Number.isSafeInteger(pid)||pid<1||pid>0xffffffff)fail('invalid','A positive owned Windows PID is required.');
 if(path!==undefined&&(!path||/[\x00-\x1f]/.test(path)||path.length>4096))fail('invalid','ProcMon path must be a bounded literal native path without control characters.');
 const rules=[rule(40054,String(pid),pid),...(path?[rule(40071,path)]:[])];
 return Buffer.concat([record('FilterRules',Buffer.concat([Buffer.from([1]),u32(rules.length),...rules])),record('DestructiveFilter',u32(1)),record('Profiling',u32(0)),record('ResolveAddresses',u32(0)),record('Autoscroll',u32(0)),record('HistoryDepth',u32(1)),record('AdvancedMode',u32(0))]);
}
