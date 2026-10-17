import {fail} from './model.js';
export interface ProcmonEvent {time:string;process:string;pid:number;operation:string;path:string;result:string;detail:string;duration?:string}
/** Parse complete, bounded native CSV rather than splitting quoted paths/details at commas. */
export function procmonEvents(bytes:Buffer):ProcmonEvent[]{
 if(bytes.length>16*1024**2)fail('limit','Native ProcMon CSV exceeds 16 MiB; retained diagnostics are incomplete.');
 let source:string;try{const marker=bytes.subarray(0,2).toString('hex');source=new TextDecoder(marker==='fffe'?'utf-16le':marker==='feff'?'utf-16be':'utf-8',{fatal:true}).decode(bytes);}catch{fail('partial','Native ProcMon CSV encoding is invalid; retained bytes were not replaced.');}
 if(source.includes('\0'))fail('partial','Native ProcMon CSV contains invalid text.');
 const rows:string[][]=[];let row:string[]=[],value='',quoted=false,closed=false;
 const cell=()=>{if(row.length>=64)fail('limit','Native ProcMon CSV exceeds its column bound.');row.push(value);value='';closed=false;};
 const record=()=>{cell();if(row.some(x=>x.length))rows.push(row);row=[];if(rows.length>100001)fail('limit','Native ProcMon CSV exceeds 100000 event rows.');};
 for(let i=0;i<source.length;i++){
  const c=source[i]!;
  if(quoted){if(c==='"'){if(source[i+1]==='"'){value+='"';i++;}else{quoted=false;closed=true;}}else value+=c;continue;}
  if(c==='"'){if(value||closed)fail('partial','Native ProcMon CSV has an invalid quote.');quoted=true;}
  else if(c===',')cell();else if(c==='\n'||c==='\r'){if(c==='\r'&&source[i+1]==='\n')i++;record();}
  else{if(closed)fail('partial','Native ProcMon CSV has text after a quoted cell.');value+=c;}
 }
 if(quoted)fail('partial','Native ProcMon CSV ends inside a quoted value.');if(value||row.length||closed)record();
 const header=rows.shift();if(!header)fail('partial','Native ProcMon CSV has no header.');
 const columns=['Process Name','PID','Operation','Path','Result','Detail'],indices=Object.fromEntries(columns.map(name=>[name,header.indexOf(name)]));
 if(Object.values(indices).some(i=>i<0)||new Set(header).size!==header.length)fail('partial','Native ProcMon CSV has an unsupported header.');
 const time=header.indexOf('Time of Day')>=0?header.indexOf('Time of Day'):header.indexOf('Date & Time'),duration=header.indexOf('Duration');
 return rows.map(row=>{
  if(row.length!==header.length||!/^\d+$/.test(row[indices.PID!]!))fail('partial','Native ProcMon CSV has a malformed event.');const pid=Number(row[indices.PID!]!);if(!Number.isSafeInteger(pid)||pid>0xffffffff)fail('partial','Native ProcMon CSV PID is invalid.');
  return {time:time>=0?row[time]!:'',process:row[indices['Process Name']!]!,pid,operation:row[indices.Operation!]!,path:row[indices.Path!]!,result:row[indices.Result!]!,detail:row[indices.Detail!]!,...(duration>=0?{duration:row[duration]!}:{})};
 });
}
export function procmonScope(events:ProcmonEvent[],pid:number,path?:string){
 if(events.some(e=>e.pid!==pid||path!==undefined&&e.path.toLowerCase()!==path.toLowerCase()))fail('partial','Native ProcMon capture scope was not established; no foreign events were returned.');
 return events;
}
