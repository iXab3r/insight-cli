import {command,Permission,type CommandContext} from '@eyeauras/cli-factory';
import {scope,number,address,type Research,type ResearchBackend} from './research.js';
import type {Scope} from './workspace.js';
import {fail,object,digest,stable} from './model.js';
import {parseDomainJson} from './json.js';
import {selectedOptions} from './arguments.js';

export const referenceAlgorithm='x86-64-code-reference-candidates-v1';
export const referenceForms=['call-rel32','lea-rip','mov-rip','call-rip-slot'] as const;
type Form=typeof referenceForms[number];
export interface ReferenceQuery {targets:string[];forms:Form[];start:string;end:string}
export interface ReferenceBudgets {max_bytes:number;max_candidates:number;timeout_seconds:number;limit:number}
export interface ReferenceRequest {query:ReferenceQuery;from:string;budgets:ReferenceBudgets;expectedView?:string}
const defaults:ReferenceBudgets={max_bytes:4194304,max_candidates:200000,timeout_seconds:5,limit:100};
const hex=(v:unknown)=>{const s=address(v);if(!/^[a-f0-9]{1,16}$/.test(s))fail('invalid','Code-reference V1 requires default-space unsigned 64-bit addresses.');return s;};
const big=(s:string)=>BigInt('0x'+s);
function query(v:unknown):ReferenceQuery {
 const q=object(v);
 if(!Array.isArray(q.targets)||q.targets.length<1||q.targets.length>64||!Array.isArray(q.forms)||!q.forms.length||q.forms.length>4)fail('invalid','Select 1–64 targets and 1–4 reference forms.');
 const targets=q.targets.map(hex).sort((a,b)=>big(a)<big(b)?-1:big(a)>big(b)?1:0),forms=referenceForms.filter(f=>(q.forms as unknown[]).includes(f));
 if(new Set(targets).size!==targets.length||forms.length!==q.forms.length)fail('invalid','Targets/forms must be distinct supported values.');
 const start=hex(q.start),end=hex(q.end);if(big(start)>big(end))fail('invalid','scan-through must not precede scan-from.');
 return {targets,forms,start,end};
}
function budgets(v:Record<string,unknown>,base=defaults):ReferenceBudgets{return {max_bytes:number(v.maxBytes??base.max_bytes,16777216,15),max_candidates:number(v.maxCandidates??base.max_candidates,1000000,1),timeout_seconds:number(v.timeoutSeconds??base.timeout_seconds,30,1),limit:number(v.limit??base.limit,1000,1)};}
export function referenceRequest(o:Record<string,unknown>,who:Scope):ReferenceRequest {
 if(o.cursor!==undefined){
  if(['to','forms','scanFrom','scanThrough'].some(k=>o[k]!==undefined))fail('invalid','Cursor continuation cannot change targets, forms or scan bounds.');
  if(typeof o.cursor!=='string'||o.cursor.length>16384||!/^cr1\.[A-Za-z0-9_-]+$/.test(o.cursor))fail('invalid','Malformed code-reference cursor.');
  let c:Record<string,unknown>;try{const encoded=o.cursor.slice(4),bytes=Buffer.from(encoded,'base64url');if(bytes.toString('base64url')!==encoded)throw Error();c=object(parseDomainJson(bytes.toString('utf8')));}catch{fail('invalid','Malformed code-reference cursor.');}
  if(c.version!==1||c.algorithm!==referenceAlgorithm||stable(c.scope)!==stable(who)||typeof c.view!=='string'||!/^[a-f0-9]{64}$/.test(c.view))fail('invalid','Cursor version, scope or view is incompatible.');
  const q=query(c.query),from=hex(c.next),b=object(c.budgets);
  if(big(from)<big(q.start)||big(from)>big(q.end))fail('invalid','Cursor frontier is outside its range.');
  if(['max_bytes','max_candidates','timeout_seconds','limit'].some(k=>!Number.isSafeInteger(b[k])))fail('invalid','Malformed cursor budgets.');
  const inherited=budgets({maxBytes:b.max_bytes,maxCandidates:b.max_candidates,timeoutSeconds:b.timeout_seconds,limit:b.limit});
  return {query:q,from,budgets:budgets(o,inherited),expectedView:c.view};
 }
 if(typeof o.to!=='string'||typeof o.scanFrom!=='string'||typeof o.scanThrough!=='string')fail('invalid','Supply --to, --scan-from and --scan-through, or --cursor.');
 const q=query({targets:o.to.split(',').map(x=>x.trim()),forms:o.forms===undefined?[...referenceForms]:String(o.forms).split(',').map(x=>x.trim()),start:o.scanFrom,end:o.scanThrough});
 return {query:q,from:q.start,budgets:budgets(o)};
}

/** The deliberately small encoding contract, independently rechecked in the facade. */
export function referenceEncoding(input:Buffer){
 let p=0,rex=0,word=false;
 while(p<input.length&&p<15){const b=input[p]!;if([0x66,0x26,0x2e,0x36,0x3e].includes(b)){word ||= b===0x66;rex=0;p++;}else if(b>=0x40&&b<=0x4f){rex=b;p++;}else break;}
 const op=input[p],m=input[p+1];let form:Form,displacement:number,length:number,operand:number,bits:number;
 if(op===0xe8){form='call-rel32';length=p+5;displacement=p+1;operand=0;bits=64;}
 else {
  if(m===undefined||(m&0xc7)!==5)return;
  if(op===0x8d){form='lea-rip';operand=1;}
  else if(op!==undefined&&[0x88,0x89,0x8a,0x8b].includes(op)){form='mov-rip';operand=op===0x88||op===0x89?0:1;}
  else if(op===0xff&&((m>>3)&7)===2){form='call-rip-slot';operand=0;}
  else return;
  length=p+6;displacement=p+2;bits=form==='call-rip-slot'?64:op===0x88||op===0x8a?8:rex&8?64:word?16:32;
 }
 if(length>15||input.length<length)return;
 return {form,length,displacement,operand,bits,delta:input.readInt32LE(displacement),role:form==='call-rel32'?'direct-call-target':form==='call-rip-slot'?'pointer-slot':'effective-address'};
}
export function referenceResult(raw:unknown,r:ReferenceRequest){
 const v=object(raw),s=object(v.scan),q=r.query,b=r.budgets;
 if(v.algorithm!==referenceAlgorithm||typeof v.language!=='string'||!v.language.startsWith('x86:LE:64:')||stable(v.forms)!==stable(q.forms)||!Array.isArray(v.matches)||v.matches.length>b.limit||object(v.read_only??{}).modification_unchanged!==true)fail('partial','Malformed code-reference result.');
 for(const k of ['bytes_read','tested_starts','visited_candidates'])if(!Number.isSafeInteger(s[k])||Number(s[k])<0)fail('partial','Malformed reference scan counters.');
 const complete=s.complete;
 if(typeof complete!=='boolean'||Number(s.bytes_read)>b.max_bytes||Number(s.tested_starts)>Number(s.bytes_read)||Number(s.visited_candidates)>b.max_candidates||Number(s.visited_candidates)<v.matches.length||Number(s.visited_candidates)>Number(s.tested_starts)||!['exhausted','byte_limit','candidate_limit','timeout','result_limit'].includes(String(s.reason))||complete!==(s.reason==='exhausted')||!Number.isFinite(s.elapsed_ms)||Number(s.elapsed_ms)<0||hex(s.from)!==r.from||hex(s.through)!==q.end)fail('partial','Inconsistent code-reference coverage.');
 const next=complete?null:hex(s.next_start);
 if(complete&&s.next_start!==null||next!==null&&(big(next)<big(r.from)||big(next)>big(q.end))||next!==null&&BigInt(Number(s.tested_starts))>big(next)-big(r.from))fail('partial','Reference frontier changed.');
 let previous=-1n;
 for(const rawRow of v.matches){const row=object(rawRow),from=hex(row.from),to=hex(row.to),bytes=row.bytes;
  if(typeof bytes!=='string'||! /^(?:[a-f0-9]{2}){1,15}$/.test(bytes))fail('partial','Reference omitted its instruction bytes.');
  const encoding=referenceEncoding(Buffer.from(bytes,'hex'));
  if(!encoding||row.form!==encoding.form||!q.forms.includes(encoding.form)||row.length!==encoding.length||bytes.length!==encoding.length*2||row.operand_index!==encoding.operand||row.operand_bits!==encoding.bits||row.target_role!==encoding.role||!q.targets.includes(to)||big(to)!==BigInt.asUintN(64,big(from)+BigInt(encoding.length+encoding.delta))||big(from)<=previous||big(from)<big(r.from)||big(from)+BigInt(encoding.length-1)>big(q.end)||next!==null&&big(from)>=big(next)||!['listing-confirmed','listing-conflict','unconfirmed'].includes(String(row.boundary))||row.validation!=='decoded'||typeof row.instruction!=='string'||row.instruction.length>512)fail('partial','Reference bytes, target, form or frontier are inconsistent.');
  previous=big(from);
 }
 if(Buffer.byteLength(JSON.stringify(v))>1048576)fail('limit','Code-reference response exceeds one MiB.');return v;
}
export async function inspectCodeReferences(backend:ResearchBackend,who:Scope,r:ReferenceRequest,view:string,observation:unknown){
 if(r.expectedView!==undefined&&r.expectedView!==view)fail('binding','Code-reference continuation view changed.',{reason:'changed_view'});
 const q=r.query,result=await backend.call(who,'/code_references',{targets:q.targets,forms:q.forms,scan_from:r.from,scan_through:q.end,...r.budgets});
 if(digest(observation)!==digest(await backend.observation!(who)))fail('binding','Native view changed during code-reference scan.',{reason:'changed_view'});
 const value=referenceResult(result,r),s=object(value.scan);
 const cursor=s.complete?null:'cr1.'+Buffer.from(stable({version:1,algorithm:referenceAlgorithm,scope:who,query:q,next:hex(s.next_start),view,budgets:r.budgets})).toString('base64url');
 return {...who,value:{...value,view:{identity:view},cursor}};
}
export function codeReferenceCommands(research:(c:CommandContext)=>Research){return [command('analysis','Static analysis',[command('code-references','Find bounded x86-64 byte reference candidates without changing Listing or xrefs',({options:o},c)=>{const who=scope(o);return research(c).codeReferences(who,referenceRequest(o,who));},{permission:Permission.ReadOnly,options:[...selectedOptions,
 {flags:'--to <addresses>',description:'1–64 distinct exact default-space targets, comma separated'},
 {flags:'--forms <forms>',description:'call-rel32,lea-rip,mov-rip,call-rip-slot; defaults to all four'},
 {flags:'--scan-from <address>',description:'First candidate start (initial request)'},{flags:'--scan-through <address>',description:'Inclusive final byte; matches must fit completely'},
 {flags:'--cursor <token>',description:'Stateless continuation; excludes targets/forms/range selectors'},
 {flags:'--max-bytes <count>',description:'15–16777216 bytes read including lookahead; default 4194304'},
 {flags:'--max-candidates <count>',description:'1–1000000 prefiltered starts including rejected candidates; default 200000'},
 {flags:'--timeout-seconds <count>',description:'1–30 second cooperative native scan deadline; default 5'},
 {flags:'--limit <count>',description:'1–1000 matches per call; default 100'}]})])];}
