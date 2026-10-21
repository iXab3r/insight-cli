import {command,Permission,type CommandContext} from '@eyeauras/cli-factory';
import {scope,number,address,type Research,type ResearchBackend} from './research.js';
import type {Scope} from './workspace.js';
import {selectedOptions} from './arguments.js';
import {fail,object,digest,stable} from './model.js';
import {parseDomainJson} from './json.js';

export const anchorAlgorithm='raw-string-anchors-v1';
export const anchorEncodings=['ascii','utf16le'] as const;
type Encoding=typeof anchorEncodings[number];
interface Frontier {address:string;encoding:Encoding}
interface Query {text:string;encodings:Encoding[];start:string;end:string;cap:number}
interface Budgets {max_bytes:number;max_candidates:number;timeout_seconds:number;limit:number}
export interface AnchorRequest {query:Query;from:Frontier;budgets:Budgets;expectedView?:string}
const defaults:Budgets={max_bytes:4194304,max_candidates:10000,timeout_seconds:5,limit:100};
const big=(s:string)=>BigInt('0x'+s);
const hex=(v:unknown)=>{const s=address(v);if(!/^[a-f0-9]{1,16}$/.test(s))fail('invalid','String anchors require default-space unsigned addresses.');return s;};
const bytes=(s:string,e:Encoding)=>Buffer.from(s,e==='ascii'?'ascii':'utf16le');
function wellFormed(s:string){for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const next=s.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))return false;}else if(c>=0xdc00&&c<=0xdfff)return false;}return true;}
function query(raw:unknown):Query{
 const q=object(raw),text=q.text;
 if(typeof text!=='string'||!text.length||text.length>256||!wellFormed(text)||text.includes('\0'))fail('invalid','Supply a literal of 1–256 UTF-16 units, without NUL or unpaired surrogates.');
 if(!Array.isArray(q.encodings)||q.encodings.length<1||q.encodings.length>2)fail('invalid','Select ascii, utf16le, or both.');
 const encodings=anchorEncodings.filter(e=>(q.encodings as unknown[]).includes(e));
 if(encodings.length!==q.encodings.length)fail('invalid','Encodings must be distinct supported values.');
 if(encodings.includes('ascii')&&/[^\x00-\x7f]/.test(text))fail('invalid','Text is not representable in ASCII; select utf16le only.');
 const cap=number(q.cap,8192,16);if(cap%2||encodings.some(e=>bytes(text,e).length>cap))fail('invalid','--max-string-bytes must be even and fit every encoded needle.');
 const start=hex(q.start),end=hex(q.end);if(big(start)>big(end))fail('invalid','scan-through must not precede scan-from.');
 return {text,encodings,start,end,cap};
}
function budgets(o:Record<string,unknown>,base=defaults):Budgets{return {max_bytes:number(o.maxBytes??base.max_bytes,16777216,32768),max_candidates:number(o.maxCandidates??base.max_candidates,100000,1),timeout_seconds:number(o.timeoutSeconds??base.timeout_seconds,30,1),limit:number(o.limit??base.limit,1000,1)};}
function frontier(raw:unknown,q:Query):Frontier{
 const f=object(raw),at=hex(f.address);if(big(at)<big(q.start)||big(at)>big(q.end)||!q.encodings.includes(f.encoding as Encoding))fail('invalid','String-anchor frontier is outside the query.');
 return {address:at,encoding:f.encoding as Encoding};
}
function ordinal(f:Frontier,q:Query){return big(f.address)*BigInt(q.encodings.length)+BigInt(q.encodings.indexOf(f.encoding));}
export function anchorRequest(o:Record<string,unknown>,who:Scope):AnchorRequest{
 if(o.cursor!==undefined){
  if(['text','encodings','scanFrom','scanThrough','maxStringBytes'].some(k=>o[k]!==undefined))fail('invalid','Cursor excludes text, encodings, range and context-cap selectors.');
  if(typeof o.cursor!=='string'||o.cursor.length>16384||!/^sa1\.[A-Za-z0-9_-]+$/.test(o.cursor))fail('invalid','Malformed string-anchor cursor.');
  let c:Record<string,unknown>;try{const encoded=o.cursor.slice(4),b=Buffer.from(encoded,'base64url');if(b.toString('base64url')!==encoded)throw Error();c=object(parseDomainJson(b.toString('utf8')));}catch{fail('invalid','Malformed string-anchor cursor.');}
  if(c.version!==1||c.algorithm!==anchorAlgorithm||stable(c.scope)!==stable(who)||typeof c.view!=='string'||!/^[a-f0-9]{64}$/.test(c.view))fail('invalid','Cursor scope, algorithm or view is incompatible.');
  const q=query(c.query),b=object(c.budgets);if(['max_bytes','max_candidates','timeout_seconds','limit'].some(k=>!Number.isSafeInteger(b[k])))fail('invalid','Malformed cursor budgets.');
  return {query:q,from:frontier(c.next,q),expectedView:c.view,budgets:budgets(o,budgets({maxBytes:b.max_bytes,maxCandidates:b.max_candidates,timeoutSeconds:b.timeout_seconds,limit:b.limit}))};
 }
 if(typeof o.text!=='string'||typeof o.encodings!=='string'||typeof o.scanFrom!=='string'||typeof o.scanThrough!=='string')fail('invalid','Supply --text, --encodings, --scan-from and --scan-through, or --cursor.');
 const q=query({text:o.text,encodings:o.encodings.split(',').map(x=>x.trim()),start:o.scanFrom,end:o.scanThrough,cap:o.maxStringBytes??1024});
 return {query:q,from:{address:q.start,encoding:q.encodings[0]!},budgets:budgets(o)};
}
function decoded(raw:Buffer,e:Encoding):string|null{
 if(e==='ascii')return raw.some(x=>x>127)?null:raw.toString('ascii');
 try{return new TextDecoder('utf-16le',{fatal:true,ignoreBOM:true}).decode(raw);}catch{return null;}
}
export function anchorResult(raw:unknown,r:AnchorRequest,modification:string){
 const v=object(raw),s=object(v.scan),q=r.query,b=r.budgets;
 if(v.algorithm!==anchorAlgorithm||stable(v.encodings)!==stable(q.encodings)||v.modification!==modification){
  if(typeof v.modification==='string'&&v.modification!==modification)fail('binding','Native view changed during string-anchor scan.',{reason:'changed_view'});
  fail('partial','Malformed string-anchor protocol facts.');
 }
 if(!Array.isArray(v.matches)||v.matches.length>b.limit||stable(s.from)!==stable(r.from)||s.through!==q.end||typeof s.complete!=='boolean'||s.complete!==(s.reason==='exhausted')||!['exhausted','byte_limit','candidate_limit','timeout','result_limit'].includes(String(s.reason)))fail('partial','Malformed string-anchor coverage.');
 for(const k of ['bytesRead','testedPairs','candidates'])if(!Number.isSafeInteger(s[k])||Number(s[k])<0)fail('partial','Malformed string-anchor counters.');
 if(Number(s.bytesRead)>b.max_bytes||Number(s.testedPairs)>Number(s.bytesRead)*q.encodings.length||Number(s.candidates)>b.max_candidates||Number(s.candidates)<v.matches.length||Number(s.candidates)>Number(s.testedPairs)+1||!Number.isFinite(s.elapsedMs)||Number(s.elapsedMs)<0)fail('partial','Inconsistent string-anchor budgets.');
 const next=s.complete?null:frontier(s.next,q);if(s.complete&&s.next!==null||next&&ordinal(next,q)<ordinal(r.from,q)||next&&BigInt(Number(s.testedPairs))>ordinal(next,q)-ordinal(r.from,q))fail('partial','String-anchor frontier changed.');
 if(next&&ordinal(next,q)===ordinal(r.from,q)&&s.reason!=='timeout')fail('partial','String-anchor scan made no progress despite its minimum work budget.');
 let previous=ordinal(r.from,q)-1n;
 for(const item of v.matches){
  const row=object(item),at=hex(row.matchAddress),encoding=row.encoding as Encoding;
  if(!q.encodings.includes(encoding))fail('partial','Unknown string-anchor encoding.');
  const pair={address:at,encoding},order=ordinal(pair,q),needle=bytes(q.text,encoding),unit=encoding==='ascii'?1:2,l=object(row.literalCandidate);
  if(order<=previous||order<ordinal(r.from,q)||next&&order>=ordinal(next,q)||big(at)+BigInt(needle.length-1)>big(q.end)||row.matchByteLength!==needle.length)fail('partial','String-anchor pair/order changed.');previous=order;
  if(typeof l.textBytes!=='string'||! /^(?:[a-f0-9]{2})+$/.test(l.textBytes)||l.textBytes.length>q.cap*2)fail('partial','String-anchor context bytes are missing or unbounded.');
  const data=Buffer.from(l.textBytes,'hex'),from=hex(l.textFrom),offset=big(at)-big(from),left=l.start===null?null:hex(l.start),right=l.terminatorAddress===null?null:hex(l.terminatorAddress);
  if(offset<0n||offset>BigInt(q.cap)||Number(offset)%unit||data.length%unit||l.textByteLength!==data.length||big(from)<big(q.start)||big(from)+BigInt(data.length-1)>big(q.end)||!data.subarray(Number(offset),Number(offset)+needle.length).equals(needle))fail('partial','String-anchor preview does not contain its byte match.');
  for(let i=0;i<data.length;i+=unit)if(data[i]===0&&(unit===1||data[i+1]===0))fail('partial','String-anchor preview crossed a NUL boundary.');
  const boundaries=['nul','range_edge','memory_edge','string_limit'];
  if(!boundaries.includes(String(l.leftBoundary))||!boundaries.includes(String(l.rightBoundary))||(l.leftBoundary==='nul')!==(left!==null)||(l.rightBoundary==='nul')!==(right!==null))fail('partial','String-anchor boundary facts changed.');
  if(left!==null&&(big(left)>big(at)||big(left)<big(q.start)+BigInt(unit)||big(left)>big(from)||row.matchOffsetBytes!==Number(big(at)-big(left))||Number(big(at)-big(left))%unit||Number(big(at)-big(left))>q.cap-needle.length)||left===null&&row.matchOffsetBytes!==null)fail('partial','Invalid candidate start/offset.');
  if(right!==null&&(big(right)<big(at)+BigInt(needle.length)||big(right)+BigInt(unit-1)>big(q.end)||big(right)<big(from)+BigInt(data.length)||Number(big(right)-big(at)-BigInt(needle.length))%unit||Number(big(right)-big(at)-BigInt(needle.length))>q.cap-needle.length))fail('partial','Invalid candidate terminator.');
  const bounded=left!==null&&right!==null,total=bounded?Number(big(right!)-big(left!)):null,text=decoded(data,encoding),complete=bounded&&total!<=q.cap&&text!==null;
  const reason=complete?'complete':total!==null&&total>q.cap||l.leftBoundary==='string_limit'||l.rightBoundary==='string_limit'?'string_limit':!bounded?'missing_boundary':'invalid_encoding';
  if(l.boundariesComplete!==bounded||l.byteLength!==total||l.text!==text||l.decoding!==(text===null?'invalid':'valid')||l.complete!==complete||l.reason!==reason||complete&&(from!==left||data.length!==total))fail('partial','Inconsistent string-anchor context/decoding facts.');
 }
 if(Buffer.byteLength(JSON.stringify(v))>1000000)fail('limit','String-anchor native response exceeds its envelope reserve.');return v;
}
export async function inspectAnchors(backend:ResearchBackend,who:Scope,r:AnchorRequest,view:string,observation:unknown,observe:()=>Promise<unknown>){
 if(r.expectedView!==undefined&&r.expectedView!==view)fail('binding','String-anchor continuation view changed.',{reason:'changed_view'});
 const modification=object(observation).modification;if(typeof modification!=='string')fail('unsupported','String anchors require guarded native observations.');
 const q=r.query;let raw:unknown;
 try{raw=await backend.call(who,'/insight/string-anchors/v1',{text:q.text,encodings:q.encodings.join(','),scan_from:q.start,scan_through:q.end,resume_address:r.from.address,resume_encoding:r.from.encoding,max_string_bytes:q.cap,...r.budgets});}
 catch(error){if(digest(observation)!==digest(await observe()))fail('binding','Native view changed during string-anchor scan.',{reason:'changed_view'});throw error;}
 if(digest(observation)!==digest(await observe()))fail('binding','Native view changed during string-anchor scan.',{reason:'changed_view'});
 const value=anchorResult(raw,r,modification),cursor=value.scan&&object(value.scan).complete?null:'sa1.'+Buffer.from(stable({version:1,algorithm:anchorAlgorithm,scope:who,query:q,next:object(value.scan).next,view,budgets:r.budgets})).toString('base64url');
 const result={...who,value:{...value,view:{identity:view},cursor}};if(Buffer.byteLength(JSON.stringify(result))>1048576)fail('limit','String-anchor response exceeds one MiB.');return result;
}
export function stringAnchorCommands(research:(c:CommandContext)=>Research){return [command('strings','String research',[command('anchors','Find raw literal byte hits and separate bounded NUL-delimited candidate context',({options:o},c)=>{const who=scope(o);return research(c).stringAnchors(who,anchorRequest(o,who));},{permission:Permission.ReadOnly,options:[...selectedOptions,
 {flags:'--text <literal>',description:'Case-sensitive literal, 1–256 UTF-16 units, no NUL'},
 {flags:'--encodings <encodings>',description:'Explicit ascii, utf16le, or both; no alignment assumption'},
 {flags:'--scan-from <address>',description:'Inclusive range start; context stays inside the range'},
 {flags:'--scan-through <address>',description:'Inclusive range end; the whole needle must fit'},
 {flags:'--max-string-bytes <count>',description:'Even candidate/preview payload cap 16–8192, default 1024'},
 {flags:'--cursor <token>',description:'Stateless continuation; excludes text/encodings/range/context selectors'},
 {flags:'--max-bytes <count>',description:'32768–16777216 actual bytes read including context/rereads; default 4194304'},
 {flags:'--max-candidates <count>',description:'1–100000 raw matched address/encoding pairs; default 10000'},
 {flags:'--timeout-seconds <count>',description:'1–30 second cooperative scan deadline; default 5'},
 {flags:'--limit <count>',description:'1–1000 raw hits per call; default 100'}]})])];}
