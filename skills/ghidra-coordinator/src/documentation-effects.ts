import type {ResearchBackend} from './research.js';
import {address} from './research.js';
import type {Artifact} from './artifacts.js';
import {object,fail} from './model.js';
const equal=(actual:unknown,expected:unknown,label:string)=>{if(actual!==expected)fail('partial',`Saved documentation ${label} differs from the requested effect.`);};
function offset(at:string,value:unknown) {
  const normalized=address(at),parts=normalized.split(':'),hex=parts.pop()!,distance=BigInt(String(value));
  if(distance<0n||distance>0x7fffffffffffffffn)fail('invalid','Documentation offsets must be nonnegative signed 64-bit integers.');
  return (parts.length?parts[0]+':':'')+(BigInt('0x'+hex)+distance).toString(16);
}
export async function verifyDocumentation(backend:ResearchBackend,snapshot:Artifact,p:Record<string,unknown>) {
  if(!backend.inspect)fail('configuration','Documentation requires saved-state inspection.');
  const document=object(p.json_body),at=address(document.target_address),inspect=(kind:string,parameters:Record<string,unknown>)=>backend.inspect!(snapshot,{kind,...parameters});
  const value=await inspect('function',{address:at});equal(value.exists,true,'function presence');
  if(document.function_name)equal(value.name,document.function_name,'function name');
  if(document.calling_convention)equal(value.callingConvention,document.calling_convention,'calling convention');
  const checkType=async(actual:unknown,name:unknown)=>{const wanted=await inspect('resolve_type',{name});equal(wanted.exists,true,'type presence');equal(actual,object(wanted.type).name,'type');};
  if(document.return_type)await checkType(value.returnType,document.return_type);
  if(document.plate_comment){const comments=await inspect('comments',{address:at});equal(comments.plate,document.plate_comment,'plate comment');}
  const requested=document.parameters??[];if(!Array.isArray(requested)||!Array.isArray(value.parameters))fail('partial','Documentation parameter inventory is absent.');
  for(const raw of requested){const parameter=object(raw),ordinal=Number(parameter.ordinal);
    if(!Number.isSafeInteger(ordinal)||ordinal<0||ordinal>=value.parameters.length)fail('partial','Documentation parameter ordinal is absent.');
    const saved=object(value.parameters[ordinal]);if(parameter.name)equal(saved.name,parameter.name,'parameter name');
    if(parameter.type)await checkType(saved.type,parameter.type);}
  if(document.comments!==undefined&&!Array.isArray(document.comments)||document.labels!==undefined&&!Array.isArray(document.labels))fail('invalid','Documentation comments and labels must be arrays.');
  for(const raw of document.comments as unknown[]??[]){const comment=object(raw),saved=await inspect('comments',{address:offset(at,comment.relative_offset)});
    if(comment.eol_comment)equal(saved.eol,comment.eol_comment,'EOL comment');if(comment.pre_comment)equal(saved.pre,comment.pre_comment,'PRE comment');}
  for(const raw of document.labels as unknown[]??[]){const label=object(raw),saved=await inspect('symbols',{address:offset(at,label.relative_offset)});
    if(!Array.isArray(saved.symbols)||!saved.symbols.some(symbol=>object(symbol).name===label.name))fail('partial','Documented label is absent from saved state.');}
  return {function:value};
}
