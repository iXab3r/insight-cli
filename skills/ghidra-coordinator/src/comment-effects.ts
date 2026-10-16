import type {ResearchBackend} from './research.js';
import {address} from './research.js';
import type {Artifact} from './artifacts.js';
import {object,fail} from './model.js';
const normalize=(value:unknown)=>value===''?null:value;
export async function verifyComments(backend:ResearchBackend,snapshot:Artifact,path:string,p:Record<string,unknown>) {
  if(!backend.inspect)fail('configuration','Batch comments require saved-state inspection.');
  const inspect=(kind:string,parameters:Record<string,unknown>)=>backend.inspect!(snapshot,{kind,...parameters});
  if(path==='/clear_function_comments') {
    const ref=String(p.function);let selector;try{selector={address:address(ref)};}catch{selector={name:ref};}
    const value=await inspect('function_comments',selector);
    if(p.clear_plate!==false&&value.plate!==null)fail('partial','Saved function plate comment was not cleared.');
    if(!Array.isArray(value.comments))fail('partial','Saved function comment inventory is absent.');
    for(const item of value.comments){const comment=object(item);
      if(comment.kind==='eol'&&p.clear_eol!==false||comment.kind==='pre'&&p.clear_pre!==false)
        fail('partial','Requested function comments remain in saved state.');}
    return value;
  }
  const verified=[];
  for(const [parameter,kind]of [['decompiler_comments','pre'],['disassembly_comments','eol']] as const) {
    const requested=p[parameter]??[];if(!Array.isArray(requested))fail('invalid','Batch comments require arrays of {address,comment}.');
    const expected=new Map<string,string|null>();
    for(const raw of requested){const item=object(raw);if(typeof item.comment!=='string')fail('invalid','Each batch comment requires text or empty text to clear.');
      expected.set(address(item.address),normalize(item.comment) as string|null);}
    for(const [at,text]of expected){const value=await inspect('comments',{address:at});
      if(value[kind]!==text)fail('partial','Saved batch comment differs from the requested text.');verified.push({address:at,kind,text});}
  }
  if(p.plate_comment!==undefined&&p.plate_comment!==null&&!(path==='/batch_apply_documentation'&&p.plate_comment==='')) {
    const value=await inspect('comments',{address:p.address});
    if(value.plate!==normalize(p.plate_comment))fail('partial','Saved batch plate comment differs from the requested text.');
    verified.push({address:p.address,kind:'plate',text:value.plate});
  }
  return {comments:verified};
}
