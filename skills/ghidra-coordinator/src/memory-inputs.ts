import {createHash} from 'node:crypto';
import {fail,object} from './model.js';
import {address,number} from './research.js';
import type {ResearchBackend} from './research.js';
import type {Artifact} from './artifacts.js';

export function blockContent(p:Record<string,unknown>) {
  let bytes:Buffer|undefined;
  if(p.bytes_hex!==undefined&&p.bytes_base64!==undefined)fail('invalid','Choose bytes-hex or bytes-base64, not both.');
  if(p.bytes_hex!==undefined){const value=String(p.bytes_hex).replace(/\s/g,'');
    if(!value||value.length>33554432||value.length%2||!/^[0-9a-f]+$/i.test(value))fail('invalid','bytes-hex needs complete hex byte pairs, at most 16 MiB.');bytes=Buffer.from(value,'hex');}
  if(p.bytes_base64!==undefined){const value=String(p.bytes_base64);
    if(!value||value.length>22369624||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))fail('invalid','bytes-base64 needs canonical padded base64, at most 16 MiB.');
    bytes=Buffer.from(value,'base64');if(bytes.toString('base64')!==value)fail('invalid','bytes-base64 is not canonical.');}
  const initialized=p.initialized!==false,fill=number(p.fill_byte??0,255),size=number(p.size??bytes?.length,16777216,1);
  if(bytes&&bytes.length>size)fail('invalid','Initial content exceeds the requested block size.');
  if(!initialized&&(bytes||fill!==0))fail('invalid','Uninitialized blocks cannot have byte content or a nonzero fill byte.');
  const content=initialized?Buffer.alloc(size,fill):undefined;if(content&&bytes)bytes.copy(content);
  return {size,initialized,sha256:content?createHash('sha256').update(content).digest('hex'):null};
}

export async function verifyMemoryCreation(backend:ResearchBackend,snapshot:Artifact,p:Record<string,unknown>) {
  if(!backend.inspect)fail('configuration','Memory creation needs immutable saved-state inspection.');
  const expected=blockContent(p),value=object(await backend.inspect(snapshot,{kind:'memory',name:p.name,digest_bytes:true}));
  const equal=(actual:unknown,wanted:unknown,label:string)=>{if(actual!==wanted)fail('partial',`Saved memory ${label} differs from the requested effect.`);};
  equal(value.exists,true,'presence');equal(value.name,p.name,'name');equal(value.size,expected.size,'size');
  equal(value.initialized,expected.initialized,'initialization');equal(value.overlay,p.overlay??false,'overlay');
  for(const flag of ['read','write','execute','volatile'])equal(value[flag],p[flag]??['read','write'].includes(flag),flag);
  equal(value.comment??'',p.comment??'','comment');equal(value.sha256,expected.sha256,'content digest');
  const at=address(p.address),actual=String(value.start);
  if(p.overlay){equal(value.physicalStart!==undefined?address(value.physicalStart):undefined,at,'physical start');if(!actual.includes(':'))fail('partial','Saved overlay lost its address-space identity.');}
  else equal(address(actual),at,'start');
  return value;
}
