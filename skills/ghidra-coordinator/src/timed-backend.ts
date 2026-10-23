import {timed} from './internal-timing.js';
import type {ResearchBackend} from './research.js';
/** Observe existing boundaries; retain original method receivers and domain behavior. */
export function timedBackend(backend:ResearchBackend):ResearchBackend {
 return new Proxy(backend,{get(target,key){const member=Reflect.get(target,key);if(typeof member!=='function')return member;
  if(key==='open')return (...args:unknown[])=>timed('context.open','open',async()=>Reflect.apply(member,target,args));
  if(key==='saved')return (...args:unknown[])=>timed('context.save','saved',async()=>Reflect.apply(member,target,args));
  if(key==='call')return (...args:unknown[])=>timed('backend.operation',String(args[1]),async()=>Reflect.apply(member,target,args));
  return member.bind(target);
 }});
}
