import type {OptionDefinition} from '@eyeauras/cli-factory';
import {address} from './research.js';
import {fail} from './model.js';
import {parseDomainJson} from './json.js';
export interface Parameter {name:string;type:string;required:boolean;default?:string;semantic?:string;allowEmpty?:boolean}
export const key=(name:string)=>name.replace(/_([a-z])/g,(_,letter:string)=>letter.toUpperCase());
export const flag=(name:string)=>name.replaceAll('_','-');
export function parsed(p:Parameter,value:unknown):unknown {
  if(p.type==='boolean') {
    if(value===true||value==='true')return true;if(value===false||value==='false')return false;
    fail('invalid',`${flag(p.name)} must be true or false.`);
  }
  if(p.type==='integer'||p.type==='number') {
    if(typeof value!=='string'&&typeof value!=='number'||typeof value==='string'&&!/^-?\d+(?:\.\d+)?$/.test(value))
      fail('invalid',`${flag(p.name)} must be a finite ${p.type}.`);
    const result=Number(value);
    if(!Number.isFinite(result)||p.type==='integer'&&!Number.isSafeInteger(result))fail('invalid',`${flag(p.name)} is outside numeric range.`);
    if(p.name==='offset'&&p.default!=='-1'&&result<0||p.name==='limit'&&(result<1||result>1000)||
      p.name==='length'&&(result<(p.default==='0'?0:1)||result>65536)||p.name==='max_steps'&&(result<1||result>1000000)||
      /^(max_steps|max_functions|num_examples|context_instructions|call_context_limit|call_context_lines|depth)$/.test(p.name)&&result<0)
      fail('invalid',`${flag(p.name)} is outside its supported query range.`);
    if(p.name==='timeout_seconds'&&(result<1||result>1800))fail('invalid','timeout-seconds must be between 1 and 1800.');
    return result;
  }
  if(['json','object','array','any'].includes(p.type)) {
    let result=value;
    if(typeof value==='string'){if(value.length>65536)fail('limit','JSON input exceeds 64 KiB.');try{result=parseDomainJson(value);}catch{fail('invalid',`${flag(p.name)} requires valid JSON.`);}}
    if(p.type==='object'&&(!result||Array.isArray(result)||typeof result!=='object')||p.type==='array'&&!Array.isArray(result))
      fail('invalid',`${flag(p.name)} has the wrong JSON shape.`);
    if(JSON.stringify(result).length>65536)fail('limit','JSON input exceeds 64 KiB.');return result;
  }
  if(typeof value!=='string'||value.length>16000||value.includes('\0')||!value&&p.required&&!p.allowEmpty)fail('invalid',`${flag(p.name)} needs bounded text.`);
  return p.semantic==='address'?address(value):value;
}
export const selectedOptions:OptionDefinition[]=[{flags:'--session <id>',description:'Select the durable research session',required:true},
  {flags:'--target <id>',description:'Select the immutable input target',required:true}];
export function option(p:Parameter):OptionDefinition {
  const value=p.default;
  const defaultValue=value===undefined||value===''?undefined:parsed(p,value);
  return {flags:`--${flag(p.name)} <${p.type==='json'?'json':p.type}>`,
    description:p.semantic==='function_ref'?'Function name or explicit address':p.semantic==='address'?'Explicit hexadecimal address':
      `${flag(p.name)} (${p.type}${p.name==='limit'?', 1–1000':p.name==='length'?', 1–65536 bytes':''})`,
    ...(p.required?{required:true}:{}),...(defaultValue===undefined?{}:{defaultValue}),
    ...(['json','object','array','any'].includes(p.type)?{}:{parse:(value:string)=>parsed(p,value)})};
}
