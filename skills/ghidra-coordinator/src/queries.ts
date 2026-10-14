import {readFileSync} from 'node:fs';
import {command,Permission,type CommandContext,type CommandDefinition,type OptionDefinition} from '@eyeauras/cli-factory';
import {Research,scope,address} from './research.js';
import {fail} from './model.js';
import {queryResult} from './query-results.js';

interface Parameter {name:string;type:string;required:boolean;default?:string;semantic?:string;allowEmpty?:boolean}
interface Query {path:string;command:string;params:Parameter[]}
const catalog=JSON.parse(readFileSync(new URL('../../references/queries.json',import.meta.url),'utf8')) as {source:string;tools:Query[]};
if(catalog.source!=='57e37a8bf388b1279cff46378f85be1554548f61'||catalog.tools.length!==72)
  throw Error('Installed query contracts differ from the pinned facade build.');
const key=(name:string)=>name.replace(/_([a-z])/g,(_,letter:string)=>letter.toUpperCase());
const flag=(name:string)=>name.replaceAll('_','-');
function parsed(p:Parameter,value:unknown):unknown {
  if(p.type==='boolean') {
    if(value===true||value==='true')return true;if(value===false||value==='false')return false;
    fail('invalid',`${flag(p.name)} must be true or false.`);
  }
  if(p.type==='integer'||p.type==='number') {
    if(typeof value!=='string'&&typeof value!=='number'||typeof value==='string'&&!/^-?\d+(?:\.\d+)?$/.test(value))
      fail('invalid',`${flag(p.name)} must be a finite ${p.type}.`);
    const result=Number(value);
    if(!Number.isFinite(result)||p.type==='integer'&&!Number.isSafeInteger(result))fail('invalid',`${flag(p.name)} is outside numeric range.`);
    if(p.name==='offset'&&result<0||p.name==='limit'&&(result<1||result>1000)||
      p.name==='length'&&(result<1||result>65536)||p.name==='max_steps'&&(result<1||result>1000000)||
      /^(max_steps|max_functions|num_examples|context_instructions|call_context_limit|call_context_lines|depth)$/.test(p.name)&&result<0)
      fail('invalid',`${flag(p.name)} is outside its supported query range.`);
    return result;
  }
  if(['json','object','array','any'].includes(p.type)) {
    let result=value;
    if(typeof value==='string'){if(value.length>65536)fail('limit','JSON input exceeds 64 KiB.');try{result=JSON.parse(value);}catch{fail('invalid',`${flag(p.name)} requires valid JSON.`);}}
    if(p.type==='object'&&(!result||Array.isArray(result)||typeof result!=='object')||p.type==='array'&&!Array.isArray(result))
      fail('invalid',`${flag(p.name)} has the wrong JSON shape.`);
    if(JSON.stringify(result).length>65536)fail('limit','JSON input exceeds 64 KiB.');return result;
  }
  if(typeof value!=='string'||value.length>16000||value.includes('\0')||!value&&p.required&&!p.allowEmpty)fail('invalid',`${flag(p.name)} needs bounded text.`);
  return p.semantic==='address'?address(value):value;
}
const selectedOptions:OptionDefinition[]=[{flags:'--session <id>',description:'Select the durable research session',required:true},
  {flags:'--target <id>',description:'Select the immutable input target',required:true}];
function option(p:Parameter):OptionDefinition {
  const value=p.default;
  const defaultValue=value===undefined||value===''?undefined:parsed(p,value);
  return {flags:`--${flag(p.name)} <${p.type==='json'?'json':p.type}>`,
    description:p.semantic==='function_ref'?'Function name or explicit address':p.semantic==='address'?'Explicit hexadecimal address':
      `${flag(p.name)} (${p.type}${p.name==='limit'?', 1–1000':p.name==='length'?', 1–65536 bytes':''})`,
    ...(p.required?{required:true}:{}),...(defaultValue===undefined?{}:{defaultValue}),
    ...(['json','object','array','any'].includes(p.type)?{}:{parse:(value:string)=>parsed(p,value)})};
}
function value(result:unknown) {
  if(result===undefined||result===null)fail('partial','Query did not return its result.');
  let encoded;try{encoded=JSON.stringify(result);}catch{fail('partial','Query returned malformed JSON.');}
  if(encoded.length>1048576)fail('limit','Query result exceeds one MiB; narrow its scope or request a smaller page.');
  if(typeof result==='object'&&!Array.isArray(result)) {
    const o=result as Record<string,unknown>;
    if(o.error||o.success===false||o.status==='error')fail('remote','Query reported a failure.');
    for(const name of ['total','count','offset','limit'])if(o[name]!==undefined&&(!Number.isSafeInteger(o[name])||Number(o[name])<0))
      fail('partial','Query returned inconsistent pagination metadata.');
  }
  return result;
}

/** Static pinned domain leaves. Callers choose typed flags, never endpoint/payload routing. */
export function queryCommands(research:(context:CommandContext)=>Research):CommandDefinition[] {
  const groups=new Map<string,CommandDefinition[]>();
  for(const q of catalog.tools) {
    const [group,leaf,...rest]=q.command.split(' ');
    if(!group||!leaf||rest.length||q.params.some(p=>['session','target','program'].includes(p.name)))throw Error('Invalid installed query contract.');
    const children=groups.get(group)??[];groups.set(group,children);
    children.push(command(leaf,leaf.replaceAll('-',' '),async({options:o},c)=>{
      const parameters:Record<string,unknown>={};
      for(const p of q.params){const input=o[key(p.name)];if(input===undefined){if(p.required)fail('invalid',`Missing --${flag(p.name)}.`);continue;}parameters[p.name]=parsed(p,input);}
      const who=scope(o),result=await research(c).read(who,q.path,parameters);
      return {...who,value:queryResult(q.path,parameters,value(result))};
    },{permission:Permission.ReadOnly,options:[...selectedOptions,...q.params.map(option)]}));
  }
  return [...groups].map(([group,children])=>command(group,`${group} research`,children));
}
export function extendQueries(existing:readonly CommandDefinition[],queries:readonly CommandDefinition[]):CommandDefinition[] {
  const result=[...existing];
  for(const group of queries) {
    const index=result.findIndex(entry=>entry.name===group.name);
    if(index<0)result.push(group);
    else {
      const before=result[index]!;
      if(!before.children||group.children?.some(leaf=>before.children!.some(entry=>entry.name===leaf.name)))throw Error('Duplicate query command.');
      result[index]={...before,children:[...before.children,...group.children!]};
    }
  }
  return result;
}
