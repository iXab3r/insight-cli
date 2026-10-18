import {readFileSync} from 'node:fs';
import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Research,scope,number} from './research.js';
import {fail} from './model.js';
import {queryResult} from './query-results.js';
import {type Parameter,key,flag,parsed,option,selectedOptions} from './arguments.js';
import {nativeQueries,qualifyQuery,queryDescription} from './query-policy.js';


interface Query {path:string;command:string;params:Parameter[]}
const catalog=JSON.parse(readFileSync(new URL('../../references/queries.json',import.meta.url),'utf8')) as {source:string;tools:Query[]};
if(catalog.source!=='57e37a8bf388b1279cff46378f85be1554548f61'||catalog.tools.length!==74)
  throw Error('Installed query contracts differ from the pinned facade build.');
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
    children.push(command(leaf,queryDescription(q.path,leaf.replaceAll('-',' ')),async({options:o},c)=>{
      const parameters:Record<string,unknown>={};
      for(const p of q.params){const input=o[key(p.name)];if(input===undefined){if(p.required)fail('invalid',`Missing --${flag(p.name)}.`);continue;}parameters[p.name]=parsed(p,input);}
      if(q.path==='/get_functions')return research(c).inspectFunctions(scope(o),parameters,{limit:number(o.limitChars??16000,32768,1),offset:number(o.offsetChars??0,4*1024**2),total:number(o.totalChars??64000,128000,1),...(o.expectView===undefined?{}:{expectView:String(o.expectView)}),...(o.saveOwnerDirectory===undefined?{}:{saveDirectory:String(o.saveOwnerDirectory)})});
      if(nativeQueries.has(q.path)) {
        if(Number(parameters.timeout_seconds??5)>30)fail('invalid','Native query timeout must be at most 30 seconds.');
        if(Number(parameters.max_steps??10000)>100000)fail('invalid','Native emulation supports at most 100000 steps per candidate.');
        if(parameters.abi!==undefined&&!['auto','x86-cdecl','windows-x64','sysv-x64'].includes(String(parameters.abi)))
          fail('invalid','ABI must be auto, x86-cdecl, windows-x64 or sysv-x64.');
      }
      const who=scope(o),result=q.path==='/list_scripts'?
        await research(c).scripts(who,String(parameters.filter??''),Number(o.limit),Number(o.offset)):
        await research(c).read(who,q.path,parameters);
      return {...who,value:value(qualifyQuery(q.path,queryResult(q.path,parameters,value(result))))};
    },{permission:Permission.ReadOnly,options:[...selectedOptions,...q.params.map(option),...(q.path==='/get_functions'?[
      {flags:'--limit-chars <count>',description:'Per-function Unicode window, 1–32768',defaultValue:16000},
      {flags:'--offset-chars <count>',description:'Per-function Unicode offset',defaultValue:0},
      {flags:'--total-chars <count>',description:'Total returned decompiler characters, 1–128000',defaultValue:64000},
      {flags:'--expect-view <identity>',description:'Reject continuation from another observed view'},
      {flags:'--save-owner-directory <path>',description:'Save full returned native text and manifest in a NEW directory on the owner host'}]:[]),...(q.path==='/list_scripts'?
      [option({name:'limit',type:'integer',required:false,default:'50'}),option({name:'offset',type:'integer',required:false,default:'0'})]:[])]}));
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
