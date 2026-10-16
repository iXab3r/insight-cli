import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {sdkOperations} from './sdk-contracts.js';
import {option,key,parsed,selectedOptions} from './arguments.js';
import {Research,scope,address,number} from './research.js';
import {id,fail,object,text} from './model.js';
import {verifyMutation} from './mutation-effects.js';
import {resolve} from 'node:path';

export function sdkInputs(operation:string,p:Record<string,unknown>) {
  if(['type-structure','type-layout','type-settings'].includes(operation)&&! /^\/(?:[^/\0]+\/)*[^/\0]+$/.test(String(p.path)))fail('invalid','Types require an absolute native type path.');
  for(const name of ['packing','alignment'])if(p[name]!==undefined){const n=number(Number(p[name])+1,65)-1;if(n>0&&(n&(n-1))!==0)fail('invalid','Packing/alignment must be -1, zero or a power of two through 64.');}
  if(p.types!==undefined&&(!Array.isArray(p.types)||!p.types.length||p.types.length>256||p.types.some(v=>typeof v!=='string'||!v.startsWith('/'))))fail('invalid','Select 1–256 explicit type paths.');
  if(operation==='type-structure'&&(!Array.isArray(p.fields)||!p.fields.length||p.fields.length>256))fail('invalid','A structure needs 1–256 field objects.');
  if(operation==='type-structure'){
    const names=new Set<string>();for(const item of p.fields as unknown[]){const field=object(item),name=text(field.name,512);text(field.type,512);
      if(names.has(name)||Object.keys(field).some(key=>!['name','type','comment','offset','bit_size','bit_offset','byte_width'].includes(key)))fail('invalid','Fields require unique names and known layout properties.');names.add(name);
      if(field.comment!==undefined&&(typeof field.comment!=='string'||field.comment.length>4096||field.comment.includes('\0')))fail('invalid','Field comment exceeds its text bound.');
      for(const [key,max,min]of [['offset',1048576,0],['bit_size',512,1],['bit_offset',511,0],['byte_width',64,1]] as const)if(field[key]!==undefined){
        if(typeof field[key]!=='number')fail('invalid','Field numeric values must be exact JSON integers.');number(field[key],max,min);}
      if(field.offset!==undefined&&Number(p.packing??0)>=0)fail('invalid','Explicit field offsets require disabled packing (-1).');
      if((field.bit_offset!==undefined||field.byte_width!==undefined)&&(field.bit_size===undefined||field.offset===undefined))fail('invalid','Explicit bit placement requires a bitfield and byte offset.');
    }
  }
  if(operation==='type-settings')for(const value of Object.values(object(p.settings))){
    if(value!==null&&(!['string','number','boolean'].includes(typeof value)||typeof value==='number'&&!Number.isSafeInteger(value)||typeof value==='string'&&(value.length>4096||value.includes('\0'))))fail('invalid','Type settings require bounded primitive values or null.');
  }
  if(operation==='decompiler-ir')for(const [key,value]of Object.entries(object(p.options??{})))if(!['eliminate_unreachable','respect_read_only','infer_constant_pointers','split_structures','split_arrays'].includes(key)||typeof value!=='boolean')fail('invalid','Decompiler options require known Boolean properties.');
  if(operation==='changes'){
    const categories=p.categories;if(!Array.isArray(categories)||!categories.length||categories.length>8||new Set(categories).size!==categories.length||categories.some(value=>!['bytes','code_units','comments','symbols','functions','references','context','properties'].includes(String(value))))fail('invalid','Select 1–8 distinct supported diff categories.');
  }
  for(const name of ['expect_hex','bytes_hex'])if(p[name]!==undefined&&
    (typeof p[name]!=='string'||! /^(?:[a-fA-F0-9]{2}){1,4096}$/.test(p[name] as string)))fail('invalid',name+' needs 1–4096 complete hex bytes.');
  if(operation==='patch-bytes'&&String(p.expect_hex).length!==String(p.bytes_hex).length)fail('invalid','Expected and replacement lengths must match.');
  for(const name of ['expect_sha256','second_sha256'])if(p[name]!==undefined&&! /^[a-f0-9]{64}$/.test(String(p[name])))fail('invalid','Memory preconditions require SHA256.');
  for(const name of ['expect_size','second_size'])if(p[name]!==undefined)p[name]=number(p[name],16777216,1);
  for(const [name,max]of [['max_ranges',1000],['max_ops',10000],['timeout_seconds',120]] as const)if(p[name]!==undefined)p[name]=number(p[name],max,1);
  if(p.instructions!==undefined&&(!Array.isArray(p.instructions)||!p.instructions.length||p.instructions.length>64||p.instructions.some(v=>typeof v!=='string'||v.length>512||/[\r\n\0]/.test(v))))fail('invalid','Assembly requires 1–64 bounded instruction strings.');
  if(operation==='library-update'&&p.new_name===undefined&&p.path===undefined)fail('invalid','Supply a library name or path update.');
  if(operation.startsWith('context-')&&p.end_address!==undefined){
    const start=address(p.address),end=address(p.end_address),parts=(v:string)=>v.split(':');
    const a=parts(start),b=parts(end);if(a.length!==b.length||a.length===2&&a[0]!==b[0])fail('invalid','Processor context needs one address space.');
    const length=BigInt('0x'+b.at(-1)!)-BigInt('0x'+a.at(-1)!)+1n;
    if(length<1n||length>65536n)fail('invalid','Processor context range is 1–65536 bytes.');
  }
  if(operation==='context-set'&&! /^(?:0x)?[a-f0-9]{1,128}$/i.test(String(p.value)))fail('invalid','Context value must be an unsigned hex integer.');
  if(operation==='context-set')p.value=String(p.value).toLowerCase();
}
export function sdkCommands(research:(c:CommandContext)=>Research):CommandDefinition[] {
  const groups=new Map<string,CommandDefinition[]>();
  for(const entry of sdkOperations){
    const children=groups.get(entry.group)??[];groups.set(entry.group,children);
    children.push(command(entry.name,entry.description,async({options:o},c)=>{
      const selected=scope(o),p:Record<string,unknown>={};
      for(const parameter of entry.params){const value=o[key(parameter.name)];if(value!==undefined)p[parameter.name]=parsed(parameter,value);else if(parameter.required)fail('invalid','Missing '+parameter.name);}
      sdkInputs(entry.operation,p);const api=research(c),operation='/sdk/'+entry.operation;
      if(entry.operation==='type-archive-import'){
        const archive=await api.workspace.artifacts.capture(resolve(c.cwd,String(p.input)),'input');if(archive.size>67108864)fail('limit','Type archive exceeds 64 MiB.');delete p.input;p.archive=archive;
      }
      if(entry.write)return api.mutate(selected,operation,p,async()=>({}),o.requestId===undefined?undefined:id(o.requestId),(backend,snapshot,response)=>verifyMutation(backend,snapshot,operation,p,response));
      const other=entry.pair?{session:o.otherSession===undefined?selected.session:id(o.otherSession),target:id(o.otherTarget)}:undefined;
      const value=object(other?await api.crossRead(selected,other,operation,p):await api.read(selected,operation,p));
      if(Buffer.byteLength(JSON.stringify(value))>1048576)fail('limit','SDK result exceeds 1 MiB; narrow the operation.');
      return {...selected,...(other?{other}:{}),value};
    },{permission:entry.write?'Destructive':Permission.ReadOnly,options:[...selectedOptions,...entry.params.map(option),
      ...(entry.pair?[{flags:'--other-target <id>',description:'Second immutable target',required:true},{flags:'--other-session <id>',description:'Second session (default selected session)'}]:[]),
      ...(entry.write?[{flags:'--request-id <id>',description:'Retrieve this changing intent without repeating it'}]:[])]}));
  }
  return [...groups].map(([name,children])=>command(name,name+' native SDK workflows',children));
}
