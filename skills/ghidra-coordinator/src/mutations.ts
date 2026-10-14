import {readFileSync} from 'node:fs';
import {command,Permission,type CommandDefinition,type CommandContext} from '@eyeauras/cli-factory';
import {type Parameter,key,flag,parsed,option,selectedOptions} from './arguments.js';
import {Research,scope} from './research.js';
import {id,fail} from './model.js';
import {verifyMutation} from './mutation-effects.js';
import {mutationInputs} from './mutation-inputs.js';

interface Mutation {path:string;command:string;access:'WRITE'|'DESTRUCTIVE';params:Parameter[]}
const catalog=JSON.parse(readFileSync(new URL('../../references/mutations.json',import.meta.url),'utf8')) as {source:string;tools:Mutation[]};
if(catalog.source!=='57e37a8bf388b1279cff46378f85be1554548f61')throw Error('Installed mutation contracts differ from the pinned build.');
/** Concrete pinned edit leaves with durable intent and independent saved-state effect checks. */
export function mutationCommands(research:(context:CommandContext)=>Research):CommandDefinition[] {
  const groups=new Map<string,CommandDefinition[]>();
  for(const m of catalog.tools) {
    const [group,leaf,...rest]=m.command.split(' ');if(!group||!leaf||rest.length)throw Error('Invalid installed mutation contract.');
    const parameters=m.params.map(p=>({...p,publicName:p.name==='target'?'symbol':p.name==='no_return'?'non_returning':p.name==='json_body'?'document':p.name}));
    const options=parameters.map(p=>option({...p,name:p.publicName}));
    const children=groups.get(group)??[];groups.set(group,children);
    children.push(command(leaf,leaf.replaceAll('-',' '),({options:o},c)=>{
      const values:Record<string,unknown>={};
      for(const p of parameters){const input=o[key(p.publicName)];if(input===undefined){if(p.required)fail('invalid',`Missing --${flag(p.publicName)}.`);continue;}values[p.name]=parsed(p,input);}
      for(const name of ['decompiler_comments','disassembly_comments'])if(values[name]!==undefined) {
        const comments=values[name];if(!Array.isArray(comments))fail('invalid','Comments must be an array.');
        for(const item of comments){if(!item||typeof item!=='object'||typeof item.comment!=='string'||item.comment.length>16000||item.comment.includes('\0'))
          fail('invalid','Every comment requires an address and bounded text.');
          parsed({name:'address',type:'string',required:true,semantic:'address'},item.address);}
      }
      const selected=scope(o),request=o.requestId===undefined?undefined:id(o.requestId);
      mutationInputs(m.path,values);
      if(['/set_program_option','/remove_program_option'].includes(m.path)&&values.group==='Program Information'&&values.name==='Executable SHA256')
        fail('binding','The immutable consumed input identity cannot be rewritten as a program option.');
      return research(c).mutate(selected,m.path,values,async(_backend,response)=>response,request,
        (backend,snapshot,response)=>verifyMutation(backend,snapshot,m.path,values,response));
    },{permission:m.access==='DESTRUCTIVE'||['/recreate_struct','/resize_struct','/clone_data_type','/set_global'].includes(m.path)?'Destructive':Permission.Update,
      options:[...selectedOptions,...options,{flags:'--request-id <id>',description:'Retrieve this changing intent after a lost response'}]}));
  }
  return [...groups].map(([name,children])=>command(name,`${name} changes`,children));
}
