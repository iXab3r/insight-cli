import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Research,scope} from './research.js';
import {id,fail} from './model.js';
import {option,key,parsed,selectedOptions,type Parameter} from './arguments.js';
import {crossResult} from './cross-results.js';
import {qualifyQuery} from './query-policy.js';
const leaves:{path:string;group:string;name:string;params:Parameter[]}[]=[
  {path:'/compare_programs_documentation',group:'documentation',name:'compare',params:[]},
  {path:'/diff_functions',group:'functions',name:'diff',params:[{name:'address_a',type:'string',required:true,semantic:'address'},{name:'address_b',type:'string',required:true,semantic:'address'}]},
  {path:'/find_similar_functions_fuzzy',group:'documentation',name:'find-similar-functions-fuzzy',params:[{name:'function',type:'string',required:true},
    {name:'threshold',type:'number',required:false,default:'0.7'},{name:'limit',type:'integer',required:false,default:'20'}]},
  {path:'/bulk_fuzzy_match',group:'documentation',name:'bulk-fuzzy-match',params:[{name:'threshold',type:'number',required:false,default:'0.7'},
    {name:'offset',type:'integer',required:false,default:'0'},{name:'limit',type:'integer',required:false,default:'50'},{name:'filter',type:'string',required:false,default:'',allowEmpty:true}]},
];
export function crossCommands(research:(context:CommandContext)=>Research):CommandDefinition[] {
  const groups=new Map<string,CommandDefinition[]>();
  for(const leaf of leaves) {
    const children=groups.get(leaf.group)??[];groups.set(leaf.group,children);
    children.push(command(leaf.name,'Compare two explicitly selected working contexts',async({options:o},c)=>{
      const selected=scope(o),other={session:o.otherSession===undefined?selected.session:id(o.otherSession),target:id(o.otherTarget)},parameters:Record<string,unknown>={};
      for(const p of leaf.params){const input=o[key(p.name)];if(input!==undefined)parameters[p.name]=parsed(p,input);}
      if(parameters.threshold!==undefined&&(Number(parameters.threshold)<0||Number(parameters.threshold)>1))fail('invalid','Threshold must be between 0 and 1.');
      const value=crossResult(leaf.path,parameters,await research(c).crossRead(selected,other,leaf.path,parameters));
      return {...selected,other,value:qualifyQuery(leaf.path,value)};
    },{permission:Permission.ReadOnly,options:[...selectedOptions,{flags:'--other-target <id>',description:'Second immutable target',required:true},
      {flags:'--other-session <id>',description:'Second context session (defaults to --session)'},...leaf.params.map(option)]}));
  }
  const documentation=groups.get('documentation')!;
  documentation.push(command('transfer','Copy documentation into a saved private destination; publish with explicit merge',({options:o},c)=>{
    const selected=scope(o),source={session:o.sourceSession===undefined?selected.session:id(o.sourceSession),target:id(o.sourceTarget)};
    return research(c).transfer(selected,source,Boolean(o.dryRun),o.requestId===undefined?undefined:id(o.requestId));
  },{permission:'Destructive',options:[...selectedOptions,{flags:'--source-target <id>',description:'Documentation source target',required:true},
    {flags:'--source-session <id>',description:'Source context session (defaults to --session)'},
    {flags:'--dry-run',description:'Preview transfer counts without applying documentation'},
    {flags:'--request-id <id>',description:'Retrieve the prior transfer outcome after a lost response'}]}));
  return [...groups].map(([name,children])=>command(name,`${name} across two working contexts`,children));
}
