import {localCommand,CliError,tableView,recordView,type CommandDefinition} from '@eyeauras/cli-factory';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {packageVersion} from './package-version.js';

interface PackagedSkill {name:string;title:string;path:string;resources:Record<string,string>}
interface Capability {
 id:string;namespace:string;kind:'analytical'|'supporting';skill:string;purpose:string;
 evaluationCase:{id:string;inputFamily:string;task:string;modes:string[];requiredObservations:string[]};
 inputs:string[];tasks:string[];platforms:string[];dependencies:string[];workflowCommands:string[];limitations:string[];
}
export interface Toolbox {schema:1;skills:PackagedSkill[];tools:Capability[]}
const packageRoot=new URL('../../',import.meta.url);
export const toolbox:Toolbox=JSON.parse(readFileSync(new URL('runtime/toolbox.json',packageRoot),'utf8'));

export function locateSkill(name='insight-cli') {
 const skill=toolbox.skills.find(s=>s.name===name);
 if(!skill)throw new CliError(`Unknown skill '${name}'.`,{code:'toolbox.skillNotFound',next:[['tools','list']]});
 return {version:packageVersion,name,bundlePath:fileURLToPath(new URL('skill-bundle',packageRoot)),path:fileURLToPath(new URL(skill.path,packageRoot)),skills:toolbox.skills.map(s=>s.name)};
}
export function describeTool(id:string) {
 const tool=toolbox.tools.find(t=>t.id===id);
 if(!tool)throw new CliError(`Unknown tool '${id}'.`,{code:'toolbox.notFound',next:[['tools','list']]});
 return {...tool,status:'available',version:packageVersion,skill:locateSkill(tool.skill),
  runtime:tool.kind==='supporting'?{required:false}:{required:true,readiness:'notChecked',statusCommand:['insight-cli',tool.namespace,'status','--json']}};
}
export function skillCommand():CommandDefinition {
 return localCommand('skill [name]','Locate packaged tool instructions',({args})=>locateSkill(args.name===undefined?undefined:String(args.name)),{
  view:recordView<ReturnType<typeof locateSkill>>({fields:[{label:'Skill',value:x=>x.name},{label:'Version',value:x=>x.version},{label:'Path',value:x=>x.path}]})});
}
export function toolboxCommands():CommandDefinition[] {
 return [
  localCommand('list','List shipped research capabilities',()=>({version:packageVersion,items:toolbox.tools.map(t=>({id:t.id,namespace:t.namespace,kind:t.kind,purpose:t.purpose,inputs:t.inputs,tasks:t.tasks,platforms:t.platforms,skill:t.skill,status:'available'}))}),{
   view:tableView<Capability,{items:Capability[]}>({rows:x=>x.items,columns:[{header:'Tool',value:x=>x.id},{header:'Purpose',value:x=>x.purpose},{header:'Skill',value:x=>x.skill}]})}),
  localCommand('show <tool>','Describe tasks and tool preparation',({args})=>describeTool(String(args.tool)),{
   view:recordView<ReturnType<typeof describeTool>>({fields:[{label:'Tool',value:x=>x.id},{label:'Purpose',value:x=>x.purpose},{label:'Kind',value:x=>x.kind},{label:'Platforms',value:x=>x.platforms.join(', ')},{label:'Dependencies',value:x=>x.dependencies.join(', ')||'none'},{label:'Skill',value:x=>x.skill.path}],
    sections:[{title:()=> 'Tasks',lines:x=>x.tasks},{title:()=> 'Limitations',lines:x=>x.limitations}],next:x=>[['skill',x.skill.name]]})}),
 ];
}
