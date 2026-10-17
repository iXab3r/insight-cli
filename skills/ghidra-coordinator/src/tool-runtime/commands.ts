import {command,Permission,CliError,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {listProcesses,processStatus,terminateProcess,type ProcessRecord} from './supervisor.js';
import {text} from '../model.js';
const number=(value:unknown,max:number,min=0)=>{const n=Number(value);if(!Number.isSafeInteger(n)||n<min||n>max)throw new CliError('Invalid process page bound.',{code:'tool.input'});return n;};
export interface ToolProcessHooks {
 discover?:(c:CommandContext)=>Promise<void>;
 verify?:(record:ProcessRecord,c:CommandContext)=>Promise<boolean|undefined>;
 stop?:(record:ProcessRecord,c:CommandContext)=>Promise<void>;
 beforeKill?:(record:ProcessRecord,c:CommandContext)=>Promise<void>;
}
export function toolProcessCommands(hooks:Record<string,ToolProcessHooks>={},metadata:readonly CommandDefinition[]=[]):CommandDefinition[]{
 const verifier=(c:CommandContext)=>(record:ProcessRecord)=>hooks[record.tool]?.verify?.(record,c)??Promise.resolve(undefined);
 const discover=async(c:CommandContext)=>{for(const h of Object.values(hooks))await h.discover?.(c);};
 const processes:CommandDefinition={
  name:'processes',description:'List owned tool processes; inspect or stop one recorded execution',permission:Permission.ReadOnly,
  options:[{flags:'--tool <name>',description:'Filter by tool'},{flags:'--session <id>',description:'Filter by research session'},{flags:'--target <id>',description:'Filter by input target'},
   {flags:'--all',description:'Include completed and failed executions'},{flags:'--limit <count>',description:'Maximum records in this page',defaultValue:50,parse:v=>number(v,1000,1)},
   {flags:'--offset <count>',description:'Skip records before this page',defaultValue:0,parse:v=>number(v,2147483647)}],
  async run({options:o},c){
   await discover(c);let items=await listProcesses(c.appArguments.AppDataDirectory,{tool:o.tool===undefined?undefined:text(o.tool,64),session:o.session===undefined?undefined:text(o.session,128),target:o.target===undefined?undefined:text(o.target,128)},verifier(c));
   if(!o.all)items=items.filter(r=>!['exited','failed'].includes(r.state));
   const limit=number(o.limit,1000,1),offset=number(o.offset,2147483647);return {items:items.slice(offset,offset+limit),total:items.length,limit,offset,truncated:items.length>offset+limit};
  },
  children:[
   command('show <process>','Inspect a recorded execution and its diagnostic paths',async({args},c)=>{await discover(c);return processStatus(c.appArguments.AppDataDirectory,text(args.process,64),verifier(c));},{permission:Permission.ReadOnly}),
   command('stop <process>','Request tool-aware graceful shutdown of an owned process',async({args},c)=>{
    await discover(c);return terminateProcess(c.appArguments.AppDataDirectory,text(args.process,64),false,verifier(c),r=>hooks[r.tool]?.stop?.(r,c)??Promise.resolve());
   },{permission:Permission.Update}),
   command('kill <process>','Force termination of a verified owned process; preserve uncertain work',async({args},c)=>{
    await discover(c);const id=text(args.process,64),r=await processStatus(c.appArguments.AppDataDirectory,id,verifier(c));
    if(r.state==='running')await hooks[r.tool]?.beforeKill?.(r,c);return terminateProcess(c.appArguments.AppDataDirectory,id,true,verifier(c));
   },{permission:'Destructive'}),
  ],
 };
 return [command('tools','Inspect research tools and executions',[...metadata,processes])];
}
