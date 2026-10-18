import {command,Permission,CliError,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {join,resolve,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import type {ToolInstaller} from './tool-runtime/installer.js';
import {dotnetLaunch} from './tool-runtime/dotnet.js';
import {runTool} from './tool-runtime/run.js';
import {atomicWrite} from './tool-runtime/store.js';
import {fileSha256} from './tool-runtime/archives.js';
import {fail,text,id} from './model.js';
import {number} from './research.js';
import type {Workspace} from './workspace.js';
const helper=fileURLToPath(new URL('../../runtime/managed/insight-heap/Insight.Heap.dll',import.meta.url));
export function managedHeapCommand(workspace:(c:CommandContext)=>Workspace,installer:(c:CommandContext)=>ToolInstaller):CommandDefinition{
 return command('query [input]','Read bounded managed heap objects, fields and stacks from one immutable dump',async({args,options:o},c)=>{
  if(process.platform!=='darwin'||process.arch!=='arm64')fail('unsupported','The structured ClrMD facade is verified for matching macOS ARM64 CoreCLR dumps. Other native DAC profiles remain unverified.');
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply one dump input or --target.');
  const view=text(o.view??'overview',16);if(!['overview','objects','object','stacks'].includes(view))fail('invalid','Use overview, objects, object or stacks.');
  const address=o.address===undefined?undefined:text(o.address,18);if((view==='object')!==Boolean(address)||address&&!/^0x[0-9a-fA-F]{1,16}$/.test(address))fail('invalid','Only object view requires a dump-scoped hexadecimal --address.');
  if(o.thread!==undefined&&view!=='stacks')fail('invalid','--thread selects an OS thread in stacks view.');
  const limit=number(o.limit??50,500,1),offset=number(o.offset??0,1000000),maxObjects=number(o.maxObjects??1000000,1000000,1),runtime=number(o.runtimeIndex??0,15);
  const w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target)),input=await w.artifacts.verify(target.input);
  if(target.input.size>4*1024**3)fail('limit','Dump input exceeds four GiB.');
  return installer(c).use(async selected=>{
   let launch;if(selected.roots.dotnet)launch=dotnetLaunch(selected.roots.dotnet,helper);else{if(!o.dotnetHost)fail('configuration','An external diagnostics selection requires an explicit compatible --dotnet-host and --dac-file.');const host=resolve(c.cwd,text(o.dotnetHost,4096));if(!['dotnet','dotnet.exe'].includes(basename(host).toLowerCase()))fail('invalid','Select a compatible .NET 10 host.');await fileSha256(host);launch={executable:host,arguments:[helper],environment:{DOTNET_ROOT:dirname(host),DOTNET_MULTILEVEL_LOOKUP:'0',DOTNET_CLI_TELEMETRY_OPTOUT:'1'}};}
   const dac=o.dacFile?resolve(c.cwd,text(o.dacFile,4096)):selected.roots.dotnet?join(selected.roots.dotnet,'shared/Microsoft.NETCore.App/10.0.13/libmscordaccore.dylib'):undefined;if(!dac)fail('configuration','Select an explicit matching native --dac-file.');
   if(basename(dac)!=='libmscordaccore.dylib')fail('invalid','Select the matching CoreCLR macOS DAC library, not a target assembly.');const dacSha256=await fileSha256(dac),directory=join(c.appArguments.AppDataDirectory,'runtime/managed-heap/queries',randomUUID()),plan=join(directory,'plan.json');
   await atomicWrite(plan,{schema:1,input,dac,view,address,type:o.type===undefined?undefined:text(o.type,4096),thread:o.thread===undefined?undefined:number(o.thread,4294967295,1),runtime,limit,offset,maxObjects});
   const result=await runTool(c,{tool:'dotnet-dump',role:'structured-query',installation:selected.id,executable:launch.executable,arguments:[...launch.arguments,plan],environment:{...launch.environment,DOTNET_EnableDiagnostics:'0'},nativeDeadline:true,timeoutMs:60000,maxOutputBytes:8*1024**2,target:target.id,metadata:{view,helperSha256:await fileSha256(helper),dacSha256}});
   let observation;try{observation=JSON.parse(result.stdout);}catch{throw new CliError('Dump query did not return complete bounded JSON.',{code:'tool.partial',result:{process:result.process,diagnostics:result.diagnostics}});}
   if(!['completed','partial'].includes(observation?.state)||typeof observation.complete!=='boolean')fail('partial','Dump query receipt was not verified.',{process:result.process,diagnostics:result.diagnostics});
   if(await fileSha256(input)!==target.binarySha256||await fileSha256(dac)!==dacSha256)fail('binding','Dump or explicit DAC changed during the query.');
   const value={...observation,target:target.id,inputSha256:target.binarySha256,dacSha256,dacSelection:o.dacFile?'explicit-local':'managed-10.0.13',process:result.process,elapsedMs:result.elapsedMs,diagnostics:result.diagnostics};
   if(o.output){const output=resolve(c.cwd,text(o.output,4096)),content=JSON.stringify(value,null,2)+'\n';await mkdir(dirname(output),{recursive:true,mode:0o700});await writeFile(output,content,{flag:'wx',mode:0o600});return {state:value.state,complete:value.complete,reason:value.reason,target:target.id,output,bytes:Buffer.byteLength(content),process:result.process,diagnostics:result.diagnostics};}
   return value;
  });
 },{permission:Permission.Update,options:[{flags:'--target <id>',description:'Reuse captured immutable dump bytes'},{flags:'--view <kind>',description:'overview, objects, object or stacks',defaultValue:'overview'},{flags:'--type <name>',description:'Exact heap type fullname; object view verifies the expected type'},{flags:'--address <hex>',description:'Object address from this exact dump'},{flags:'--thread <id>',description:'Dump-scoped OS thread ID for stacks'},{flags:'--runtime-index <index>',description:'CLR runtime index from overview',defaultValue:0},{flags:'--dac-file <file>',description:'Explicit matching trusted native CoreCLR DAC; managed default is 10.0.13'},{flags:'--dotnet-host <file>',description:'Compatible .NET 10 host for external diagnostics selection'},{flags:'--max-objects <count>',description:'Scan at most 1–1000000 objects; reaching this bound is partial',defaultValue:1000000},{flags:'--limit <count>',description:'Return 1–500 objects, fields or threads',defaultValue:50},{flags:'--offset <count>',description:'Skip matching rows',defaultValue:0},{flags:'--output <file>',description:'Save this bounded query to a new ordinary JSON file'}]});
}
