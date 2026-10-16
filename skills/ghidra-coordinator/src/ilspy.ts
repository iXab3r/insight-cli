import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {join,resolve,dirname,relative,sep} from 'node:path';
import {mkdir,writeFile,readdir,lstat,copyFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {defineTool,lifecycleCommands,type ToolArtifact} from './tool-runtime/definition.js';
import {ToolInstaller,type ToolLaunch} from './tool-runtime/installer.js';
import {catalogArtifact} from './tool-runtime/catalog.js';
import {runTool} from './tool-runtime/run.js';
import {fail,text,id} from './model.js';
import type {Workspace} from './workspace.js';
const runtimeHashes:Record<string,string>={
 'darwin-arm64':'fdf7ef21688338ad5d1d99d7eca7f3cf2e159c86e552d3f5acd0553b11c80ca6',
 'darwin-x64':'50fd6ea005731494a6144fd4617746f4155fdc0f3682d0ba7292eac9e9bf46e3',
 'linux-x64':'958c952691d2c3f8ce21f717f4e911c02b5da0e21ead21bd576368c454b79c77',
 'win32-x64':'8db74a746baa450925d01325a2108ccf6ac39af4018047475292ae155c013d89',
};
export function ilspyComponents(platform:string=process.platform,architecture=process.arch):Record<string,ToolArtifact>{
 const hash=runtimeHashes[platform+'-'+architecture];if(!hash)fail('configuration','No pinned ILSpy runtime for this platform; use an external compatible executable.');
 return {ilspy:catalogArtifact('74c07facaf1850c78a779fc509031f756e1c0de24b1a536f3363d7ef81ce001f'),dotnet:catalogArtifact(hash)};
}
export function ilspyInstaller(c:CommandContext){
 return new ToolInstaller(c,{id:'ilspy',primary:'ilspy',components:ilspyComponents,
  launch:roots=>({executable:join(roots.dotnet!,'dotnet'+(process.platform==='win32'?'.exe':'')),arguments:[join(roots.ilspy!,'ilspycmd.dll')],environment:{DOTNET_ROOT:roots.dotnet!,DOTNET_MULTILEVEL_LOOKUP:'0',DOTNET_CLI_TELEMETRY_OPTOUT:'1',DOTNET_NOLOGO:'1'}}),
  async probe(launch:ToolLaunch,context){const result=await runTool(context,{tool:'ilspy',role:'version',executable:launch.executable,arguments:[...launch.arguments,'--disable-updatecheck','--version'],environment:launch.environment,timeoutMs:30000,maxOutputBytes:65536});
   if(!/^ilspycmd: 11\.1\.0\.9782\s*$/m.test(result.stdout))fail('configuration','The selected executable must provide ilspycmd 11.1.0.9782.');
   return {version:'11.1.0.9782',runtime:'private .NET 10.0.13 for managed installations'};},
 });
}
async function exportDirectory(stage:string,output:string){
 const files:{name:string;size:number}[]=[];let bytes=0;
 async function walk(path:string){for(const entry of await readdir(path)){const at=join(path,entry),info=await lstat(at);
  if(info.isSymbolicLink()||!info.isFile()&&!info.isDirectory())fail('binding','Tool output contains an unsupported link or special file.');
  if(files.length>100000||(bytes+=info.isFile()?info.size:0)>256*1024**2)fail('limit','ILSpy export exceeds its 100000-file/256-MiB bound.');
  if(info.isDirectory())await walk(at);else files.push({name:relative(stage,at),size:info.size});
 }}await walk(stage);await mkdir(output,{mode:0o700});
 for(const file of files){const destination=join(output,file.name);await mkdir(dirname(destination),{recursive:true,mode:0o700});await copyFile(join(stage,file.name),destination,constants.COPYFILE_EXCL);}
 return {outputDirectory:output,files,bytes};
}
export function ilspyCommands(workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{
 const installer=(c:CommandContext)=>ilspyInstaller(c);
 const common=[{flags:'--target <id>',description:'Reuse an immutable research target'},{flags:'--session <id>',description:'Associate an existing research session'},
  {flags:'--output <path>',description:'Write a new ordinary file (directory for project/resource)'},
  {flags:'--timeout-seconds <seconds>',description:'Execution deadline, from 1 to 1800 seconds',defaultValue:120}];
 const run=(operation:string,options:CommandDefinition['options']=[])=>command(operation+' [input]','Static .NET '+operation,async({args,options:o},c)=>{
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');
  if(o.type&&o.member)fail('invalid','Choose --type or --member.');
  const timeout=Number(o.timeoutSeconds);if(!Number.isSafeInteger(timeout)||timeout<1||timeout>1800)fail('invalid','timeout-seconds must be from 1 to 1800.');
  const w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target)),session=o.session===undefined?undefined:w.session(id(o.session)).id,input=await w.artifacts.verify(target.input);
  const directory=operation==='project'||operation==='resource';if(directory&&!o.output)fail('invalid','This operation requires --output DIRECTORY.');
  const stage=directory?join(c.appArguments.AppDataDirectory,'runtime/exports',randomUUID()):undefined;if(stage)await mkdir(stage,{recursive:true,mode:0o700});
  const parameters:string[]=['--disable-updatecheck'];
  if(operation==='types'){const kind=o.kind===undefined?'c,i,s,d,e':text(o.kind,32);if(!/^[cisde](?:,[cisde])*$/.test(kind))fail('invalid','kind must be c,i,s,d,e selections.');parameters.push('--list',kind.replaceAll(',',''));}
  if(o.type)parameters.push('--type',text(o.type,4096));if(o.member)parameters.push('--member',text(o.member,4096));
  if(operation==='il')parameters.push('--ilcode');if(operation==='resources')parameters.push('--list-resources');
  if(operation==='resource')parameters.push('--resource',text(o.name,4096),'--outputdir',stage!);
  if(operation==='project')parameters.push('--project','--outputdir',stage!);
  if(operation==='metadata')parameters.push('--dump-table',text(o.table,128),'--json');parameters.push(input);
  return installer(c).use(async selected=>{
   const result=await runTool(c,{tool:'ilspy',role:operation,installation:selected.id,executable:selected.executable,arguments:[...selected.arguments,...parameters],environment:selected.environment,timeoutMs:timeout*1000,target:target.id,session});
   const base={state:'completed',target:target.id,inputSha256:target.binarySha256,session,process:result.process,elapsedMs:result.elapsedMs,diagnostics:result.diagnostics,truncated:result.truncated};
   if(stage){const output=resolve(c.cwd,text(o.output,4096));if(output===stage||output.startsWith(stage+sep)||stage.startsWith(output+sep))fail('invalid','Output directory must be outside tool staging.');return {...base,...await exportDirectory(stage,output)};}
   if(o.output){const output=resolve(c.cwd,text(o.output,4096));await writeFile(output,result.stdout,{flag:'wx',mode:0o600});return {...base,output,bytes:Buffer.byteLength(result.stdout)};}
   return {...base,content:result.stdout};
  });
 },{permission:Permission.Update,options:[...common,...options]});
 const type={flags:'--type <name>',description:'Fully qualified type name'},member={flags:'--member <id>',description:'XML member ID or metadata token'};
 const definition=defineTool({id:'ilspy',description:'Static .NET decompilation with a private runtime',components:[{id:'ilspy',version:'11.1.0.9782',artifacts:[],dependencies:['dotnet']},{id:'dotnet',version:'10.0.13',artifacts:[]}],
  lifecycle:{download:(o,c)=>installer(c).download(Boolean(o.offline)),install:(o,c)=>installer(c).install(o),uninstall:(o,c)=>installer(c).uninstall(Boolean(o.purgeCache)),doctor:(_o,c)=>installer(c).doctor(),status:(_o,c)=>installer(c).status()},
  installOptions:[{flags:'--archive <path>',description:'Pinned ILSpy NuGet/zip archive'},{flags:'--archive-sha256 <sha256>',description:'Expected ILSpy archive SHA256'},{flags:'--dotnet-archive <path>',description:'Private .NET runtime tar.gz/zip'},{flags:'--dotnet-archive-sha256 <sha256>',description:'Expected .NET archive SHA256'},{flags:'--executable <path>',description:'External compatible ilspycmd executable; never removed'},{flags:'--offline',description:'Use only supplied archives and verified cache'}],
 });
 return [command('ilspy',definition.description,[...lifecycleCommands(definition),run('types',[{flags:'--kind <kinds>',description:'Comma-separated c,i,s,d,e'}]),run('decompile',[type,member]),run('il',[type]),run('resources'),run('resource',[{flags:'--name <name>',description:'Resource name',required:true}]),run('project'),run('metadata',[{flags:'--table <name>',description:'Metadata table name or number',required:true}])])];
}
