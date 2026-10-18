import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {join,resolve,dirname} from 'node:path';
import {mkdir,lstat} from 'node:fs/promises';
import {ToolInstaller} from './tool-runtime/installer.js';
import {defineTool,lifecycleCommands} from './tool-runtime/definition.js';
import {catalogArtifact} from './tool-runtime/catalog.js';
import {runTool} from './tool-runtime/run.js';
import {fail,text,id} from './model.js';
import {number} from './research.js';
import type {Workspace} from './workspace.js';
const archiveSha='7bb52641f2e0dc9b8f5b180be4b0ab46b6d3127361a4e817938175603850c714';
export interface ArchiveEntry {path:string;directory:boolean;size:number;encrypted:boolean;attributes:string}
/** Technical listing is bounded, not a general line-escaping format. Extraction never trusts native paths. */
export function parseArchiveListing(content:string):ArchiveEntry[]{
 const entries:ArchiveEntry[]=[];
 for(const block of content.replaceAll('\r\n','\n').trim().split(/\n\n+/)){
  if(!block)continue;const fields=new Map<string,string>();
  for(const line of block.split('\n')){const at=line.indexOf(' = ');if(at<1)fail('unsupported','Archive listing contains a multiline or unsupported field.');const key=line.slice(0,at);if(fields.has(key))fail('unsupported','Archive listing contains ambiguous fields.');fields.set(key,line.slice(at+3));}
  if(['Symbolic Link','Hard Link','Reparse'].some(key=>fields.has(key)))fail('unsupported','Archive links are not supported for ordinary-file recovery.');
  const path=fields.get('Path'),size=Number(fields.get('Size'));
  if(!path||!Number.isSafeInteger(size)||size<0||!['+','-'].includes(fields.get('Folder')??''))fail('unsupported','Archive entry omitted its path, size or kind.');
  if(entries.length>=10000)fail('limit','Archive inventory exceeds 10000 entries.');
  entries.push({path,size,directory:fields.get('Folder')==='+',encrypted:fields.get('Encrypted')==='+',attributes:fields.get('Attributes')??''});
 }
 return entries;
}
export function safeArchivePath(path:string){
 if(!path||/[\\\x00-\x1f\x7f:]/.test(path)||path.startsWith('/')||path.split('/').some(p=>!p||p==='.'||p==='..')||path.length>2048)fail('invalid','Archive entry has an unsafe or unsupported output path.');return path;
}
export function sevenzipInstaller(c:CommandContext){
 return new ToolInstaller(c,{id:'sevenzip',primary:'sevenzip',components:()=>{
  if(process.platform!=='darwin'||!['arm64','x64'].includes(process.arch))fail('unsupported','Managed 7-Zip is currently provided for macOS ARM64/x64; select an external 7zz 26.04 on another host.');
  return {sevenzip:catalogArtifact(archiveSha)};
 },launch:roots=>({executable:join(roots.sevenzip!,'7zz'),arguments:[],environment:{}}),
 probe:async(launch,context)=>{const r=await runTool(context,{tool:'sevenzip',role:'version',executable:launch.executable,arguments:[...launch.arguments,'i'],environment:launch.environment,maxOutputBytes:65536,timeoutMs:30000});
  if(!/7-Zip \(z\) 26\.04 /.test(r.stdout))fail('configuration','The selected executable must provide 7zz 26.04.');return {version:'26.04'};}});
}
export function sevenzipCommands(workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{
 const definition=defineTool({id:'sevenzip',description:'Inventory, verify and recover files from containers',components:[{id:'sevenzip',version:'26.04',artifacts:[]}],lifecycle:{
  download:(o,c)=>sevenzipInstaller(c).download(Boolean(o.offline)),install:(o,c)=>sevenzipInstaller(c).install(o),uninstall:(o,c)=>sevenzipInstaller(c).uninstall(Boolean(o.purgeCache)),doctor:(_o,c)=>sevenzipInstaller(c).doctor(),status:(_o,c)=>sevenzipInstaller(c).status()}});
 const common=[{flags:'--target <id>',description:'Reuse an immutable input target'},{flags:'--timeout-seconds <seconds>',description:'Per-process deadline (1–600)',defaultValue:120}];
 const operation=(name:'list'|'test'|'extract')=>command(name+' [input]',name==='list'?'Inspect a bounded archive inventory':name==='test'?'Check container integrity without extracting':'Recover regular files into a new ordinary directory',async({args,options:o},c)=>{
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');
  const w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target));const input=await w.artifacts.verify(target.input),timeoutMs=number(o.timeoutSeconds,600,1)*1000;
  return sevenzipInstaller(c).use(async selected=>{
   const invoke=(role:string,parameters:string[],extra:Partial<Parameters<typeof runTool>[1]>={})=>runTool(c,{tool:'sevenzip',role,installation:selected.id,executable:selected.executable,arguments:[...selected.arguments,...parameters],environment:selected.environment,target:target.id,timeoutMs,...extra});
   if(name==='test'){const result=await invoke('test',['t','-bd','-y','-p','--',input]);return {state:'verified',target:target.id,inputSha256:target.binarySha256,process:result.process,elapsedMs:result.elapsedMs,diagnostics:result.diagnostics,content:result.stdout};}
   const listing=await invoke('inventory',['l','-slt','-ba','-sccUTF-8','-p','--',input]);const entries=parseArchiveListing(listing.stdout);const base={target:target.id,inputSha256:target.binarySha256,process:listing.process,diagnostics:listing.diagnostics,total:entries.length};
   if(name==='list'){const limit=number(o.limit,100,1),offset=number(o.offset,10000,0);return {...base,items:entries.slice(offset,offset+limit),limit,offset,truncated:offset+limit<entries.length};}
   const chosen=o.entry?entries.filter(e=>e.path===text(o.entry,2048)):entries;
   if(!chosen.length)fail('notFound','No matching archive entry.');if(chosen.length>512)fail('limit','Select an entry; bulk recovery is limited to 512 entries.');
   const paths=new Set<string>();let bytes=0;
   for(const entry of chosen){safeArchivePath(entry.path);const key=entry.path.normalize('NFC').toLowerCase();if(paths.has(key))fail('unsupported','Archive output paths collide.');paths.add(key);
    if(entry.encrypted)fail('unsupported','Encrypted recovery is not supported by this adapter.');
    if(entry.size>64*1024**2||(bytes+=entry.size)>256*1024**2)fail('limit','Recovery exceeds its 64-MiB per-file/256-MiB total bound.');
    if(/(?:^|\s)[bclps][rwx-]{9}/.test(entry.attributes))fail('unsupported','Only ordinary archive files and directories can be recovered.');
   }
   const output=resolve(c.cwd,text(o.output,4096));await mkdir(dirname(output),{recursive:true,mode:0o700});await mkdir(output,{mode:0o700});const files=[];
   for(const entry of chosen){const destination=join(output,entry.path);if(entry.directory){await mkdir(destination,{recursive:true,mode:0o700});continue;}
    await mkdir(dirname(destination),{recursive:true,mode:0o700});
    const result=await invoke('recover',['x','-so','-spd','-bd','-y','-p','--',input,entry.path],{maxOutputBytes:Math.max(65536,entry.size+65536),outputFile:destination});
    if((await lstat(destination)).size!==entry.size)fail('binding','Recovered file size differs from the inventory; retained partial output requires inspection.');files.push({path:entry.path,size:entry.size,process:result.process});
   }
   return {...base,state:'extracted',outputDirectory:output,files,bytes,publication:'ordinary files; no shared analysis merge'};
  });
 },{permission:Permission.Update,options:[...common,...(name==='list'?[{flags:'--limit <count>',description:'Page size (1–100)',defaultValue:50},{flags:'--offset <count>',description:'Skip entries',defaultValue:0}]:name==='extract'?[{flags:'--entry <path>',description:'Recover one exact regular entry'},{flags:'--output <directory>',description:'New output directory',required:true}]:[])]});
 return [command('sevenzip',definition.description,[...lifecycleCommands(definition),operation('list'),operation('test'),operation('extract')])];
}
