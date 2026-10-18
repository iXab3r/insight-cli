import type {CommandContext} from '@eyeauras/cli-factory';
import {mkdir,stat,rm,readdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve,sep,dirname} from 'node:path';
import {cacheArtifact,consumeArchive,extractArchive,fileSha256,archiveName} from './archives.js';
import {atomicWrite,readJson,toolRoot,withToolLock,installationStage,removeInstallation,treeFingerprint,assertUnused,withToolUse} from './store.js';
import type {ToolArtifact,ToolInstallation} from './definition.js';
import {listProcesses} from './supervisor.js';
import {digest,fail,text} from '../model.js';
export interface ToolLaunch {executable:string;arguments:string[];environment:Record<string,string>}
export interface SelectedTool extends ToolInstallation,ToolLaunch {roots:Record<string,string>;lastProbe:Record<string,unknown>;externalInputs?:Record<string,string>;noticeDigest?:string;execution?:ToolLaunch;executionFingerprint?:string}
/** Read-only verification used by an owned child after the command owner has staged a runtime. */
export async function verifyManagedInstallation(directory:string,tool:string,selected:SelectedTool){
 const root=join(toolRoot(directory,tool),'installations',selected.id);
 if(selected.schema!==1||selected.tool!==tool||selected.mode!=='managed'||selected.uninstalledAt||!/^[a-f0-9]{64}$/.test(selected.id)||selected.root!==root||!resolve(selected.executable).startsWith(resolve(root)+sep))fail('binding','Invalid managed tool installation receipt.');
 const ready=await readJson<SelectedTool>(join(root,'ready.json'));
 const binding=(v:SelectedTool)=>{const {selectedAt,uninstalledAt,...rest}=v;return rest;};
 if(!ready||digest(binding(ready))!==digest(binding(selected)))fail('binding','Managed tool receipt differs from its verified installation.');
 if(await treeFingerprint(root)!==selected.fingerprint)fail('binding','Managed tool code differs from its verified installation.');
}
export interface InstallDescriptor {
 id:string;primary:string;components:()=>Record<string,ToolArtifact>;
 launch:(roots:Record<string,string>)=>ToolLaunch;
 probe:(launch:ToolLaunch,c:CommandContext)=>Promise<Record<string,unknown>>;
 /** Reviewed nested packaging preparation inside owned staging, before probe/fingerprint. */
 prepare?:(roots:Record<string,string>,c:CommandContext)=>Promise<void>;
 /** Exceptional upstream adaptation: prepare an owned execution copy, never rewrite external software. */
 prepareExternal?:(executable:string,stage:string,c:CommandContext)=>Promise<ToolLaunch>;
 preparationId?:string;
 /** Known sibling executables/data files needed by an external tool family. */
 externalInputs?:(executable:string,c:CommandContext)=>Promise<Record<string,string>>;
 /** Full retained notices copied into owned installation storage, including external selections. */
 noticeFiles?:Record<string,string>;
}
/** Standard archive-based tools supply layout and a real probe; exceptional tools reuse the stage primitives. */
export class ToolInstaller {
 readonly directory:string;readonly root:string;readonly cache:string;
 constructor(readonly c:CommandContext,readonly descriptor:InstallDescriptor){
  this.directory=c.appArguments.AppDataDirectory;this.root=toolRoot(this.directory,descriptor.id);this.cache=join(this.directory,'runtime/cache');
 }
 private async receipt(){return readJson<SelectedTool>(join(this.root,'selection.json'));}
 async status(){
  const selected=await this.receipt();let present=false;
  if(selected&&!selected.uninstalledAt)try{present=(await stat(selected.executable)).isFile()&&(selected.mode==='external'||Boolean(await readJson(join(this.root,'installations',selected.id,'ready.json'))));}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  const stages=await readdir(join(this.root,'stages')).catch(e=>{if(e.code==='ENOENT')return [];throw e;});
  const processes=(await listProcesses(this.directory,{tool:this.descriptor.id})).filter(r=>!['exited','failed'].includes(r.state));
  return {retainedStages:stages.slice(0,100),processes,tool:this.descriptor.id,state:present?'installed':'not_ready',mode:selected?.mode??'unconfigured',installation:selected?.id,executable:selected?.executable,components:selected?.components??{},lastProbe:selected?.lastProbe,recommended:'managed'};
 }
 async download(offline=false,vendorDirect=false){
  const items=[];for(const [component,a]of Object.entries(this.descriptor.components()))items.push({component,path:await cacheArtifact(a,this.cache,this.c.fetch,this.c.signal,offline,vendorDirect),sha256:a.sha256,license:a.license,url:a.url,delivery:a.delivery??{kind:'owned-release'}});
  return {tool:this.descriptor.id,state:'downloaded',items};
 }
 async install(o:Record<string,unknown>){return withToolLock(this.directory,this.descriptor.id,async()=>{
  await assertUnused(this.directory,this.descriptor.id);
  if(o.executable&&o.archive)fail('invalid','Choose --executable or --archive.');
  const external=o.executable?resolve(this.c.cwd,text(o.executable,4096)):undefined,parts=external?{}:this.descriptor.components(),consumed:Record<string,{path:string;artifact:ToolArtifact}>={};
  for(const [id,artifact]of Object.entries(parts)){
   const key=id===this.descriptor.primary?'archive':id+'Archive',checksum=id===this.descriptor.primary?'archiveSha256':id+'ArchiveSha256';
   if(o[checksum]&&!o[key])fail('invalid','Archive checksum requires its archive path.');
   consumed[id]=o[key]?await consumeArchive(resolve(this.c.cwd,text(o[key],4096)),this.cache,artifact,o[checksum]===undefined?undefined:text(o[checksum],64),this.c.signal):{path:await cacheArtifact(artifact,this.cache,this.c.fetch,this.c.signal,Boolean(o.offline),Boolean(o.vendorDirect)),artifact};
  }
  const components=Object.fromEntries(Object.entries(consumed).map(([id,v])=>[id,v.artifact.sha256]));
  const externalDigest=external?await fileSha256(external,this.c.signal):undefined;
  const externalInputs=external&&this.descriptor.externalInputs?await this.descriptor.externalInputs(external,this.c):undefined;
  const noticeDigest=this.descriptor.noticeFiles?digest(this.descriptor.noticeFiles):undefined;
  const id=digest({tool:this.descriptor.id,schema:1,platform:process.platform,architecture:process.arch,external,externalDigest,components,...(externalInputs?{externalInputs}:{}),...(noticeDigest?{noticeDigest}:{}),...(this.descriptor.preparationId?{preparationId:this.descriptor.preparationId}:{})});
  const rootsAt=(directory:string)=>Object.fromEntries(Object.entries(consumed).map(([part,v])=>{archiveName(v.artifact.root);return [part,join(directory,part,v.artifact.root)];}));
  const selected=await installationStage<SelectedTool>(this.root,id,async(stage,installed)=>{
   for(const [part,v]of Object.entries(consumed))await extractArchive(v.path,join(stage,part),v.artifact.format,this.c.signal);
   if(!external)await this.descriptor.prepare?.(rootsAt(stage),this.c);
   const execution=external?await this.descriptor.prepareExternal?.(external,stage,this.c):undefined;
   if(execution&&!resolve(execution.executable).startsWith(resolve(stage)+sep))fail('binding','Prepared external execution must use owned staging.');
   for(const [name,body]of Object.entries(this.descriptor.noticeFiles??{})){archiveName(name);if(!name||Buffer.byteLength(body)>1024**2)fail('configuration','Invalid bundled license notice.');const destination=join(stage,name);await mkdir(dirname(destination),{recursive:true,mode:0o700});await writeFile(destination,body,{flag:'wx',mode:0o600});}
   const stageLaunch=external?{executable:external,arguments:[],environment:{}}:this.descriptor.launch(rootsAt(stage));
   const lastProbe=await this.descriptor.probe(execution??stageLaunch,this.c),launch=external?stageLaunch:this.descriptor.launch(rootsAt(installed));
   const fingerprint=external?await fileSha256(external,this.c.signal):await treeFingerprint(stage);
   if(external&&fingerprint!==externalDigest)fail('binding','External tool changed during installation.');
   if(externalInputs&&digest(await this.descriptor.externalInputs!(external!,this.c))!==digest(externalInputs))fail('binding','External tool family changed during installation.');
   const installedExecution=execution?{...execution,executable:join(installed,execution.executable.slice(stage.length+1))}:undefined;
   return {schema:1,tool:this.descriptor.id,id,mode:external?'external':'managed',root:installed,...launch,roots:rootsAt(installed),components,fingerprint,lastProbe,...(externalInputs?{externalInputs}:{}),...(noticeDigest?{noticeDigest}:{}),...(installedExecution?{execution:installedExecution,executionFingerprint:await treeFingerprint(stage)}:{}),selectedAt:new Date().toISOString()};
  },value=>this.verify(value),this.c.signal);
  await atomicWrite(join(this.root,'selection.json'),{...selected,selectedAt:new Date().toISOString()});
  return {tool:this.descriptor.id,state:'installed',mode:selected.mode,installation:id,executable:selected.executable,components,checks:selected.lastProbe};
 },this.c.signal);}
 private async verify(selected:SelectedTool){
  if(selected.schema!==1||selected.tool!==this.descriptor.id||!/^[a-f0-9]{64}$/.test(selected.id))fail('binding','Invalid tool installation receipt.');
  const root=join(this.root,'installations',selected.id);
  if(selected.root!==root||selected.mode==='managed'&&!resolve(selected.executable).startsWith(resolve(root)+sep))fail('binding','Selected tool points outside its owned installation.');
  const ready=await readJson<SelectedTool>(join(root,'ready.json'));
  const binding=(v:SelectedTool)=>{const {selectedAt,uninstalledAt,...rest}=v;return rest;};
  if(!ready||digest(binding(ready))!==digest(binding(selected)))fail('binding','Selected tool receipt differs from its verified installation.');
  if(this.descriptor.noticeFiles){if(selected.noticeDigest!==digest(this.descriptor.noticeFiles))fail('binding','Bundled license notices changed; reinstall the selected tool.');for(const [name,body]of Object.entries(this.descriptor.noticeFiles)){archiveName(name);try{if(await readFile(join(root,name),'utf8')!==body)fail('binding','Installed license notice differs from its retained text.');}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')fail('binding','Installed license notice is missing.');throw error;}}}
  if(selected.mode==='managed')await verifyManagedInstallation(this.directory,this.descriptor.id,selected);
  else if(await fileSha256(selected.executable,this.c.signal)!==selected.fingerprint)fail('binding','Selected tool code differs from its verified installation.');
  if(selected.execution&&(!resolve(selected.execution.executable).startsWith(resolve(root)+sep)||await treeFingerprint(root)!==selected.executionFingerprint))fail('binding','Owned external-tool execution copy differs from its verified installation.');
  if(selected.mode==='external'&&this.descriptor.externalInputs&&(!selected.externalInputs||digest(await this.descriptor.externalInputs(selected.executable,this.c))!==digest(selected.externalInputs)))fail('binding','External tool family differs from its verified installation.');
 }
 async use<T>(action:(selection:SelectedTool)=>Promise<T>):Promise<T>{
  const lease=await withToolUse(this.directory,this.descriptor.id,()=>this.selected(),this.c.signal);
  try{return await action({...lease.value,...lease.value.execution});}finally{lease.release();}
 }
 async selected(){
  const selected=await this.receipt();if(!selected||selected.uninstalledAt)fail('configuration','Tool is not installed; run insight-cli '+this.descriptor.id+' install.');
  await this.verify(selected);return selected;
 }
 async doctor(){return withToolLock(this.directory,this.descriptor.id,async()=>{
  const selected=await this.selected(),checks=await this.descriptor.probe(selected.execution??selected,this.c);
  await atomicWrite(join(this.root,'last-check.json'),{fingerprint:selected.fingerprint,checkedAt:new Date().toISOString(),checks});
  return {tool:this.descriptor.id,state:'verified',installation:selected.id,checks};
 },this.c.signal);}
 async uninstall(purgeCache=false){return withToolLock(this.directory,this.descriptor.id,async()=>{
  await assertUnused(this.directory,this.descriptor.id);const selected=await this.receipt();if(!selected)fail('configuration','No selected tool installation exists.');
  await removeInstallation(this.root,selected.id);
  if(purgeCache)for(const sha of Object.values(selected.components)){if(!/^[a-f0-9]{64}$/.test(sha))fail('binding','Invalid component digest.');for(const extension of ['zip','tgz'])await rm(join(this.cache,sha+'.'+extension),{force:true});}
  await atomicWrite(join(this.root,'selection.json'),{...selected,uninstalledAt:new Date().toISOString()});
  return {tool:this.descriptor.id,state:'uninstalled',externalInstallationPreserved:selected.mode==='external',researchPreserved:true,materialsPreserved:true};
 },this.c.signal);}
}
