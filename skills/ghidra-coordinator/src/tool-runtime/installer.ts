import type {CommandContext} from '@eyeauras/cli-factory';
import {mkdir,stat,rm} from 'node:fs/promises';
import {join,resolve,sep} from 'node:path';
import {cacheArtifact,consumeArchive,extractArchive,fileSha256,archiveName} from './archives.js';
import {atomicWrite,readJson,toolRoot,withToolLock,installationStage,removeInstallation,treeFingerprint,assertUnused,withToolUse} from './store.js';
import type {ToolArtifact,ToolInstallation} from './definition.js';
import {digest,fail,text} from '../model.js';
export interface ToolLaunch {executable:string;arguments:string[];environment:Record<string,string>}
export interface SelectedTool extends ToolInstallation,ToolLaunch {roots:Record<string,string>;lastProbe:Record<string,unknown>}
export interface InstallDescriptor {
 id:string;primary:string;components:()=>Record<string,ToolArtifact>;
 launch:(roots:Record<string,string>)=>ToolLaunch;
 probe:(launch:ToolLaunch,c:CommandContext)=>Promise<Record<string,unknown>>;
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
  return {tool:this.descriptor.id,state:present?'installed':'not_ready',mode:selected?.mode??'unconfigured',installation:selected?.id,executable:selected?.executable,components:selected?.components??{},lastProbe:selected?.lastProbe,recommended:'managed'};
 }
 async download(offline=false){
  const items=[];for(const [component,a]of Object.entries(this.descriptor.components()))items.push({component,path:await cacheArtifact(a,this.cache,this.c.fetch,this.c.signal,offline),sha256:a.sha256,license:a.license});
  return {tool:this.descriptor.id,state:'downloaded',items};
 }
 async install(o:Record<string,unknown>){return withToolLock(this.directory,this.descriptor.id,async()=>{
  await assertUnused(this.directory,this.descriptor.id);
  if(o.executable&&o.archive)fail('invalid','Choose --executable or --archive.');
  const external=o.executable?resolve(this.c.cwd,text(o.executable,4096)):undefined,parts=external?{}:this.descriptor.components(),consumed:Record<string,{path:string;artifact:ToolArtifact}>={};
  for(const [id,artifact]of Object.entries(parts)){
   const key=id===this.descriptor.primary?'archive':id+'Archive',checksum=id===this.descriptor.primary?'archiveSha256':id+'ArchiveSha256';
   if(o[checksum]&&!o[key])fail('invalid','Archive checksum requires its archive path.');
   consumed[id]=o[key]?await consumeArchive(resolve(this.c.cwd,text(o[key],4096)),this.cache,artifact,o[checksum]===undefined?undefined:text(o[checksum],64),this.c.signal):{path:await cacheArtifact(artifact,this.cache,this.c.fetch,this.c.signal,Boolean(o.offline)),artifact};
  }
  const components=Object.fromEntries(Object.entries(consumed).map(([id,v])=>[id,v.artifact.sha256]));
  const externalDigest=external?await fileSha256(external,this.c.signal):undefined;
  const id=digest({tool:this.descriptor.id,schema:1,platform:process.platform,architecture:process.arch,external,externalDigest,components});
  const rootsAt=(directory:string)=>Object.fromEntries(Object.entries(consumed).map(([part,v])=>{archiveName(v.artifact.root);return [part,join(directory,part,v.artifact.root)];}));
  const selected=await installationStage<SelectedTool>(this.root,id,async(stage,installed)=>{
   for(const [part,v]of Object.entries(consumed))await extractArchive(v.path,join(stage,part),v.artifact.format,this.c.signal);
   const stageLaunch=external?{executable:external,arguments:[],environment:{}}:this.descriptor.launch(rootsAt(stage));
   const lastProbe=await this.descriptor.probe(stageLaunch,this.c),launch=external?stageLaunch:this.descriptor.launch(rootsAt(installed));
   const fingerprint=external?await fileSha256(external,this.c.signal):await treeFingerprint(stage);
   if(external&&fingerprint!==externalDigest)fail('binding','External tool changed during installation.');
   return {schema:1,tool:this.descriptor.id,id,mode:external?'external':'managed',root:installed,...launch,roots:rootsAt(installed),components,fingerprint,lastProbe,selectedAt:new Date().toISOString()};
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
  const actual=selected.mode==='external'?await fileSha256(selected.executable,this.c.signal):await treeFingerprint(root);
  if(actual!==selected.fingerprint)fail('binding','Selected tool code differs from its verified installation.');
 }
 async use<T>(action:(selection:SelectedTool)=>Promise<T>):Promise<T>{
  const lease=await withToolUse(this.directory,this.descriptor.id,()=>this.selected(),this.c.signal);
  try{return await action(lease.value);}finally{lease.release();}
 }
 async selected(){
  const selected=await this.receipt();if(!selected||selected.uninstalledAt)fail('configuration','Tool is not installed; run insight-cli '+this.descriptor.id+' install.');
  await this.verify(selected);return selected;
 }
 async doctor(){return withToolLock(this.directory,this.descriptor.id,async()=>{
  const selected=await this.selected(),checks=await this.descriptor.probe(selected,this.c);
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
