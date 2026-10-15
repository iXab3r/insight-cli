import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {mkdir,readdir,lstat,readFile,open,rename,copyFile,realpath,chmod} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {Workspace,type Scope} from './workspace.js';
import {Research,scope,address,number,type ResearchBackend} from './research.js';
import {object,fail,text,id,stable} from './model.js';
import type {Artifact} from './artifacts.js';
import {parseDomainJson} from './json.js';
import {selectedOptions} from './arguments.js';
import {randomUUID} from 'node:crypto';

interface ExportFile {name:string;artifact:Artifact}
async function persist(path:string,value:unknown){const temp=path+'.new-'+randomUUID(),file=await open(temp,'wx',0o600);try{await file.writeFile(stable(value));await file.sync();}finally{await file.close();}await rename(temp,path);if(process.platform!=='win32'){const directory=await open(dirname(path),'r');try{await directory.sync();}finally{await directory.close();}}}
/** Native SDK file effects have retained input/output bytes and never repeat an uncertain call. */
export class SdkFiles {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>){}
  async loaders(input:string){const artifact=await this.workspace.artifacts.capture(input,'input'),backend=await this.backend();
    if(!backend.sdkFile)fail('configuration','Native SDK file workflows are unavailable.');
    return {inputSha256:artifact.sha256,...await backend.sdkFile('loaders',{input:await this.workspace.artifacts.verify(artifact)})};
  }
  async exporters(selected:Scope){return this.research.ordered(selected,async()=>{
    const backend=await this.backend();if(!backend.sdkFile)fail('configuration','Native SDK file workflows are unavailable.');await backend.open(selected);
    const snapshot=await backend.saved(selected);return {...selected,value:await backend.sdkFile('exporters',{snapshot:await this.workspace.artifacts.verify(snapshot)})};
  });}
  private async copy(files:ExportFile[],directory:string,recovery=false){
    try{await mkdir(directory,{mode:0o700});}catch(error){if(!recovery||(error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
    if(await realpath(directory)!==resolve(directory)||(await lstat(directory)).isSymbolicLink())fail('binding','Export destination is not the requested ordinary directory.');
    for(const file of files){if(!/^[a-zA-Z0-9_.-]{1,160}$/.test(file.name)||file.name==='.'||file.name==='..')fail('binding','Exporter produced an unsupported output filename.');
      const source=await this.workspace.artifacts.verify(file.artifact),output=join(directory,file.name);
      try{await copyFile(source,output,constants.COPYFILE_EXCL);}catch(error){if(!recovery||(error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
      if((await this.workspace.artifacts.capture(output,'input')).id!==file.artifact.id)fail('partial','Exported file bytes differ from retained native output.');
      // Artifact copies retain their read-only mode. The owned user output needs a writable
      // descriptor for FlushFileBuffers on Windows; verify existing recovery bytes first.
      await chmod(output,0o600);const handle=await open(output,'r+');try{await handle.sync();}finally{await handle.close();}
    }
    if(process.platform!=='win32')for(const path of [directory,dirname(directory)]){const handle=await open(path,'r');try{await handle.sync();}finally{await handle.close();}}
  }
  private async completedOutput(stage:string,request:string,operation:string){
    const marker=object(JSON.parse(await readFile(join(stage,'native-result.json'),'utf8')));
    if(marker.request!==request||marker.operation!==operation||object(marker.value).state!=='exported'||!Array.isArray(marker.files)||!marker.files.length||marker.files.length>64)fail('binding','Native file completion receipt differs from the retained request.');
    const files:ExportFile[]=[];
    for(const item of marker.files){const row=object(item),name=text(row.name,160);if(!/^[a-zA-Z0-9_.-]+$/.test(name)||name==='.'||name==='..')fail('binding','Native output name is not a simple owned file.');
      const path=join(stage,'outputs',name);if(!(await lstat(path)).isFile()||(await lstat(path)).isSymbolicLink())fail('binding','Native output is not a regular owned file.');
      const artifact=await this.workspace.artifacts.capture(path,'input');if(artifact.sha256!==row.sha256||artifact.size!==row.size)fail('partial','Native output changed after its completion receipt.');files.push({name,artifact});
    }
    return {files,value:marker.value};
  }
  async databaseQuery(selected:Scope,operation:'fid-query'|'bsim-query',database:string,p:Record<string,unknown>){
    const artifact=await this.workspace.artifacts.capture(database,'input');if(artifact.size>268435456)fail('limit','Function database exceeds 256 MiB.');
    return this.research.ordered(selected,async()=>{const backend=await this.backend();if(!backend.sdkFile)fail('configuration','Native function databases are unavailable.');await backend.open(selected);
      const snapshot=await backend.saved(selected),value=await backend.sdkFile(operation,{...p,database:await this.workspace.artifacts.verify(artifact),snapshot:await this.workspace.artifacts.verify(snapshot)});
      return {...selected,databaseSha256:artifact.sha256,sourceSnapshotSha256:snapshot.sha256,value};
    });
  }
  async export(selected:Scope,operation:'export'|'archive-export'|'fid-build'|'bsim-build',parameters:Record<string,unknown>,directory:string,callerId?:string){
    const reserved=this.workspace.reserveRequest(selected,'ghidra.sdk-file.'+operation,{...parameters,outputDirectory:directory},callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id),stage=join(this.workspace.directory,'sdk-exports',request.id),receiptPath=join(stage,'receipt.json');
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        let saved;try{saved=object(JSON.parse(await readFile(receiptPath,'utf8')));}catch{
          let completed;try{completed=await this.completedOutput(stage,request.id,operation);}catch{fail('unknown','Native export has no verified completed receipt; the original call is not repeated.');}
          saved={request:request.id,operation,...completed};await persist(receiptPath,saved);
        }
        if(saved.request!==request.id||saved.operation!==operation||!Array.isArray(saved.files))fail('binding','Native export receipt differs from the retained intent.');
        const files=saved.files as ExportFile[];await this.copy(files,directory,true);const current=this.workspace.context(selected);
        const result={...selected,state:'exported',outputDirectory:directory,files:files.map(file=>({name:file.name,sha256:file.artifact.sha256,size:file.artifact.size})),value:saved.value};
        this.workspace.completeSavedRequest(selected,request.id,current.generation,{},result);return result;
      }
      try{await lstat(directory);fail('exists','Export directory already exists; choose a new directory.');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
      const backend=await this.backend();if(!backend.sdkFile)fail('configuration','Native SDK file workflows are unavailable.');await backend.open(selected);
      const snapshot=await backend.saved(selected),current=this.workspace.context(selected);
      await mkdir(stage,{recursive:true,mode:0o700});const outputs=join(stage,'outputs');await mkdir(outputs,{recursive:true,mode:0o700});
      if(await realpath(outputs)!==resolve(outputs)||(await lstat(outputs)).isSymbolicLink()||(await readdir(outputs)).length)fail('binding','Accepted file preparation must retain an empty owned output directory.');
      this.workspace.startRequest(request.id,{kind:'sdk-file',operation,snapshot,generation:current.generation});
      try{
        const filename=operation==='archive-export'?'types.gdt':operation==='fid-build'?'database.fidb':operation==='bsim-build'?'database.mv.db':'program.out';
        const value=await backend.sdkFile(operation,{...parameters,request_id:request.id,receipt:join(stage,'native-result.json'),snapshot:await this.workspace.artifacts.verify(snapshot),output:join(outputs,filename)});
        if(value.state!=='exported')fail('partial','Native exporter did not establish a completed output.');
        const completed=await this.completedOutput(stage,request.id,operation),files=completed.files;
        if(stable(completed.value)!==stable(value))fail('partial','Native file reply differs from its durable receipt.');
        await persist(receiptPath,{request:request.id,operation,files,value});await this.copy(files,directory);
        const result={...selected,state:'exported',outputDirectory:directory,files:files.map(file=>({name:file.name,sha256:file.artifact.sha256,size:file.artifact.size})),value};
        this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot},result);return result;
      }catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown'});throw error;}
    });
  }
}
function json(value:unknown){return parseDomainJson(text(value,16000));}
export function sdkFileCommands(service:(c:CommandContext)=>SdkFiles):CommandDefinition[]{
  const outputs=[...selectedOptions,{flags:'--output-directory <directory>',description:'New output directory including all exporter companion files',required:true},
    {flags:'--request-id <id>',description:'Retrieve retained export bytes without repeating native export'}];
  const databases:CommandDefinition[]=[];
  for(const kind of ['fid','bsim'] as const){
    databases.push(command('build-'+kind,'Build a genuine native '+kind+' database from the saved private snapshot',({options:o},c)=>service(c).export(scope(o),kind+'-build' as 'fid-build'|'bsim-build',
      {library:text(o.library,512),...(kind==='fid'?{version:text(o.libraryVersion,128)}:{})},resolve(c.cwd,text(o.outputDirectory,4096)),o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[...outputs,{flags:'--library <name>',description:'Native library/database name',required:true},...(kind==='fid'?[{flags:'--library-version <version>',description:'Native library version',required:true}]:[])]}));
    databases.push(command(kind+'-query','Query one explicitly consumed native '+kind+' database with provenance and no-match semantics',({options:o},c)=>{
      const p:Record<string,unknown>={limit:number(o.limit,1000,1)};if(o.function!==undefined)p.function=address(o.function);
      if(kind==='fid'){const threshold=Number(o.threshold);if(!Number.isFinite(threshold)||threshold<0||threshold>100000)fail('invalid','FID threshold must be 0–100000 native code units.');p.threshold=threshold;}
      else{const similarity=Number(o.similarity),significance=Number(o.significance);if(!Number.isFinite(similarity)||similarity<0||similarity>1||!Number.isFinite(significance)||significance<0||significance>1000000)fail('invalid','Invalid native BSim similarity/significance threshold.');p.similarity=similarity;p.significance=significance;}
      return service(c).databaseQuery(scope(o),kind+'-query' as 'fid-query'|'bsim-query',resolve(c.cwd,text(o.database,4096)),p);
    },{permission:Permission.ReadOnly,options:[...selectedOptions,{flags:'--database <file>',description:'Native FID or BSim/H2 file; immutable bytes are consumed first',required:true},
      {flags:'--function <address>',description:'Exact function entry',...(kind==='bsim'?{required:true}:{})},{flags:'--limit <count>',description:'Maximum returned matches',defaultValue:20},
      ...(kind==='fid'?[{flags:'--threshold <score>',description:'Native matching code-unit threshold',defaultValue:14.6}]:[{flags:'--similarity <number>',description:'Native feature similarity 0–1',defaultValue:0.7},{flags:'--significance <number>',description:'Native feature significance',defaultValue:0}])]}));
  }
  return [command('libraries','Native FID and BSim/H2 library identity/similarity databases',databases),command('formats','Native loaders and exporters',[
    command('loaders','Read installed loader names and supported specs/options for consumed bytes',({options:o},c)=>service(c).loaders(resolve(c.cwd,text(o.input,4096))),{permission:Permission.ReadOnly,options:[{flags:'--input <file>',description:'Input file to inspect',required:true}]}),
    command('exporters','Read installed exporters and their actual options for this program',({options:o},c)=>service(c).exporters(scope(o)),{permission:Permission.ReadOnly,options:selectedOptions}),
    command('export','Export through an explicitly selected native exporter with typed options/ranges',({options:o},c)=>{
      const p:Record<string,unknown>={exporter:text(o.exporter,512),options:object(json(o.options))};if(o.ranges!==undefined){const ranges=json(o.ranges);if(!Array.isArray(ranges)||!ranges.length||ranges.length>64)fail('invalid','Export ranges require 1–64 start/end objects.');p.ranges=ranges;}
      return service(c).export(scope(o),'export',p,resolve(c.cwd,text(o.outputDirectory,4096)),o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...outputs,{flags:'--exporter <id>',description:'Explicit native exporter name/ID',required:true},{flags:'--options <json>',description:'Named primitive native options',defaultValue:'{}'},{flags:'--ranges <json>',description:'Address ranges with start/end; exporter must support restricted output'}]}),
  ]),command('types','Native type archives',[
    command('archive-export','Export 1–256 explicit type paths to a native GDT with checked layout',({options:o},c)=>{
      const types=json(o.types);if(!Array.isArray(types)||!types.length||types.length>256||types.some(v=>typeof v!=='string'||!v.startsWith('/')))fail('invalid','Types must be 1–256 absolute type paths.');
      return service(c).export(scope(o),'archive-export',{types},resolve(c.cwd,text(o.outputDirectory,4096)),o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...outputs,{flags:'--types <json>',description:'Selected native type paths',required:true}]}),
  ])];
}
