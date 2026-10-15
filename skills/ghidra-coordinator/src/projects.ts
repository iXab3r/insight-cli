import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {constants} from 'node:fs';
import {mkdir,lstat,realpath,readFile,open,rename,readdir,copyFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {randomUUID} from 'node:crypto';
import {Workspace,type AdministrationRequest} from './workspace.js';
import {Research,type ResearchBackend,scope,number} from './research.js';
import {id,text,object,fail,stable} from './model.js';
import {repositoryPath} from './administration.js';
import {selectedOptions} from './arguments.js';
import type {Artifact} from './artifacts.js';

const projectName=(value:unknown)=>{const name=id(value);if(name.startsWith('.')||name.length>80)fail('invalid','Project name requires 1–80 non-hidden ID characters.');return name;};
async function persist(path:string,value:unknown) {
  const temporary=path+'.new-'+randomUUID(),h=await open(temporary,'wx',0o600);
  try{await h.writeFile(stable(value));await h.sync();}finally{await h.close();}
  await rename(temporary,path);
  if(process.platform!=='win32'){const dir=await open(dirname(path),'r');try{await dir.sync();}finally{await dir.close();}}
}
export class Projects {
  constructor(private readonly workspace:Workspace,private readonly backend:()=>Promise<ResearchBackend>,private readonly research:Research,private readonly tasks:Map<string,Promise<unknown>>){}
  private async ordered<T>(action:()=>Promise<T>){const key='projects',previous=this.tasks.get(key),task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);this.tasks.set(key,task);
    try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}}
  private async container(){const path=join(this.workspace.directory,'ghidra-projects');await mkdir(path,{recursive:true,mode:0o700});
    if((await lstat(path)).isSymbolicLink()||await realpath(path)!==resolve(path))fail('binding','Project container moved outside the selected workspace.');return path;}
  private async owned(name:string,create=false){const root=join(await this.container(),projectName(name));
    if(create){await mkdir(root,{mode:0o700});await persist(join(root,'owner.json'),{schema:1,project:name,profile:this.workspace.profile});}
    if((await lstat(root)).isSymbolicLink()||await realpath(root)!==resolve(root))fail('binding','Project root moved outside owned storage.');
    const owner=object(JSON.parse(await readFile(join(root,'owner.json'),'utf8')));
    if(owner.schema!==1||owner.project!==name||owner.profile!==this.workspace.profile)fail('binding','Project ownership receipt differs.');return root;}
  private result(op:string,name:string,p:Record<string,unknown>,raw:unknown){const value=object(raw);
    if(value.project!==name)fail('binding','Native operation returned another project.');
    const states:Record<string,string>={create:'ready',restore:'ready',open:'ready',close:'closed',info:'ready',create_folder:'created',move_file:'moved',move_folder:'moved',delete_file:'deleted',delete:'deleted',import:'imported',archive:'archived'};
    if(op==='files'){
      if(value.path!==p.path||value.offset!==p.offset||value.limit!==p.limit||!Number.isSafeInteger(value.total)||Number(value.total)<0||!Array.isArray(value.items)||value.items.length>Number(p.limit))fail('partial','Project listing omitted its selected page.');
      for(const raw of value.items){const row=object(raw);for(const field of ['name','path','type'])if(typeof row[field]!=='string'||!row[field])fail('partial','Project file identity is incomplete.');repositoryPath(row.path);}
      return {...value,truncated:Number(p.offset)+value.items.length<Number(value.total)};
    }
    if(value.state!==states[op])fail('partial','Project operation did not establish its expected state.');
    if(['create_folder','delete_file'].includes(op)&&value.path!==p.path)fail('binding','Project operation selected another path.');
    if(['move_file','move_folder'].includes(op)){
      const expected=(p.destination==='/'?'':p.destination)+'/'+String(p.path).split('/').at(-1);
      if(value.path!==expected)fail('binding','Moved item destination differs.');
    }
    if(op==='import'&&object(value.file).path!==p.path)fail('binding','Imported file destination differs.');
    if(op==='archive'&&(!Number.isSafeInteger(value.size)||Number(value.size)<1))fail('partial','Archive output is empty.');return value;
  }
  private async native(op:string,name:string,p:Record<string,unknown>,create=false){const root=await this.owned(name,create),backend=await this.backend();
    if(!backend.project)fail('configuration','Selected backend lacks project file operations.');
    return this.result(op,name,p,await backend.project(op,{request_id:'read_'+randomUUID(),...p,root,project:name,profile:this.workspace.profile}));}
  async list(){return this.ordered(async()=>{const items=[];for(const name of (await readdir(await this.container())).sort()){
    const root=await this.owned(name);try{if((await lstat(join(root,'project.gpr'))).isFile())items.push({project:name});}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}}
    return {items,count:items.length};});}
  async read(op:string,name:string,p:Record<string,unknown>){return this.ordered(async()=>{const value=await this.native(op,name,p);
    return op==='info'?{...value,unresolvedRequests:this.workspace.unresolvedProject(name).map(request=>({operation:request.operation,state:request.state,...(request.callerId?{requestId:request.callerId}:{})}))}:value;});}
  private async recovered(request:AdministrationRequest,op:string,name:string,p:Record<string,unknown>){
    const original=object(object(request.intent).parameters),expected:Record<string,unknown>={...original,request_id:request.id};
    if(op==='import'||op==='restore')expected.input=await this.workspace.artifacts.verify(original.input as Artifact);
    if(op==='archive')expected.output=join(this.workspace.directory,'project-archives',request.id,'project.gar');
    const backend=await this.backend(),root=await this.owned(name),outcome=await backend.projectOutcome?.(request.id,{...expected,project:name,root,profile:this.workspace.profile,operation:op});
    if(!outcome)return;
    let value=this.result(op,name,p,outcome);
    if(op==='archive'){const output=join(this.workspace.directory,'project-archives',request.id,'project.gar'),artifact=await this.workspace.artifacts.capture(output,'input');
      await this.exportArtifact(artifact,text(p.output,4096),true);value={...value,output:p.output,sha256:artifact.sha256};}
    this.workspace.administrationState(request.id,'applied',value);return value;
  }
  async change(op:string,name:string,p:Record<string,unknown>,callerId?:string){
    name=projectName(name);
    let input:Artifact|undefined;
    if(op==='import'||op==='restore')input=await this.workspace.artifacts.capture(text(p.input,4096),'input');
    const intent={project:name,...p,...(input?{input}: {})},reserved=this.workspace.reserveAdministration('projects.'+op,intent,callerId);
    return this.ordered(async()=>{
      const request=this.workspace.administration(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        const value=await this.recovered(request,op,name,p);if(value)return value;
        fail('unknown','Project outcome is retained; the operation is not repeated.',request.result);
      }
      for(const earlier of this.workspace.unresolvedProject(name))if(earlier.id!==request.id&&earlier.operation.startsWith('projects.')){
        const params=object(object(earlier.intent).parameters);await this.recovered(earlier,earlier.operation.slice('projects.'.length),name,params);
      }
      if(this.workspace.unresolvedProject(name).some(item=>item.id!==request.id))
        fail('blocked','An earlier project operation is unresolved; preserve its project before continuing.');
      const creating=op==='create'||op==='restore';if(!creating)await this.owned(name);
      const nativeParameters:Record<string,unknown>={...p,request_id:request.id,...(input?{input:await this.workspace.artifacts.verify(input)}:{})};
      let output:string|undefined;
      if(op==='archive'){await this.newOutput(text(p.output,4096));const stage=join(this.workspace.directory,'project-archives',request.id);await mkdir(stage,{recursive:true,mode:0o700});output=join(stage,'project.gar');nativeParameters.output=output;}
      this.workspace.administrationState(request.id,'running');
      try{
        const value=await this.native(op,name,nativeParameters,creating);
        if(output){const artifact=await this.workspace.artifacts.capture(output,'input');await this.exportArtifact(artifact,text(p.output,4096));
          const result={...value,output:p.output,sha256:artifact.sha256};this.workspace.administrationState(request.id,'applied',result);return result;}
        this.workspace.administrationState(request.id,'applied',value);return value;
      }catch(error){this.workspace.administrationState(request.id,'unknown',{project:name,operation:op,state:'unknown'});throw error;}
    });
  }
  private async newOutput(output:string){try{await lstat(output);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}fail('exists','Output already exists; choose a new file.');}
  private async exportArtifact(artifact:Artifact,output:string,recover=false){const source=await this.workspace.artifacts.verify(artifact);
    try{await copyFile(source,output,constants.COPYFILE_EXCL);}catch(error){if(!recover||(error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
    const handle=await open(output,'r');try{await handle.sync();}finally{await handle.close();}
    const readback=await this.workspace.artifacts.capture(output,artifact.kind);if(readback.id!==artifact.id)fail('partial','Exported bytes differ from the retained snapshot.');}
  async export(selected:{session:string;target:string},output:string,callerId?:string){
    const reserved=this.workspace.reserveRequest(selected,'ghidra.program.export',{output},callerId);
    return this.research.ordered(selected,async()=>{const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        const execution=object(request.execution),snapshot=execution.snapshot as Artifact;await this.workspace.artifacts.verify(snapshot);
        const observed=await this.workspace.artifacts.capture(output,'snapshot'),current=this.workspace.context(selected);
        if(observed.id!==snapshot.id||current.generation!==execution.generation)fail('unknown','Export output cannot establish the retained outcome.');
        const result={...selected,state:'exported',output,sha256:snapshot.sha256,size:snapshot.size};
        this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot},result);return result;
      }
      await this.newOutput(output);
      const backend=await this.backend();await backend.open(selected);const snapshot=await backend.saved(selected),context=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:'export',generation:context.generation,snapshot,output});
      try{await this.exportArtifact(snapshot,output);const result={...selected,state:'exported',output,sha256:snapshot.sha256,size:snapshot.size};
        this.workspace.completeSavedRequest(selected,request.id,context.generation,{workingSnapshot:snapshot},result);return result;
      }catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',savedSnapshot:snapshot});throw error;}
    });
  }
}
const projectOption={flags:'--project <name>',description:'Select a managed project in this profile',required:true},requestOption={flags:'--request-id <id>',description:'Retrieve this outcome without repeating it'};
export function projectCommands(service:(c:CommandContext)=>Projects):CommandDefinition[]{
  const leaves:CommandDefinition[]=[command('list','List owned projects',(_,c)=>service(c).list(),{permission:Permission.ReadOnly})];
  for(const [name,op,permission] of [['create','create',Permission.Update],['open','open',Permission.Update],['close','close',Permission.Update],['delete','delete','Destructive'],['info','info',Permission.ReadOnly],
    ['files','files',Permission.ReadOnly],['create-folder','create_folder',Permission.Update],['move-file','move_file',Permission.Update],['move-folder','move_folder',Permission.Update],['delete-file','delete_file','Destructive'],['archive','archive',Permission.Update],['restore','restore',Permission.Update]] as const){
    const path=['files','create_folder','move_file','move_folder','delete_file'].includes(op),moving=op.startsWith('move_'),changing=permission!==Permission.ReadOnly;
    const options=[projectOption,...(path?[{flags:'--path <path>',description:'Absolute path inside the project',...(op==='files'?{defaultValue:'/'}:{required:true})}]:[]),
      ...(moving?[{flags:'--destination <folder>',description:'Existing destination folder',required:true}]:[]),
      ...(op==='files'?[{flags:'--limit <count>',description:'Page size 1–100',defaultValue:50},{flags:'--offset <count>',description:'Page offset',defaultValue:0}]:[]),
      ...(op==='archive'?[{flags:'--output <file>',description:'Create a new Ghidra project archive',required:true}]:[]),
      ...(op==='restore'?[{flags:'--input <file>',description:'Restore into a new owned project',required:true}]:[]),...(changing?[requestOption]:[])];
    leaves.push(command(name,'Manage project files without changing research contexts',({options:o},c)=>{const p:Record<string,unknown>={};
      if(path)p.path=repositoryPath(o.path);if(moving)p.destination=repositoryPath(o.destination);
      if(op==='files'){p.limit=number(o.limit,100,1);p.offset=number(o.offset,2147483647);}
      for(const key of ['input','output'])if(o[key]!==undefined)p[key]=resolve(c.cwd,text(o[key],4096));
      return changing?service(c).change(op,projectName(o.project),p,o.requestId===undefined?undefined:id(o.requestId)):service(c).read(op,projectName(o.project),p);
    },{permission,options}));
  }
  return [command('projects','Manage isolated Ghidra projects in the selected profile',leaves),command('program','Program files',[
    command('export','Export the selected private program to a new GZF file',({options:o},c)=>service(c).export(scope(o),resolve(c.cwd,text(o.output,4096)),o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[...selectedOptions,{flags:'--output <file>',description:'New output file; existing files are preserved',required:true},requestOption]}),
    command('import','Import a GZF into a managed project',({options:o},c)=>service(c).change('import',projectName(o.project),{input:resolve(c.cwd,text(o.input,4096)),path:repositoryPath(o.path)},o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[projectOption,{flags:'--input <file>',description:'Saved Ghidra program file',required:true},{flags:'--path <path>',description:'New file path inside the project',required:true},requestOption]}),
  ])];
}
