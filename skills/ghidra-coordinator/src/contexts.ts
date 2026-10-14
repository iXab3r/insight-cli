import type { CommandContext } from '@eyeauras/cli-factory';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, link, realpath } from 'node:fs/promises';
import { join, delimiter, sep, resolve } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { nativeHelpers, nativeInputs, type NativeInputs } from './native-inputs.js';
import { GhidraServer, type ServerBinding } from './server.js';
import { Workspace, type ResearchTarget, type Scope, type GhidraContext, type ScalarChange, type Publication } from './workspace.js';
import { type Artifact } from './artifacts.js';
import { object, fail, text, version, stable } from './model.js';
import { HttpBridge } from './transport.js';
import {scriptInventory,scriptPath} from './scripts.js';

export type ToolMode = 'headless' | 'gui';
interface ProcessBinding {
  pid: number; endpoint: string; root: string; target: string; context?: string;
  mode: ToolMode; program: string; tokenSecret: string; runtimeFingerprint: string;
  kind: 'context' | 'shared' | 'bootstrap' | 'candidate'; baseRevision?:number;viewEpoch?:number;
}
interface Running {binding: ProcessBinding; http: HttpBridge; child?: ChildProcess}
const alive = (pid: number) => {
  try { process.kill(pid,0); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; }
};
const programPath = (target: string) => '/' + target + '.bin';
async function durable(path: string, value: unknown) {
  const temporary=path+'.new-'+randomUUID(),handle=await open(temporary,'wx',0o600);
  try {await handle.writeFile(stable(value));await handle.sync();}finally{await handle.close();}
  await rename(temporary,path);
}
async function port() {
  const listener=createServer();await new Promise<void>((ok,bad)=>{listener.once('error',bad);listener.listen(0,'127.0.0.1',ok);});
  const address=listener.address();if(!address||typeof address==='string')fail('launch','Owned context port allocation failed.');
  await new Promise<void>(ok=>listener.close(()=>ok()));return address.port;
}

/** Isolated native contexts. This layer has no agent-facing instance/worker selector. */
export class GhidraContexts {
  constructor(private readonly workspace: Workspace, private readonly inputs: NativeInputs,
    private readonly c: CommandContext, private readonly running = new Map<string,Running>(),
    private readonly modelTasks = new Map<string,Promise<void>>(),
    private readonly ownedServer = new GhidraServer(workspace.directory,inputs,c),
    private readonly capacity: {slots: Set<string>; inventory?: Promise<void>} = {slots:new Set()}) {}
  fork(c: CommandContext) {return new GhidraContexts(this.workspace,this.inputs,c,this.running,this.modelTasks,this.ownedServer.fork(c),this.capacity);}
  private directory() {return join(this.workspace.directory,'ghidra-native');}
  private server() {return this.ownedServer;}
  private async prepareRoot(kind: ProcessBinding['kind'], target: string, context?: string) {
    const root=join(this.directory(),kind,context??target,randomUUID());await mkdir(root,{recursive:true,mode:0o700});return root;
  }
  private async launch(root: string, target: ResearchTarget, kind: ProcessBinding['kind'], program: string,
    mode: ToolMode, context?: string, credentials: Record<string,string> = {}): Promise<Running> {
    if((await nativeInputs(this.c.profile.values)).fingerprint!==this.inputs.fingerprint)
      fail('binding','Native runtime inputs changed; stop the owner before using a different build.');
    const endpointPort=await port(),tokenSecret='context-'+randomUUID(),token=randomBytes(32).toString('hex');
    await this.c.secrets.set(tokenSecret,token);
    const classes=await nativeHelpers(this.workspace.directory,this.inputs);
    const main=mode==='gui'?'InsightGuiMain':'InsightHeadlessMain';
    const args=mode==='gui'?[root,'view',String(endpointPort)]:['--bind','127.0.0.1','--port',String(endpointPort)];
    const log=await open(join(root,'runtime.log'),'a',0o600);
    const child=spawn(this.inputs.java,['-Xmx768m','-Djava.awt.headless='+String(mode!=='gui'),'-Dghidra.home='+this.inputs.ghidraHome,
      '-Duser.home='+root,'-Djava.io.tmpdir='+root,'-cp',classes+delimiter+this.inputs.classpath,main,...args],
      {cwd:root,detached:true,windowsHide:true,stdio:['ignore',log.fd,log.fd],
        env:{PATH:this.c.environment.PATH??process.env.PATH,HOME:root,TMPDIR:root,XDG_RUNTIME_DIR:root,
          GHIDRA_MCP_AUTH_TOKEN:token,GHIDRA_MCP_FILE_ROOT:root,GHIDRA_MCP_SHARED_PROJECT_DIR:root,
          GHIDRA_MCP_ALLOW_SCRIPTS:'1',...credentials}});
    child.on('error',()=>{});child.unref();await log.close();
    if(!child.pid)fail('launch','Owned Ghidra context could not be launched.');
    const binding: ProcessBinding={pid:child.pid,endpoint:`http://127.0.0.1:${endpointPort}`,root,target:target.id,
      ...(context?{context}:{}),kind,mode,program,tokenSecret,runtimeFingerprint:this.inputs.fingerprint};
    await durable(join(root,'process.json'),binding);
    const record={binding,http:new HttpBridge(binding.endpoint,this.c.fetch,this.c.signal,token),child};
    this.running.set(root,record);
    const deadline=Date.now()+90000;
    try {
      while(Date.now()<deadline&&child.exitCode===null&&child.signalCode===null&&!this.c.signal.aborted) {
        try {
          const info=await record.http.instance();
          if(info.pid!==binding.pid||info.tcp_port!==endpointPort)fail('binding','Context endpoint belongs to a different native process.');
          return record;
        } catch {await delay(100);}
      }
      fail('launch','Owned Ghidra context did not become ready; its stage is retained.');
    } catch(error) {
      if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
      for(let i=0;i<100&&child.exitCode===null&&child.signalCode===null;i++)await delay(50);
      this.running.delete(root);throw error;
    }
  }
  private async verified(binding: ProcessBinding, target: ResearchTarget, verifySource = true): Promise<Running> {
    const root=resolve(binding.root);
    if(!root.startsWith(resolve(this.directory())+sep)||await realpath(root)!==root||binding.target!==target.id||binding.runtimeFingerprint!==this.inputs.fingerprint)
      fail('binding','Native context receipt does not match its profile, target or runtime.');
    if(stable(JSON.parse(await readFile(join(root,'process.json'),'utf8')))!==stable(binding))
      fail('binding','Native context receipt changed.');
    const token=await this.c.secrets.require(binding.tokenSecret);
    const http=new HttpBridge(binding.endpoint,this.c.fetch,this.c.signal,token);
    const info=await http.instance();
    if(info.pid!==binding.pid||info.tcp_port!==Number(new URL(binding.endpoint).port)||
        !String(info.project_path??'').startsWith(root+sep))fail('binding','Live context PID, endpoint or project no longer matches its receipt.');
    const record={...this.running.get(root),binding,http};this.running.set(root,record);
    if(verifySource)await this.source(record,target);return record;
  }
  private async source(record: Running, target: ResearchTarget) {
    const result=object(await record.http.call('/get_program_options',{program:record.binding.program,group:'Program Information'}));
    if(!Array.isArray(result.options)||object(result.options.find(value=>object(value).name==='Executable SHA256')??{}).value!==target.binarySha256)
      fail('binding','Opened native program does not match the target input bytes.');
    return object(await record.http.call('/get_metadata',{program:record.binding.program}));
  }
  private async stopRecord(record: Running, ready = true, releaseCapacity = true) {
    const {binding,child}=record;
    const childFinished=child&&child.pid===binding.pid&&(child.exitCode!==null||child.signalCode!==null);
    if(!childFinished&&alive(binding.pid)) {
      if(ready)await this.verified(binding,this.workspace.target(binding.target),false);
      else if(!child||child.pid!==binding.pid)fail('binding','Unready process may only be stopped through its original child handle.');
      process.kill(binding.pid,'SIGTERM');
      for(let i=0;i<100&&alive(binding.pid);i++)await delay(50);
      if(alive(binding.pid))fail('busy','Owned context did not stop; its stage is retained.');
    }
    await durable(join(binding.root,'stopped.json'),{pid:binding.pid,tokenSecret:binding.tokenSecret});
    if(releaseCapacity&&binding.context)this.capacity.slots.delete(binding.context);
    this.running.delete(binding.root);
  }
  private async capture(record: Running): Promise<Artifact> {
    const result=object(await record.http.call('/save_program',{program:record.binding.program}));
    if(result.success!==true)fail('save','Private program save was not acknowledged.');
    const output=join(record.binding.root,'exports');await mkdir(output,{recursive:true,mode:0o700});
    const name='saved-'+randomUUID()+'.gzf';
    const exported=object(await record.http.call('/export_program',{program_name:record.binding.program,output_dir:output,output_name:name}));
    if(exported.success!==true)fail('save','Saved private snapshot export was not acknowledged.');
    return this.workspace.captureSnapshot(join(output,name));
  }
  private async shared(target: ResearchTarget, binding: ServerBinding): Promise<Running> {
    const root=await this.prepareRoot('shared',target.id);
    const server=this.server();
    const record=await this.launch(root,target,'shared',programPath(target.id),'headless',undefined,await server.credentials(binding,'reader'));
    try {
      await record.http.call('/server/connect');
      await record.http.call('/open_project',{path:binding.origin+'/'+binding.repository});
      const opened=object(await record.http.call('/open_program',{path:record.binding.program}));
      if(opened.read_only!==true||opened.path!==record.binding.program)fail('authorization','Shared baseline must open through verified read-only authority.');
      await this.verified(record.binding,target);return record;
    } catch(error){await this.stopRecord(record,false);throw error;}
  }
  private async initialModel(target: ResearchTarget) {
    const model=this.workspace.model(target.id);if(model.state==='ready')return;
    if(model.state==='unknown')fail('blocked','Shared model initialization requires reconciliation.');
    const server=this.server(),binding=await server.ensure(),root=await this.prepareRoot('bootstrap',target.id);
    const record=await this.launch(root,target,'bootstrap',programPath(target.id),'headless',undefined,await server.credentials(binding,'publisher'));
    try {
      const input=join(root,target.id+'.bin');await link(await this.workspace.artifacts.verify(target.input),input);
      await record.http.call('/server/connect');
      const project=object(await record.http.call('/open_project',{path:binding.origin+'/'+binding.repository}));
      if(project.shared!==true||project.repository!==binding.repository)fail('binding','Canonical target project differs from its server binding.');
      this.workspace.beginModelInitialization(target.id);
      const result=object(await record.http.call('/import_file',{file_path:input,auto_analyze:model.settings.autoAnalyze,
        ...(model.settings.language?{language:model.settings.language}:{}),...(model.settings.compilerSpec?{compiler_spec:model.settings.compilerSpec}:{})}));
      if(result.success!==true||result.path!==record.binding.program||result.reused_existing===true||
          model.settings.autoAnalyze&&result.auto_analyzed!==true)fail('unknown','Canonical target import is not a verified fresh completed analysis; retain its stage.');
      if(model.settings.imageBase)await record.http.call('/set_image_base',{program:record.binding.program,address:'0x'+model.settings.imageBase});
      const metadata=await this.source(record,target);
      if(model.settings.language&&metadata.language!==model.settings.language||model.settings.compilerSpec&&metadata.compiler!==model.settings.compilerSpec||
          model.settings.imageBase&&String(metadata.base_address).replace(/^0+(?=.)/,'')!==model.settings.imageBase)
        fail('binding','Actual imported program does not match its requested load settings.');
      const added=object(await record.http.call('/server/version_control/add',{path:record.binding.program,comment:'insight target '+target.id,keep_checked_out:false}));
      if(added.success!==true)fail('unknown','Initial target publication was not verified.');
    } finally {await this.stopRecord(record,false);}
    const reader=await this.shared(target,binding);
    try {
      const history=object(await reader.http.call('/server/version_history',{path:reader.binding.program}));
      if(history.count!==1)fail('unknown','Initial canonical target has an unexpected version history.');
      // A read-only export does not save or alter the canonical program.
      const output=join(reader.binding.root,'exports');await mkdir(output,{mode:0o700});
      const exported=object(await reader.http.call('/export_program',{program_name:reader.binding.program,output_dir:output,output_name:'base.gzf'}));
      if(exported.success!==true)fail('save','Canonical snapshot export was not acknowledged.');
      const snapshot=await this.workspace.captureSnapshot(join(output,'base.gzf'));
      this.workspace.establishModel(target.id,1,snapshot);
    } finally {await this.stopRecord(reader);}
  }
  private async model(target: ResearchTarget) {
    let task=this.modelTasks.get(target.id);
    if(!task) {
      task=this.initialModel(target).finally(()=>{if(this.modelTasks.get(target.id)===task)this.modelTasks.delete(target.id);});
      this.modelTasks.set(target.id,task);
    }
    await task;return this.workspace.model(target.id);
  }
  private async privateCopy(context: GhidraContext, snapshot: Artifact): Promise<Running> {
    if(!this.capacity.inventory)this.capacity.inventory=this.inventory();
    await this.capacity.inventory;
    const configured=this.c.profile.values.maxContexts,max=configured===undefined?4:Number(configured);
    if(!Number.isSafeInteger(max)||max<1||max>16)fail('configuration','maxContexts must be an integer from 1 to 16.');
    if(!this.capacity.slots.has(context.id)&&this.capacity.slots.size>=max)
      fail('limit','Owned context capacity is occupied; close a saved context before opening another.');
    this.capacity.slots.add(context.id);
    let record: Running|undefined;
    try {
      const target=this.workspace.target(context.target),root=await this.prepareRoot('context',target.id,context.id);
      const file=join(root,'saved.gzf');await link(await this.workspace.artifacts.verify(snapshot),file);
      record=await this.launch(root,target,'context','/program','headless',context.id);
      const project=object(await record.http.call('/create_project',{parentDir:root,name:'view'}));
      if(project.success!==true)fail('launch','Private context project creation was not acknowledged.');
      const imported=object(await record.http.call('/import_program',{gzf_path:file,target_folder:'/',target_name:'program',overwrite:false}));
      if(imported.success!==true)fail('launch','Private context snapshot import was not acknowledged.');
      const opened=object(await record.http.call('/open_program',{path:record.binding.program}));
      if(opened.path!==record.binding.program||opened.read_only===true)fail('binding','Private context did not open its writable saved view.');
      await this.verified(record.binding,target);
      record.binding.baseRevision=context.baseRevision??this.workspace.model(context.target).sharedRevision;
      record.binding.viewEpoch=context.viewEpoch??0;
      await durable(join(root,'process.json'),record.binding);
      await durable(join(this.directory(),'context',context.id,'current.json'),record.binding);return record;
    } catch(error){if(record)await this.stopRecord(record,false);else this.capacity.slots.delete(context.id);throw error;}
  }
  async open(scope: Scope, request?: string): Promise<GhidraContext> {
    const context=this.workspace.context(scope),target=this.workspace.target(scope.target);
    if(this.workspace.unresolved(scope).some(intent=>intent.id!==request))
      fail('blocked','This context retains an unresolved operation; reconcile its recorded outcome before continuing.');
    let binding: ProcessBinding|undefined;
    try {binding=JSON.parse(await readFile(join(this.directory(),'context',context.id,'current.json'),'utf8'));}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    let stopped=false;
    if(binding) {
      try {
        const receipt=object(JSON.parse(await readFile(join(binding.root,'stopped.json'),'utf8')));
        stopped=receipt.pid===binding.pid&&receipt.tokenSecret===binding.tokenSecret;
      } catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    }
    if(binding&&!stopped&&alive(binding.pid)&&((binding.viewEpoch??0)!==(context.viewEpoch??0)||
        binding.baseRevision!==context.baseRevision&&context.baseRevision!==undefined)) {
      await this.stopRecord(await this.verified(binding,target),true,false);stopped=true;
    }
    if(binding&&!stopped&&alive(binding.pid)) {
      if(binding.context!==context.id)fail('binding','Native process belongs to a different working context.');
      await this.verified(binding,target);return context;
    }
    let model=context.workingSnapshot?this.workspace.model(target.id):await this.model(target);
    if(!context.workingSnapshot) {
      // A new session begins at the actual server revision, including external publications.
      // Existing contexts keep their saved private view until an explicit refresh.
      const shared=await this.latest(target.id);
      model=this.workspace.observeShared(target.id,shared.revision,shared.snapshot);
    }
    const snapshot=context.workingSnapshot??model.sharedSnapshot;
    if(!snapshot||!model.sharedRevision)fail('binding','Canonical target has no saved base.');
    await this.privateCopy(context,snapshot);
    if(context.workingSnapshot)return this.workspace.saveContext(scope,context.generation,{state:'ready'});
    return this.workspace.saveContext(scope,context.generation,{state:'ready',baseRevision:model.sharedRevision,
      baseSnapshot:snapshot,workingSnapshot:snapshot});
  }
  private async selected(scope: Scope): Promise<Running> {
    const context=this.workspace.context(scope);
    const binding=JSON.parse(await readFile(join(this.directory(),'context',context.id,'current.json'),'utf8')) as ProcessBinding;
    if(binding.context!==context.id)fail('binding','Context process binding changed.');
    return this.verified(binding,this.workspace.target(scope.target));
  }
  async call(scope: Scope, operation: string, parameters: Record<string,unknown> = {}): Promise<unknown> {
    if(Object.hasOwn(parameters,'program'))fail('invalid','Program routing is owned by the session and target selectors.');
    if(operation==='/set_variables'&&typeof parameters.variables!=='string')parameters={...parameters,variables:JSON.stringify(parameters.variables)};
    if(operation==='/create_function_signature'&&typeof parameters.parameters!=='string')parameters={...parameters,parameters:JSON.stringify(parameters.parameters)};
    const record=await this.selected(scope);
    if(operation==='/apply_function_documentation') {
      const name='InsightApplyDocumentation_'+randomUUID().replaceAll('-','');
      const source=await readFile(new URL('../../references/native/InsightApplyDocumentation.java',import.meta.url),'utf8');
      return record.http.call('/run_script_inline',{program:record.binding.program,
        code:source.replace('class InsightApplyDocumentation ',`class ${name} `),
        args:Buffer.from(JSON.stringify(parameters.json_body),'utf8').toString('base64')});
    }
    if(operation==='/run_ghidra_script') {
      const script=String(parameters.script_name),path=await scriptPath(this.inputs.ghidraHome,record.binding.root,script);
      const value=object(await record.http.call(operation,{...parameters,script_name:path,program:record.binding.program}));
      delete value.script_path;value.script_name=script;return value;
    }
    if(operation==='/clone_data_type') {
      // The pinned handler calls clone(manager), which can return the source itself.
      // copy(manager) preserves that source while creating an independent type.
      const name='InsightCopyType_'+randomUUID().replaceAll('-','');
      const code=`import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class ${name} extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  String original=new String(java.util.Base64.getDecoder().decode(args[0]),java.nio.charset.StandardCharsets.UTF_8);
  String desired=new String(java.util.Base64.getDecoder().decode(args[1]),java.nio.charset.StandardCharsets.UTF_8);
  DataTypeManager manager=currentProgram.getDataTypeManager();DataType source=null;
  var types=manager.getAllDataTypes();while(types.hasNext()){DataType value=types.next();if(value.getName().equals(original)||value.getPathName().equals(original)){if(source!=null)throw new IllegalArgumentException("Ambiguous source type");source=value;}}
  if(source==null)throw new IllegalArgumentException("Source type not found");
  int transaction=currentProgram.startTransaction("Copy data type");boolean committed=false;
  try {DataType copied=source.copy(manager);if(copied==source)throw new IllegalStateException("Copy reused its source");copied.setName(desired);
    manager.addDataType(copied,DataTypeConflictHandler.REPLACE_HANDLER);committed=true;}
  finally {currentProgram.endTransaction(transaction,committed);}
  println("insight-copy-type:completed");
 }
}`;
      return record.http.call('/run_script_inline',{program:record.binding.program,code,
        args:[parameters.source_type,parameters.new_name].map(value=>Buffer.from(text(value,512),'utf8').toString('base64')).join(' ')});
    }
    const descriptor=await record.http.descriptor(operation);
    return record.http.call(operation,{...parameters,...(descriptor.params.some(p=>p.name==='program')?{program:record.binding.program}:{})});
  }
  async saved(scope: Scope): Promise<Artifact> {return this.capture(await this.selected(scope));}
  async scripts(scope:Scope,filter:string,limit:number,offset:number) {
    const record=await this.selected(scope);
    return scriptInventory(this.inputs.ghidraHome,record.binding.root,filter,limit,offset);
  }
  async inspect(snapshot:Artifact,parameters:Record<string,unknown>) {
    const root=join(this.directory(),'inspection',randomUUID());await mkdir(root,{recursive:true,mode:0o700});
    const request=join(root,'request.json');await durable(request,parameters);
    const result=await this.server().inspect(await this.workspace.artifacts.verify(snapshot),request);return object(result.value);
  }
  async mode(scope: Scope, mode: ToolMode): Promise<void> {
    const record=await this.selected(scope);if(record.binding.mode===mode)return;
    const context=this.workspace.context(scope),snapshot=await this.capture(record);
    this.workspace.saveContext(scope,context.generation,{workingSnapshot:snapshot});
    await this.stopRecord(record,true,false);
    if(mode==='headless'){await this.privateCopy(this.workspace.context(scope),snapshot);return;}
    const gui=await this.launch(record.binding.root,this.workspace.target(scope.target),'context',record.binding.program,'gui',context.id);
    gui.binding.baseRevision=record.binding.baseRevision;gui.binding.viewEpoch=record.binding.viewEpoch;
    await durable(join(gui.binding.root,'process.json'),gui.binding);
    await gui.http.call('/open_program',{path:gui.binding.program});await this.verified(gui.binding,this.workspace.target(scope.target));
    await durable(join(this.directory(),'context',context.id,'current.json'),gui.binding);
  }
  async close(scope: Scope) {
    const context=this.workspace.context(scope),record=await this.selected(scope),snapshot=await this.capture(record);
    this.workspace.saveContext(scope,context.generation,{state:'stopped',workingSnapshot:snapshot});await this.stopRecord(record);
  }
  async latest(targetId:string):Promise<{revision:number;snapshot:Artifact}> {
    const target=this.workspace.target(targetId),server=this.server(),binding=await server.ensure();
    const before=await server.programStatus(binding,programPath(targetId));
    if(before.checkinActive!==false)fail('blocked','Shared model has an active check-in.');
    const expected=version(before.version),record=await this.shared(target,binding);
    try {
      const opened=await server.programStatus(binding,programPath(targetId));
      if(opened.version!==expected)fail('binding','Shared model changed while opening its saved view.');
      const output=join(record.binding.root,'exports');await mkdir(output,{recursive:true,mode:0o700});
      const exported=object(await record.http.call('/export_program',{program_name:record.binding.program,output_dir:output,output_name:'shared.gzf'}));
      if(exported.success!==true)fail('save','Shared snapshot export was not acknowledged.');
      const snapshot=await this.workspace.captureSnapshot(join(output,'shared.gzf'));
      const after=await server.programStatus(binding,programPath(targetId));
      if(after.version!==expected)fail('binding','Shared model changed before its snapshot was verified.');
      return {revision:expected,snapshot};
    } finally {await this.stopRecord(record);}
  }
  async fields(snapshot:Artifact,changes:Pick<ScalarChange,'address'|'field'>[]):Promise<Record<string,{value:string|null;dependency:string;exists:boolean}>> {
    const directory=join(this.directory(),'inspection',randomUUID());await mkdir(directory,{recursive:true,mode:0o700});
    const selectors=join(directory,'fields.json');await durable(selectors,changes.map(change=>({address:change.address,field:change.field})));
    const result=await this.server().fields(await this.workspace.artifacts.verify(snapshot),selectors),values=object(result.fields);
    for(const change of changes) {
      const item=object(values[change.address+'@'+change.field]);
      if(item.value!==null&&typeof item.value!=='string'||typeof item.exists!=='boolean'||typeof item.dependency!=='string'||!/^[a-f0-9]{64}$/.test(item.dependency))
        fail('partial','Saved field inspection returned an incomplete value or dependency.');
    }
    return values as Record<string,{value:string|null;dependency:string;exists:boolean}>;
  }
  private async applyField(record:Running,change:ScalarChange) {
    const result=object(await record.http.call(change.field==='function.name'?'/rename_function':'/set_comment',change.field==='function.name'?
      {program:record.binding.program,old_name:change.address,new_name:change.local,strict_mode:'off'}:
      {program:record.binding.program,address:change.address,type:change.field.slice(8),comment:change.local??''}));
    if(result.status!=='success'&&result.success!==true)fail('partial','Candidate edit was not acknowledged.');
    if(change.field==='function.name') {
      const read=object(await record.http.call('/get_functions',{program:record.binding.program,functions:change.address,fields:'entry_point',include_call_context:false}));
      if(object(object(read.functions)[change.address]).name!==change.local)fail('partial','Candidate name readback differs.');
    } else {
      const read=object(await record.http.call('/get_comment',{program:record.binding.program,address:change.address}));
      if((read[change.field.slice(8)]||null)!==change.local)fail('partial','Candidate comment readback differs.');
    }
  }
  async candidate(targetId:string,snapshot:Artifact,changes:ScalarChange[]):Promise<Artifact> {
    const target=this.workspace.target(targetId),root=await this.prepareRoot('candidate',targetId);
    await link(await this.workspace.artifacts.verify(snapshot),join(root,'saved.gzf'));
    const record=await this.launch(root,target,'candidate','/program','headless');
    try {
      await record.http.call('/create_project',{parentDir:root,name:'view'});
      await record.http.call('/import_program',{gzf_path:join(root,'saved.gzf'),target_folder:'/',target_name:'program',overwrite:false});
      await record.http.call('/open_program',{path:record.binding.program});await this.verified(record.binding,target);
      for(const change of changes)await this.applyField(record,change);
      return await this.capture(record);
    } finally {await this.stopRecord(record,false);}
  }
  async publish(publication:Publication):Promise<{state:'published';revision:number}|{state:'conflict';applied:0}> {
    const server=this.server(),binding=await server.ensure(),target=this.workspace.target(publication.target);
    const directory=join(this.directory(),'publications',publication.id);await mkdir(directory,{recursive:true,mode:0o700});
    const result=await server.publish(binding,programPath(target.id),await this.workspace.artifacts.verify(publication.snapshot),
      publication.expectedRevision,publication.id,join(directory,'native-intent.json'),target.binarySha256);
    if(result.state==='conflict'&&result.applied===0)return {state:'conflict',applied:0};
    if(result.state!=='published'||result.version!==publication.expectedRevision+1||result.snapshotBuffersVerified!==true||result.ownedCheckoutReleased!==true)
      fail('unknown','Native publication did not establish its version and complete saved buffers.');
    const verified=await this.recover(publication);
    if(verified.state!=='verified')fail('unknown','Independent exact-version publication verification remains unresolved.');
    return {state:'published',revision:verified.revision};
  }
  async recover(publication:Publication):Promise<{state:'verified';revision:number}|{state:'unknown'}> {
    const server=this.server(),binding=await server.ensure(),target=this.workspace.target(publication.target);
    const journal=join(this.directory(),'publications',publication.id,'native-intent.json');
    const result=await server.recoverPublication(binding,programPath(target.id),await this.workspace.artifacts.verify(publication.snapshot),
      publication.expectedRevision,publication.id,journal,target.binarySha256);
    if(result.state==='verified'&&result.version===publication.expectedRevision+1&&result.snapshotBuffersVerified===true&&result.ownedCheckoutReleased===true)
      return {state:'verified',revision:version(result.version)};
    return {state:'unknown'};
  }
  async recoverModel(targetId:string):Promise<boolean> {
    if(this.workspace.activePublication(targetId))return false;
    const model=this.workspace.model(targetId);if(model.state==='ready')return true;if(model.state==='opening')return true;
    const target=this.workspace.target(targetId),server=this.server(),binding=await server.ensure();
    let status;
    try{status=await server.programStatus(binding,programPath(targetId));}catch{return false;}
    if(status.version!==1||status.checkinActive!==false||!Array.isArray(status.versions)||status.versions.length!==1||
        object(status.versions[0]).comment!=='insight target '+targetId)return false;
    const record=await this.shared(target,binding);
    try {
      const metadata=await this.source(record,target);
      if(model.settings.language&&metadata.language!==model.settings.language||model.settings.compilerSpec&&metadata.compiler!==model.settings.compilerSpec||
          model.settings.imageBase&&String(metadata.base_address).replace(/^0+(?=.)/,'')!==model.settings.imageBase)return false;
      const output=join(record.binding.root,'exports');await mkdir(output,{recursive:true,mode:0o700});
      const exported=object(await record.http.call('/export_program',{program_name:record.binding.program,output_dir:output,output_name:'recovered.gzf'}));
      if(exported.success!==true)return false;
      const snapshot=await this.workspace.captureSnapshot(join(output,'recovered.gzf'));
      const after=await server.programStatus(binding,programPath(targetId));if(after.version!==1||after.checkinActive!==false)return false;
      this.workspace.establishModel(targetId,1,snapshot);return true;
    }finally{await this.stopRecord(record);}
  }
  async dispose() {
    // Factory has cancelled invocation signals before resource drain. Cleanup still needs
    // bounded authenticated reads to establish ownership of previously orphaned children.
    const cleanup=this.fork({...this.c,signal:new AbortController().signal});
    let failures=0;
    try {await cleanup.inventory();}catch {failures++;}
    for(const record of [...this.running.values()]) {
      try {
        // Original child handles also permit cleanup of a failed, unready owned stage.
        await cleanup.stopRecord(record,!record.child);
      } catch {failures++;}
    }
    if(failures)fail('busy','Some owned native stages could not be stopped; their receipts and saved work are retained.');
  }
  private async inventory() {
    const directory=join(this.directory(),'context');
    let entries;
    try {entries=await readdir(directory,{withFileTypes:true});}
    catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
    for(const entry of entries) {
      if(!entry.isDirectory())continue;
      let binding: ProcessBinding;
      try {binding=JSON.parse(await readFile(join(directory,entry.name,'current.json'),'utf8'));}
      catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')continue;throw error;}
      if(binding.context!==entry.name||binding.kind!=='context')fail('binding','Persisted context inventory has an inconsistent receipt.');
      let stopped=false;
      try {
        const receipt=object(JSON.parse(await readFile(join(binding.root,'stopped.json'),'utf8')));
        stopped=receipt.pid===binding.pid&&receipt.tokenSecret===binding.tokenSecret;
      }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
      if(!stopped&&alive(binding.pid)) {
        // A replacement owner must also release contexts it has not read yet.
        // PID existence alone grants no authority: authenticate the complete receipt.
        await this.verified(binding,this.workspace.target(binding.target),false);
        this.capacity.slots.add(entry.name);
      }
    }
  }
}
