import {ghidraBudget} from './budgets.js';
import {launchProcess,terminateProcess} from './tool-runtime/supervisor.js';
import {runTool} from './tool-runtime/run.js';
import {verifyGhidraProcess} from './ghidra-processes.js';
import type { CommandContext } from '@eyeauras/cli-factory';
import {runtimeProcesses} from './runtime-manager.js';
import { type ChildProcess } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, link, realpath,copyFile,chmod,writeFile } from 'node:fs/promises';
import {constants} from 'node:fs';
import { join, delimiter, sep, resolve, dirname } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { nativeHelpers, nativeInputs,nativeJvmDirectories,nativeExtensionArguments, type NativeInputs } from './native-inputs.js';
import { GhidraServer, type ServerBinding } from './server.js';
import { Workspace, type ResearchTarget, type Scope, type GhidraContext, type ScalarChange, type Publication,type DebuggerState } from './workspace.js';
import { type Artifact } from './artifacts.js';
import { object, fail, text, version, stable } from './model.js';
import { HttpBridge } from './transport.js';
import {scriptInventory,scriptPath} from './scripts.js';
import {logicalPrograms} from './cross-results.js';
import {uiResult} from './ui-results.js';
import {fileURLToPath} from 'node:url';
import {readCallerGoal,awaitCaller} from './debugger-caller.js';
import {debuggerProgramMetadata} from './debugger-results.js';
import {nativeQueries} from './query-policy.js';
import {nativeQuery} from './native-queries.js';
import {sdkWrites} from './sdk-contracts.js';
import {initialIntent,initializeModel} from './initial-model.js';
import {managedGhidraDebugger,prepareGhidraDebugger} from './ghidra-debugger-runtime.js';
import type {SelectedTool} from './tool-runtime/installer.js';

export type ToolMode = 'headless' | 'gui';
interface ProcessBinding {
  toolProcessId?:string; pid: number; endpoint: string; root: string; target: string; context?: string; session?:string;
  mode: ToolMode; debuggerPython?:string; debuggerRuntime?:SelectedTool; program: string; tokenSecret: string; runtimeFingerprint: string;
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
  async administration(operation:string,parameters:Record<string,unknown>) {
    if(operation==='stop'){
      if(this.c.profile.values.server)fail('authorization','External server lifecycle is owned by its operator. Use server disconnect.');
      const processes=await runtimeProcesses(dirname(this.workspace.directory));if(processes.some(p=>p.kind!=='server'))fail('busy','Close active Ghidra contexts before stopping their server.');
    }
    return this.server().administration(operation,parameters);
  }
  async sdkFile(operation:string,parameters:Record<string,unknown>){return this.server().sdkFile(operation,parameters);}
  private async prepareRoot(kind: ProcessBinding['kind'], target: string, context?: string) {
    const root=join(this.directory(),kind,context??target,randomUUID());await mkdir(root,{recursive:true,mode:0o700});return root;
  }
  private async launch(root: string, target: ResearchTarget, kind: ProcessBinding['kind'], program: string,
    mode: ToolMode, context?: string, credentials: Record<string,string> = {}): Promise<Running> {
    if((await nativeInputs(this.c.profile.values,this.workspace.directory,this.c)).fingerprint!==this.inputs.fingerprint)
      fail('binding','Native runtime inputs changed; stop the owner before using a different build.');
    const endpointPort=await port(),tokenSecret='context-'+randomUUID(),token=randomBytes(32).toString('hex');
    await this.c.secrets.set(tokenSecret,token);
    const classes=await nativeHelpers(this.workspace.directory,this.inputs,this.c);
    let debuggerEnvironment:Record<string,string>={},debuggerPython:string|undefined,debuggerRuntime:SelectedTool|undefined;
    if(mode==='gui'){
      if(managedGhidraDebugger())debuggerRuntime=await prepareGhidraDebugger(this.c);
      const python=join(root,'debug-python-'+randomUUID());await mkdir(python,{mode:0o700});debuggerPython=python;
      const prepared=await runTool(this.c,{tool:'ghidra',role:'debugger-wheels',installation:this.inputs.fingerprint,executable:this.inputs.java,arguments:['-cp',classes,'InsightPythonWheels',python,...this.inputs.debuggerWheels],timeoutMs:30000,maxOutputBytes:65536});
      if(object(JSON.parse(prepared.stdout)).state!=='prepared')fail('configuration','Owned debugger Python dependencies could not be prepared.');
      debuggerEnvironment={INSIGHT_DEBUGGER_PYTHON:python,PYTHONPATH:python,PYTHONNOUSERSITE:'1',PYTHONDONTWRITEBYTECODE:'1',PYTHONPYCACHEPREFIX:join(python,'isolated-cache')};
      if(process.platform==='darwin'){
        const bin=join(root,'debug-bin-'+randomUUID());await mkdir(bin,{mode:0o700});
        const quote=(value:string)=>"'"+value.replaceAll("'","'\\''")+"'",launch=join(root,'debugger-run','current.json');
        await writeFile(join(bin,'lldb'),'#!/bin/sh\n'+
          'directory='+quote(root)+'\nif [ -f '+quote(launch)+' ]; then\n directory=$(/usr/bin/plutil -extract cwd raw -o - '+quote(launch)+') || exit 1\nfi\n'+
          'cd "$directory" || exit 1\nexec '+quote(process.execPath)+' '+quote(fileURLToPath(new URL('./debugger-supervisor.js',import.meta.url)))+' '+quote(root)+' "$@"\n',{mode:0o500});
        debuggerEnvironment.PATH=bin+delimiter+(this.c.environment.PATH??process.env.PATH??'/usr/bin:/bin');
      }
    }
    const main=mode==='gui'?'InsightGuiMain':'InsightHeadlessMain';
    const args=mode==='gui'?[root,'view',String(endpointPort)]:['--bind','127.0.0.1','--port',String(endpointPort)];
    const log=await open(join(root,'runtime.log'),'a',0o600);
    let binding!:ProcessBinding;
    const child=await launchProcess(this.c.appArguments.AppDataDirectory,{tool:'ghidra',role:mode==='gui'?'gui':kind,installation:this.inputs.fingerprint,target:target.id,session:context?this.workspace.contextById(context).session:undefined,metadata:{contextRoot:root}},this.inputs.java,['-Xmx768m','-Djava.awt.headless='+String(mode!=='gui'),'-Dghidra.home='+this.inputs.ghidraHome,
      ...nativeJvmDirectories(root),...nativeExtensionArguments(this.inputs),'-cp',classes+delimiter+this.inputs.classpath,main,...args],
      {cwd:root,detached:true,windowsHide:true,stdio:['ignore',log.fd,log.fd],
        env:{PATH:this.c.environment.PATH??process.env.PATH,HOME:root,TMPDIR:root,XDG_RUNTIME_DIR:root,
          INSIGHT_TOOL_APPDATA:this.c.appArguments.AppDataDirectory,GHIDRA_MCP_AUTH_TOKEN:token,GHIDRA_MCP_FILE_ROOT:root,GHIDRA_MCP_SHARED_PROJECT_DIR:root,
          GHIDRA_MCP_ALLOW_SCRIPTS:'1',...debuggerEnvironment,...credentials}},{signal:this.c.signal,onSpawn:async spawned=>{
        if(!spawned.pid)fail('launch','Owned context did not obtain a PID.');
        binding={toolProcessId:spawned.toolProcessId,pid:spawned.pid,endpoint:`http://127.0.0.1:${endpointPort}`,root,...(debuggerPython?{debuggerPython}:{}),...(debuggerRuntime?{debuggerRuntime}:{}),target:target.id,
          ...(context?{context,session:this.workspace.contextById(context).session}:{}),kind,mode,program,tokenSecret,runtimeFingerprint:this.inputs.fingerprint};
        await durable(join(root,'process.json'),binding);
      }});
    child.on('error',()=>{});child.unref();await log.close();
    if(!child.pid)fail('launch','Owned Ghidra context could not be launched.');
    const record={binding,http:new HttpBridge(binding.endpoint,this.c.fetch,this.c.signal,token,undefined,ghidraBudget(this.c.profile.values,'save')),child};
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
    const root=await realpath(binding.root);
    if(!root.startsWith(resolve(this.directory())+sep)||binding.target!==target.id||binding.runtimeFingerprint!==this.inputs.fingerprint)
      fail('binding','Native context receipt does not match its profile, target or runtime.');
    if(stable(JSON.parse(await readFile(join(root,'process.json'),'utf8')))!==stable(binding))
      fail('binding','Native context receipt changed.');
    const token=await this.c.secrets.require(binding.tokenSecret);
    const http=new HttpBridge(binding.endpoint,this.c.fetch,this.c.signal,token,undefined,ghidraBudget(this.c.profile.values,'save'));
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
      if(ready&&binding.mode==='gui'){
        const token=await this.c.secrets.require(binding.tokenSecret),http=new HttpBridge(binding.endpoint,this.c.fetch,new AbortController().signal,token,60000);
        await this.debuggerHelperRecord({...record,http},'Stop','INSIGHT_DEBUGGER_STOPPED');
      }
      if(binding.toolProcessId)await terminateProcess(this.c.appArguments.AppDataDirectory,binding.toolProcessId,false,r=>verifyGhidraProcess(r,this.c));
      else process.kill(binding.pid,'SIGTERM');
      for(let i=0;i<100&&alive(binding.pid);i++)await delay(50);
      if(alive(binding.pid))fail('busy','Owned context did not stop; its stage is retained.');
    }
    if(binding.mode==='gui')await this.debuggerReleased(binding);
    await durable(join(binding.root,'stopped.json'),{pid:binding.pid,tokenSecret:binding.tokenSecret});
    if(releaseCapacity&&binding.context)this.capacity.slots.delete(binding.context);
    this.running.delete(binding.root);
  }
  private async debuggerReleased(binding:ProcessBinding){
    const root=await realpath(binding.root);if(!root.startsWith(resolve(this.directory())+sep)||
      stable(JSON.parse(await readFile(join(root,'process.json'),'utf8')))!==stable(binding))fail('binding','Debugger lifetime binding moved outside its owned context.');
    const directory=join(root,'debugger-supervisors'),deadline=Date.now()+15000;
    for(;;){let names:string[];try{names=await readdir(directory);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
      let pending=false;
      for(const name of names.filter(name=>/^[a-f0-9-]{36}\.json$/.test(name))){
        const path=join(directory,name);if(await realpath(path)!==resolve(path))fail('binding','Debugger lifetime receipt moved.');
        const row=object(JSON.parse(await readFile(path,'utf8')));
        if(row.schema!==1||row.id+'.json'!==name||row.root!==binding.root||row.context!==binding.context||row.target!==binding.target)fail('binding','Debugger lifetime receipt changed.');
        if(row.guiPid!==binding.pid||row.ownerToken!==binding.tokenSecret)continue;
        if(row.state==='closed'&&row.inferiorTerminated===true)continue;
        if(row.state==='failed')fail('blocked','Owned debugger termination remains unverified; its receipt and trace are retained.');
        pending=true;
      }
      if(!pending)return;if(Date.now()>=deadline)fail('busy','Owned debugger cleanup is still pending; its context is retained.');await delay(100);
    }
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
  private async retireLegacyBootstrap(target:ResearchTarget){
    const parent=join(this.directory(),'bootstrap',target.id);
    let entries;try{entries=await readdir(parent,{withFileTypes:true});}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
    for(const entry of entries){
      if(!entry.isDirectory())continue;
      const root=join(parent,entry.name);if(await realpath(root)!==resolve(root))fail('binding','Legacy initial-import stage moved outside owned storage.');
      const binding=JSON.parse(await readFile(join(root,'process.json'),'utf8')) as ProcessBinding;
      if(await realpath(binding.root)!==root||binding.target!==target.id||binding.kind!=='bootstrap'||binding.program!==programPath(target.id))fail('binding','Legacy bootstrap receipt changed.');
      let stopped=false;
      try{const receipt=object(JSON.parse(await readFile(join(root,'stopped.json'),'utf8')));stopped=receipt.pid===binding.pid&&receipt.tokenSecret===binding.tokenSecret;}
      catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
      if(stopped)continue;
      if(alive(binding.pid))await this.stopRecord(await this.verified(binding,target,false));
    }
  }
  private async initialModel(target: ResearchTarget) {
    const model=this.workspace.model(target.id);if(model.state==='ready')return;
    const server=this.server(),binding=await server.ensure();
    if(!await initialIntent(this.workspace,target.id)){
      // Old builds imported into an unversioned local shared-project stage. First stop
      // its authenticated worker; a failed probe is never treated as authoritative absence.
      if(model.state==='unknown')await this.retireLegacyBootstrap(target);
      const status=await server.programStatus(binding,programPath(target.id));
      if(status.state!=='absent')fail('unknown','Canonical initial target already exists or is reserved; retain its original stage for independent reconciliation.');
    }
    await initializeModel(this.workspace,target,binding,server,this.inputs.fingerprint);
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
    if(binding?.mode==='gui')await this.debuggerReleased(binding);
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
  async observation(scope:Scope){return this.call(scope,'/research_view');}
  async call(scope: Scope, operation: string, parameters: Record<string,unknown> = {}): Promise<unknown> {
    if(Object.hasOwn(parameters,'program'))fail('invalid','Program routing is owned by the session and target selectors.');
    if(operation==='/set_variables'&&typeof parameters.variables!=='string')parameters={...parameters,variables:JSON.stringify(parameters.variables)};
    if(operation==='/create_function_signature'&&typeof parameters.parameters!=='string')parameters={...parameters,parameters:JSON.stringify(parameters.parameters)};
    const record=await this.selected(scope);
    if(operation.startsWith('/sdk/')){
      if(operation==='/sdk/type-archive-import'){
        const root=join(record.binding.root,'sdk-archives',randomUUID());await mkdir(root,{recursive:true,mode:0o700});
        const path=join(root,'input.gdt');await link(await this.workspace.artifacts.verify(parameters.archive as Artifact),path);parameters={...parameters,input_path:path};
      }
      return nativeQuery(record.http,record.binding.program,operation,parameters,sdkWrites.has(operation));
    }
    if(nativeQueries.has(operation))return nativeQuery(record.http,record.binding.program,operation,parameters);
    if(operation==='/set_function_prototype'&&parameters.calling_convention==='default') {
      const validation=object(await nativeQuery(record.http,record.binding.program,'/validate_function_prototype',{
        function:parameters.function_address,prototype:parameters.prototype,calling_convention:'default'}));
      if(validation.valid!==true)fail('invalid','Prototype or default convention could not be resolved by Ghidra.');
      parameters={...parameters,calling_convention:object(validation.signature).calling_convention};
    }
    if(operation==='/apply_function_documentation') {
      const name='InsightApplyDocumentation_'+randomUUID().replaceAll('-','');
      const source=await readFile(new URL('../../references/native/InsightApplyDocumentation.java',import.meta.url),'utf8');
      return record.http.call('/run_script_inline',{program:record.binding.program,
        code:source.replace('class InsightApplyDocumentation ',`class ${name} `),
        args:Buffer.from(JSON.stringify(parameters.json_body),'utf8').toString('base64')});
    }
    if(operation==='/configure_analyzer'&&(this.inputs.extensionRoots?.length??0)>0){
      // A packed program need not persist disabled/default analyzer option registrations.
      // Register this JVM's actual applicable extension analyzers before the pinned handler's
      // Options.contains check. The surrounding program request already owns its journal.
      const name='InsightAnalyzerOptions_'+randomUUID().replaceAll('-','');
      const code=`import ghidra.app.script.GhidraScript;
public class ${name} extends GhidraScript {public void run(){ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(currentProgram).initializeOptions();println("INSIGHT_ANALYZER_OPTIONS_READY");}}`;
      const initialized=object(await record.http.call('/run_script_inline',{program:record.binding.program,code}));
      if(initialized.success!==true||typeof initialized.console_output!=='string'||!initialized.console_output.includes('INSIGHT_ANALYZER_OPTIONS_READY'))fail('partial','Installed analyzer option registration could not be established.');
    }
    if(operation==='/run_ghidra_script') {
      const script=String(parameters.script_name),path=await scriptPath(this.inputs.ghidraHome,record.binding.root,script,this.inputs.extensionRoots);
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
    return scriptInventory(this.inputs.ghidraHome,record.binding.root,filter,limit,offset,this.inputs.extensionRoots);
  }
  async inspect(snapshot:Artifact,parameters:Record<string,unknown>) {
    const root=join(this.directory(),'inspection',randomUUID());await mkdir(root,{recursive:true,mode:0o700});
    if(parameters.kind==='sdk'&&parameters.operation==='type-archive-import'){
      const p=object(parameters.parameters),path=join(root,'input.gdt');await link(await this.workspace.artifacts.verify(p.archive as Artifact),path);
      parameters={...parameters,parameters:{...p,input_path:path}};
    }
    const request=join(root,'request.json');await durable(request,parameters);
    const result=await this.server().inspect(await this.workspace.artifacts.verify(snapshot),request);return object(result.value);
  }
  private async removePeer(record:Running,path:string) {
    // A cancelled invocation must still release its verified owned temporary program.
    const cleanup=this.fork({...this.c,signal:new AbortController().signal});
    const checked=await cleanup.verified(record.binding,this.workspace.target(record.binding.target));
    const closed=object(await checked.http.call('/close_program',{name:path,save:false}));
    if(closed.success!==true)fail('binding','Owned cross-target snapshot could not be closed.');
    const removed=object(await checked.http.call('/delete_file',{filePath:path}));
    if(removed.success!==true)fail('binding','Owned cross-target snapshot could not be removed.');
  }
  private async reconcilePeers(record:Running) {
    const parent=join(record.binding.root,'cross-peer');let entries;
    try{entries=await readdir(parent,{withFileTypes:true});}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
    for(const entry of entries) {
      if(!entry.isDirectory()||!/^__insight_peer_[a-f0-9]{32}$/.test(entry.name))fail('binding','Owned cross-target stage inventory changed.');
      const folder=join(parent,entry.name);if(await realpath(folder)!==folder)fail('binding','Cross-target stage left its owned directory.');
      const receipt=object(JSON.parse(await readFile(join(folder,'receipt.json'),'utf8'))),path='/'+entry.name;
      if(receipt.path!==path||receipt.target!==record.binding.target||receipt.context!==record.binding.context)fail('binding','Cross-target cleanup receipt belongs to another context.');
      if(receipt.state==='closed')continue;if(receipt.state!=='preparing')fail('binding','Unknown cross-target cleanup stage.');
      await this.removePeer(record,path);await durable(join(folder,'receipt.json'),{...receipt,state:'closed'});
    }
  }
  private async withPeer<T>(record:Running,snapshot:Artifact,action:(path:string)=>Promise<T>,reconcile=true):Promise<T> {
    if(reconcile)await this.reconcilePeers(record);
    const name='__insight_peer_'+randomUUID().replaceAll('-',''),path='/'+name,
      folder=join(record.binding.root,'cross-peer',name);await mkdir(folder,{recursive:true,mode:0o700});
    const file=join(folder,'input.gzf');await link(await this.workspace.artifacts.verify(snapshot),file);
    await durable(join(folder,'receipt.json'),{path,target:record.binding.target,context:record.binding.context,state:'preparing'});
    try {
      const imported=object(await record.http.call('/import_program',{gzf_path:file,target_folder:'/',target_name:name,overwrite:false}));
      if(imported.success!==true)fail('binding','Cross-target snapshot import was not acknowledged.');
      const opened=object(await record.http.call('/open_program',{path}));if(opened.path!==path)fail('binding','Cross-target snapshot opened another program.');
      return await action(path);
    }finally {
      await this.removePeer(record,path);
      await durable(join(folder,'receipt.json'),{path,target:record.binding.target,context:record.binding.context,state:'closed'});
    }
  }
  async pair(selected:Scope,other:Scope,snapshot:Artifact,operation:string,parameters:Record<string,unknown>) {
    const record=await this.selected(selected);
    return this.withPeer(record,snapshot,async peer=>{
      if(operation==='/sdk/changes')return nativeQuery(record.http,record.binding.program,operation,{...parameters,peer_program:peer});
      let routing:Record<string,string>;
      if(operation==='/diff_functions')routing={program_a:record.binding.program,program_b:peer};
      else if(operation==='/compare_programs_documentation')routing={program:record.binding.program};
      else if(['/bulk_fuzzy_match','/find_similar_functions_fuzzy'].includes(operation))routing={source_program:record.binding.program,target_program:peer};
      else fail('invalid','Unsupported cross-target comparison.');
      const value=object(await record.http.call(operation,{...parameters,...routing}));
      if(operation==='/compare_programs_documentation') {
        if(!Array.isArray(value.programs))fail('partial','Comparison omitted its programs.');
        value.programs=value.programs.map(raw=>{const row=object(raw),who=row.path===record.binding.program?selected:row.path===peer?other:undefined;
          if(!who)fail('binding','Comparison included an undeclared context.');const {name,path,is_current,...counts}=row;
          return {...who,label:this.workspace.target(who.target).name,...counts};});
      }
      return logicalPrograms(value,new Map([[record.binding.program,selected],['program',selected],[peer,other],[peer.slice(1),other]]));
    });
  }
  async transfer(selected:Scope,source:Artifact,dryRun:boolean) {
    const record=await this.selected(selected);
    return this.withPeer(record,source,peer=>record.http.call('/merge_program_documentation',
      {source:peer,target:record.binding.program,dry_run:dryRun}));
  }
  async transferCheck(selected:Scope,source:Artifact,candidate:Artifact) {
    const record=await this.selected(selected);
    return this.withPeer(record,source,from=>this.withPeer(record,candidate,to=>record.http.call('/merge_program_documentation',
      {source:from,target:to,dry_run:true}),false));
  }
  async mode(scope: Scope, mode: ToolMode): Promise<void> {
    const record=await this.selected(scope);if(record.binding.mode===mode)return;
    const context=this.workspace.context(scope),snapshot=await this.capture(record);
    const debuggerState=record.binding.mode==='gui'&&context.debugger?.traces.length?await this.debuggerSaved(scope):context.debugger;
    const complexChanges=await this.debuggerMetadataChanges(context,snapshot);
    this.workspace.saveContext(scope,context.generation,{workingSnapshot:snapshot,complexChanges,...(debuggerState?{debugger:{...debuggerState,connected:false,traces:debuggerState.traces.map(trace=>({...trace,connected:false}))}}:{})});
    await this.stopRecord(record,true,false);
    if(mode==='headless'){await this.privateCopy(this.workspace.context(scope),snapshot);return;}
    const gui=await this.launch(record.binding.root,this.workspace.target(scope.target),'context',record.binding.program,'gui',context.id);
    gui.binding.baseRevision=record.binding.baseRevision;gui.binding.viewEpoch=record.binding.viewEpoch;
    await durable(join(gui.binding.root,'process.json'),gui.binding);
    await gui.http.call('/open_program',{path:gui.binding.program});await this.verified(gui.binding,this.workspace.target(scope.target));
    await durable(join(this.directory(),'context',context.id,'current.json'),gui.binding);
  }
  async project(operation:string,parameters:Record<string,unknown>) {return this.server().project(operation,parameters);}
  async ui(scope:Scope,operation:string,p:Record<string,unknown>){
    const record=await this.selected(scope);await this.reconcilePeers(record);
    if(operation==='plugins_list'||operation==='plugins_set'){
      if(record.binding.mode!=='gui')fail('configuration','Managed plugins require the owned GUI context.');
      const base='InsightPlugins',name=base+'_'+randomUUID().replaceAll('-',''),source=await readFile(new URL('../../references/native/'+base+'.java',import.meta.url),'utf8');
      const result=object(await record.http.call('/run_script_inline',{program:record.binding.program,code:source.replace('class '+base+' ',`class ${name} `),args:Buffer.from(JSON.stringify({...p,operation:operation==='plugins_list'?'list':'set'})).toString('base64')}));
      const lines=typeof result.console_output==='string'?result.console_output.split(/\r?\n/).filter(line=>line.includes('INSIGHT_PLUGINS:')):[];
      if(result.success!==true||lines.length!==1)fail('partial','Managed plugin effect was not established.');
      return object(JSON.parse(lines[0]!.slice(lines[0]!.indexOf('INSIGHT_PLUGINS:')+16)));
    }
    const paths:Record<string,string>={cursor:'/get_ui_cursor',tools:'/tool/running_tools',goto:'/tool/goto_address',prompt_policy:'/prompt_policy'},path=paths[operation];
    if(!path)fail('invalid','Unsupported UI operation.');
    const target=this.workspace.target(scope.target),metadata=await this.source(record,target),name=text(metadata.program_name);
    const value=await record.http.call(path,operation==='cursor'?{type:'all'}:p);
    return uiResult(operation,p,value,scope,record.binding.program,target.name,name);
  }
  async archivePayloads(scope:Scope,p:Record<string,unknown>){
    const record=await this.selected(scope),base='InsightArchivePayloads',name=base+'_'+randomUUID().replaceAll('-','');
    const source=await readFile(new URL('../../references/native/'+base+'.java',import.meta.url),'utf8');
    const result=object(await record.http.call('/run_script_inline',{program:record.binding.program,code:source.replace('class '+base+' ',`class ${name} `),args:Buffer.from(JSON.stringify(p)).toString('base64')}));
    if(result.success!==true||typeof result.console_output!=='string')fail('partial','Archive payload preparation failed.');
    const lines=result.console_output.split(/\r?\n/).filter(line=>line.includes('INSIGHT_ARCHIVE_PAYLOADS '));
    if(lines.length!==1)fail('partial','Archive payload preparation omitted its exact result.');
    return object(JSON.parse(lines[0]!.slice(lines[0]!.indexOf('INSIGHT_ARCHIVE_PAYLOADS ')+'INSIGHT_ARCHIVE_PAYLOADS '.length)));
  }
  async debuggerStart(scope:Scope){
    await this.debuggerHelper(scope,'Start','INSIGHT_DEBUGGER_READY');
    const saved=this.workspace.context(scope).debugger;
    if(saved?.traces.length){const record=await this.selected(scope),marker=join(record.binding.root,'traces-restored.json');
      try{const value=object(JSON.parse(await readFile(marker,'utf8')));if(value.pid===record.binding.pid&&value.tokenSecret===record.binding.tokenSecret)return;}
      catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
      const traces=await Promise.all(saved.traces.map(async trace=>({id:trace.id,input:await this.workspace.artifacts.verify(trace.snapshot),snap:trace.snap,...(trace.thread?{thread:trace.thread}:{})})));
      await this.traceHelper(scope,{operation:'restore',traces,...(saved.active?{active:saved.active}:{})});
      await durable(marker,{pid:record.binding.pid,tokenSecret:record.binding.tokenSecret});
    }
  }
  async debuggerStop(scope:Scope){
    return this.debuggerHelper(scope,'Stop','INSIGHT_DEBUGGER_STOPPED');
  }
  private async debuggerHelper(scope:Scope,action:'Start'|'Stop',marker:string){
    const record=await this.selected(scope);if(record.binding.mode!=='gui')fail('configuration','Debugger requires the owned GUI context.');
    return this.debuggerHelperRecord(record,action,marker);
  }
  private async debuggerHelperRecord(record:Running,action:'Start'|'Stop',marker:string){
    const base='Insight'+action+'Debugger',name=base+'_'+randomUUID().replaceAll('-',''),source=await readFile(new URL('../../references/native/'+base+'.java',import.meta.url),'utf8');
    const result=object(await record.http.call('/run_script_inline',{program:record.binding.program,code:source.replace('class '+base+' ',`class ${name} `)}));
    if(result.success!==true||typeof result.console_output!=='string'||!result.console_output.includes(marker))fail('partial','Owned debugger lifecycle effect was not established.');
  }
  async debuggerCall(scope:Scope,operation:string,p:Record<string,unknown>={}){
    const allowed=['launch','launch_offers','status','traces','resume','interrupt','step','set_breakpoint','remove_breakpoint','list_breakpoints','registers','read_memory','stack_trace','modules','static_to_dynamic','dynamic_to_static','write_memory','write_register','timeline','objects','object_values','schedule'];
    if(!allowed.includes(operation)||Object.hasOwn(p,'program'))fail('invalid','Unsupported scoped debugger operation.');
    const record=await this.selected(scope);
    if(['write_memory','write_register','timeline','objects','object_values','schedule'].includes(operation))return this.traceHelper(scope,{...p,operation});
    if(operation==='list_breakpoints')return (await this.traceHelper(scope,{operation:'breakpoints'})).items;
    if(['resume','interrupt','step','set_breakpoint','remove_breakpoint'].includes(operation))await this.traceHelper(scope,{operation:'focus'});
    if(operation==='read_memory')await this.traceHelper(scope,{operation:'read_memory',address:p.address,size:p.size});
    const token=await this.c.secrets.require(record.binding.tokenSecret),timeout=operation==='launch'?(Number(p.timeout_seconds??60)+90)*1000:45000;
    const callerPython=process.platform==='darwin'&&operation==='step'&&p.kind==='out'?record.binding.debuggerPython:undefined;
    if(callerPython&&(dirname(callerPython)!==record.binding.root||await realpath(callerPython)!==callerPython))fail('binding','Native caller Python scope changed.');
    const priorCaller=callerPython?await readCallerGoal(callerPython):undefined;
    const raw=await new HttpBridge(record.binding.endpoint,this.c.fetch,this.c.signal,token,timeout).call('/debugger/'+operation,
      {...p,...(['launch','launch_offers','static_to_dynamic'].includes(operation)?{program:record.binding.program}:{})});
    if(callerPython){const goal=await readCallerGoal(callerPython);if(goal&&goal.id!==priorCaller?.id){
      const launch=object(JSON.parse(await readFile(join(record.binding.root,'debugger-run','current.json'),'utf8')));
      if(goal.executable!==launch.executable||launch.context!==record.binding.context||launch.target!==scope.target)fail('binding','Native caller belongs to another launch.');
      await awaitCaller(callerPython,goal,this.c.signal);
    }}
    const label=this.workspace.target(scope.target).name;
    if(operation==='modules'&&Array.isArray(raw))return raw.map(value=>{const row=object(value),{path,...rest}=row;return {...rest,...(typeof row.name==='string'&&(row.name.includes(record.binding.root)||['image','image.exe'].includes(row.name))?{name:label}:{})};});
    if(raw&&typeof raw==='object'&&!Array.isArray(raw)){
      const value=object(raw),{program,executable_path,target_description,...rest}=value;
      if(operation==='launch'){
        if(value.status!=='launched'||executable_path!==p.executable_path||typeof value.trace_name!=='string')fail('binding','Debugger launch did not verify its staged executable.');
        await this.traceHelper(scope,{operation:'bind_new',name:value.trace_name});
      }
      if(program!==undefined){const metadata=await this.source(record,this.workspace.target(scope.target));if(program!==metadata.program_name&&program!==record.binding.program)fail('binding','Debugger selected another static program.');}
      if(value.trace_name!==undefined)rest.trace_name=label;
      if(typeof value.module==='string'&&(value.module.includes(record.binding.root)||['image','image.exe'].includes(value.module)))rest.module=label;
      return rest;
    }
    return raw;
  }
  private async traceHelper(scope:Scope,p:Record<string,unknown>){
    const record=await this.selected(scope),context=this.workspace.context(scope),name='InsightTraceState_'+randomUUID().replaceAll('-','');
    const source=await readFile(new URL('../../references/native/InsightTraceState.java',import.meta.url),'utf8');
    const args=Buffer.from(JSON.stringify({...p,target:scope.target,context:context.id,owned_root:record.binding.root})).toString('base64');
    const result=object(await record.http.call('/run_script_inline',{program:record.binding.program,code:source.replace('class InsightTraceState ',`class ${name} `),args}));
    const output=result.console_output;if(result.success!==true||typeof output!=='string')fail('partial','Trace state action did not complete.');
    const lines=output.split(/\r?\n/).filter(line=>line.includes('INSIGHT_TRACE_STATE '));
    if(lines.length!==1)fail('partial','Trace action omitted its exact result marker.');
    return object(JSON.parse(lines[0]!.slice(lines[0]!.indexOf('INSIGHT_TRACE_STATE ')+'INSIGHT_TRACE_STATE '.length)));
  }
  async debuggerSaved(scope:Scope):Promise<DebuggerState>{
    const record=await this.selected(scope),context=this.workspace.context(scope);let value:Record<string,unknown>|undefined,output='';
    for(let attempt=0;attempt<12;attempt++){
      output=join(record.binding.root,'trace-exports',randomUUID());await mkdir(output,{recursive:true,mode:0o700});
      try{value=await this.traceHelper(scope,{operation:'checkpoint',output});break;}
      catch(error){if(attempt===11||!String((error as Error).message).includes('Unable to lock due to active transaction'))throw error;await delay(150);}
    }
    if(!value||!Array.isArray(value.traces)||value.traces.length>64)fail('partial','Trace checkpoint inventory is malformed.');
    const traces=[];for(const raw of value.traces){const row=object(raw),traceId=text(row.id);if(!/^trace_[a-f0-9-]{36}$/.test(traceId))fail('binding','Trace checkpoint identity changed.');
      const snapshot=await this.workspace.captureSnapshot(join(output,traceId+'.gzf')),observed=await this.server().traceInspect(await this.workspace.artifacts.verify(snapshot));
      if(observed.id!==traceId||observed.target!==scope.target||observed.context!==context.id)fail('binding','Packed trace belongs to another tool context.');
      if(typeof row.snap!=='string'||!/^\d+$/.test(row.snap)||!Number.isSafeInteger(observed.modules)||!Number.isSafeInteger(observed.threads))fail('partial','Packed trace metadata is incomplete.');
      if(typeof row.connected!=='boolean')fail('partial','Trace connection state is absent.');
      if(row.thread!==undefined&&(typeof row.thread!=='string'||!/^\d+$/.test(row.thread)))fail('partial','Trace checkpoint thread identity is invalid.');
      traces.push({id:traceId,name:text(observed.name),snapshot,snap:row.snap,modules:Number(observed.modules),threads:Number(observed.threads),connected:row.connected,...(row.thread?{thread:String(row.thread)}:{})});
    }
    const active=value.active===undefined?undefined:text(value.active);if(active&&!traces.some(trace=>trace.id===active))fail('binding','Active trace is absent from its checkpoint.');
    return {traces,...(active?{active}:{}),connected:traces.some(trace=>trace.connected)};
  }
  async debuggerSelect(scope:Scope,trace:string){await this.traceHelper(scope,{operation:'select',id:trace});}
  async debuggerLaunch(scope:Scope,p:Record<string,unknown>,request:string){
    if(!/^q_[a-f0-9-]{36}$/.test(request))fail('binding','Invalid internal debugger launch identity.');
    const record=await this.selected(scope);await this.debuggerReleased(record.binding);
    const target=this.workspace.target(scope.target),root=join(record.binding.root,'debugger-run',request);await mkdir(root,{recursive:true,mode:0o700});
    const executable=join(root,process.platform==='win32'?'image.exe':'image');await copyFile(await this.workspace.artifacts.verify(target.input),executable,constants.COPYFILE_EXCL);await chmod(executable,0o500);
    const copied=await this.workspace.artifacts.capture(executable,'input');if(copied.id!==target.input.id)fail('binding','Staged debug executable differs from the immutable target.');
    const cwd=p.cwd===undefined?root:text(p.cwd,4096);if(/[\r\n\0]/.test(cwd))fail('invalid','Debugger working directory must be a single filesystem path.');
    await durable(join(record.binding.root,'debugger-run','current.json'),{request,target:scope.target,context:record.binding.context,executable,cwd,...(p.stop_at_entry===true?{stopAtEntry:true}:{})});
    const {stop_at_entry,...parameters}=p;
    return this.debuggerCall(scope,'launch',{...parameters,executable_path:executable,cwd,
      ...(this.c.profile.values.debuggerPython?{python_executable:text(this.c.profile.values.debuggerPython,4096)}:{}),
      ...(this.c.profile.values.windbgDir?{windbg_dir:text(this.c.profile.values.windbgDir,4096)}:{})});
  }
  async projectOutcome(requestId:string,expected:Record<string,unknown>) {return this.server().projectOutcome(requestId,expected);}
  private async debuggerMetadataChanges(context:GhidraContext,snapshot:Artifact){
    if(!context.debugger?.traces.length||!context.workingSnapshot)return context.complexChanges;
    return await debuggerProgramMetadata(this,context.workingSnapshot)!==await debuggerProgramMetadata(this,snapshot)?[...context.complexChanges,'debugger-metadata-'+randomUUID()]:context.complexChanges;
  }
  async close(scope: Scope) {
    const context=this.workspace.context(scope),record=await this.selected(scope),snapshot=await this.capture(record);
    const debuggerState=record.binding.mode==='gui'&&context.debugger?.traces.length?await this.debuggerSaved(scope):context.debugger;
    const complexChanges=await this.debuggerMetadataChanges(context,snapshot);
    this.workspace.saveContext(scope,context.generation,{state:'stopped',workingSnapshot:snapshot,complexChanges,...(debuggerState?{debugger:{...debuggerState,connected:false,traces:debuggerState.traces.map(trace=>({...trace,connected:false}))}}:{})});await this.stopRecord(record);
  }
  async closed(scope:Scope) {
    const context=this.workspace.context(scope),path=join(this.directory(),'context',context.id,'current.json');
    const binding=JSON.parse(await readFile(path,'utf8')) as ProcessBinding,root=await realpath(binding.root);
    if(!root.startsWith(resolve(this.directory())+sep)||binding.context!==context.id||binding.target!==scope.target||
      stable(JSON.parse(await readFile(join(root,'process.json'),'utf8')))!==stable(binding))fail('binding','Closed context receipt changed.');
    try{const stopped=object(JSON.parse(await readFile(join(root,'stopped.json'),'utf8')));
      if(stopped.pid===binding.pid&&stopped.tokenSecret===binding.tokenSecret)return true;
      // A GUI transition reuses the saved project root. Its earlier headless stop is not
      // evidence about this process; verify the current PID/binding independently below.
    }
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    if(!alive(binding.pid))return true;
    await this.verified(binding,this.workspace.target(scope.target));return false;
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
    if(await initialIntent(this.workspace,targetId)){await this.model(target);return this.workspace.model(targetId).state==='ready';}
    await this.retireLegacyBootstrap(target);
    let status;
    try{status=await server.programStatus(binding,programPath(targetId));}catch{return false;}
    if(status.state==='absent'){await this.model(target);return this.workspace.model(targetId).state==='ready';}
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
      }else if(binding.mode==='gui')await this.debuggerReleased(binding);
    }
  }
}
