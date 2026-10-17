import {skillCommand,toolboxCommands} from './toolbox.js';
import {listProcesses} from './tool-runtime/supervisor.js';
import {diagnosticsCommands} from './dotnet-diagnostics.js';
import {fridaCommands} from './frida.js';
import {lldbCommands} from './lldb.js';
import {dieCommands} from './die.js';
import {llvmCommands} from './llvm.js';
import {sevenzipCommands} from './sevenzip.js';
import {ilspyCommands} from './ilspy.js';
import {toolProcessCommands} from './tool-runtime/commands.js';
import {ghidraProcessHooks} from './ghidra-processes.js';
import {withToolLock,toolProfileBusy} from './tool-runtime/store.js';
import { command, createCli, Permission, CliError, ProfileStore, type CommandDefinition, type CliDefinition, type CliRuntime, type CommandContext, type IAppArguments } from '@eyeauras/cli-factory';
import { join, resolve } from 'node:path';
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { Workspace } from './workspace.js';
import { GhidraContexts, type ToolMode } from './contexts.js';
import { nativeInputs } from './native-inputs.js';
import { Research, type ResearchBackend, scope, address, commentKind, scalarText, number } from './research.js';
import { fail, id, text, digest, object } from './model.js';
import {queryCommands,extendQueries} from './queries.js';
import {mutationCommands} from './mutations.js';
import {crossCommands} from './cross.js';
import {Administration,administrationCommands} from './administration.js';
import {Lifecycle,lifecycleCommands} from './lifecycle.js';
import {utilityCommands} from './utility.js';
import {Projects,projectCommands} from './projects.js';
import {UserInterface,uiCommands,pluginCommands} from './ui.js';
import {Debugger,debuggerCommands} from './debugger.js';
import {Archive,archiveCommands} from './archive.js';
import {blockContent} from './memory-inputs.js';
import {verifyMutation} from './mutation-effects.js';
import {sdkCommands} from './sdk.js';
import {SdkFiles,sdkFileCommands} from './sdk-files.js';
import {parseDomainJson} from './json.js';
import {VersionTracking,trackingCommands} from './version-tracking.js';
import {Extensions,extensionCommands,extensionState,extensionInventoryCommands,managedExtensions} from './extensions.js';
import {Synchronization,synchronizationCommands} from './sync-policy.js';
import {artifactsCommands} from './saved-materials.js';
import {RuntimeManager,runtimeCommands,runtimeProcesses} from './runtime-manager.js';
import {packageVersion} from './package-version.js';
import {runtimeSelection} from './runtime-selection.js';

export interface Options {
  runtime?: CliRuntime;
  /** Offline fixture seam; production uses owned native Ghidra contexts. */
  backend?: (workspace: Workspace, context: CommandContext)=>ResearchBackend|Promise<ResearchBackend>;
}
interface ProfileOwner {
  workspace: Workspace; tasks: Map<string,Promise<unknown>>; backend?: Promise<ResearchBackend>; configuration: string;
}
const bindingFields=['java','ghidraHome','mcpJar','mcpJarSha256','server','repository','readerUser','publisherUser','maxContexts','debuggerPython','windbgDir','archiveUrl'];
class Owner {
  private readonly profiles=new Map<string,ProfileOwner>();
  private readonly runtimeChanging=new Set<string>();
  async runtime<T>(c:CommandContext,action:()=>Promise<T>,quiescent=true):Promise<T>{
    const directory=c.appArguments.AppDataDirectory;
    if(this.runtimeChanging.has(directory))fail('busy','Another runtime operation is in progress.');
    const current=this.profiles.get(directory);
    if(quiescent&&current?.tasks.size)fail('busy','Research operations are in progress; finish them before managing the runtime.');
    this.runtimeChanging.add(directory);
    try{
      if(!quiescent)return await action();
      const processes=await runtimeProcesses(directory);if(processes.length)fail('busy','Close Ghidra contexts and stop the owned server before changing or checking the runtime.',{processes});
      if(current){await (await current.backend)?.dispose();current.workspace.close();this.profiles.delete(directory);}
      return await withToolLock(directory,'ghidra',action,c.signal);
    }finally{this.runtimeChanging.delete(directory);}
  }
  constructor(private readonly options: Options) {}
  selected(c: CommandContext) {
    const directory=c.appArguments.AppDataDirectory;
    if(this.runtimeChanging.has(directory))fail('busy','Runtime preparation is in progress.');
    const configuration=digest({runtime:runtimeSelection(directory),profile:Object.fromEntries(bindingFields.map(key=>[key,c.profile.values[key]])),extensions:extensionState(join(directory,'workspace')).modules.filter(m=>m.enabled).map(m=>[m.name,m.sha256])});
    let profile=this.profiles.get(directory);
    if(!profile) {
      profile={workspace:new Workspace(join(directory,'workspace'),c.profile.name),tasks:new Map(),configuration};
      this.profiles.set(directory,profile);
    }
    if(profile.configuration!==configuration)fail('binding','Runtime profile changed; stop the IPC owner before reopening its saved workspace.');
    const selected=profile;
    const backend=async()=>{
      if(!selected.backend)selected.backend=Promise.resolve(this.options.backend?
        this.options.backend(selected.workspace,c):nativeInputs(c.profile.values,selected.workspace.directory,c).then(inputs=>new GhidraContexts(selected.workspace,inputs,c)))
        .catch(error=>{selected.backend=undefined;throw error;});
      const result=await selected.backend;
      if(result instanceof GhidraContexts)await managedExtensions(selected.workspace.directory);
      return result instanceof GhidraContexts?result.fork(c):result;
    };
    const research=new Research(profile.workspace,backend,profile.tasks);
    return {workspace:profile.workspace,research,synchronization:new Synchronization(profile.workspace,research,async()=>{
      const store=this.options.runtime?.profileStore??new ProfileStore({applicationId:c.appArguments.AppName,appArguments:c.appArguments});
      if(!(await store.getPermissions(c.profile.name))?.includes(Permission.Update))throw new CliError('Automatic synchronization requires the current Factory Update permission.',{code:'permission.denied',next:[['permissions','grant','Update']]});
    }),administration:new Administration(profile.workspace,backend,profile.tasks),lifecycle:new Lifecycle(profile.workspace,research,backend),projects:new Projects(profile.workspace,backend,research,profile.tasks),sdkFiles:new SdkFiles(profile.workspace,research,backend),tracking:new VersionTracking(profile.workspace,research,backend,profile.tasks),ui:new UserInterface(profile.workspace,research,backend),debugger:new Debugger(profile.workspace,research,backend),archive:new Archive(profile.workspace,research,backend,c),backend};
  }
  async invalidateProfile(app: IAppArguments) {
    const directory=app.AppDataDirectory,profile=this.profiles.get(directory);
    if(this.runtimeChanging.has(directory))fail('busy','Runtime preparation is in progress; finish it before changing or deleting the profile.');
    if(toolProfileBusy(directory))fail('busy','A tool operation is active.');
    if((await listProcesses(directory)).some(r=>!['exited','failed'].includes(r.state)))fail('busy','The profile has active or unverified tool processes.');
    const materials=await readdir(join(directory,'materials')).catch(error=>{if(error.code==='ENOENT')return [];throw error;});
    if(existsSync(join(directory,'workspace','workspace.sqlite'))||materials.length)
      fail('blocked','Profile has retained research data; preserve its workspace and materials before deleting or reconfiguring it.');
    if(profile) {await (await profile.backend)?.dispose();profile.workspace.close();this.profiles.delete(directory);}
  }
  async dispose() {
    for(const profile of this.profiles.values()) {
      await Promise.allSettled([...profile.tasks.values()]);
      try {await (await profile.backend)?.dispose();}finally{profile.workspace.close();}
    }
    this.profiles.clear();
  }
}
const scoped=[
  {flags:'--session <id>',description:'Select the durable research session',required:true},
  {flags:'--target <id>',description:'Select the immutable input target',required:true},
];
const at={flags:'--address <address>',description:'Explicit hexadecimal address or space:address',required:true};
const request={flags:'--request-id <id>',description:'Retrieve the same changing intent after a lost response'};
const resolveOptions=[{flags:'--resolve-conflict',description:'Resolve the existing field against an explicitly observed shared value'},
  {flags:'--expect-shared <value>',description:'Shared value used for this resolution'},
  {flags:'--expect-shared-null',description:'Expect the shared comment to be absent'}];
function resolution(options:Record<string,unknown>) {
  const expected=options.expectShared!==undefined,absent=Boolean(options.expectSharedNull);
  if(!options.resolveConflict) {
    if(expected||absent)fail('invalid','Shared expectation requires --resolve-conflict.');return;
  }
  if(expected===absent)fail('invalid','Resolution needs exactly one --expect-shared or --expect-shared-null.');
  return {expectedShared:absent?null:scalarText(options.expectShared)};
}
function structureFields(value:unknown) {
  const source=text(value,65536);let parsed;
  try{parsed=JSON.parse(source);}catch{fail('invalid','Fields must be a JSON array of name/type objects.');}
  if(!Array.isArray(parsed)||!parsed.length||parsed.length>256)fail('invalid','Structure requires 1–256 field objects.');
  return parsed.map(value=>{const field=object(value);if(Object.keys(field).some(key=>!['name','type','offset'].includes(key)))fail('invalid','Unknown structure field property.');
    return {name:text(field.name,512),type:text(field.type,512),...(field.offset===undefined?{}:{offset:number(field.offset,2147483647)})};});
}
const paged=[
  {flags:'--limit <count>',description:'Maximum items in this page (1–100)',defaultValue:50,parse:(value:string)=>number(value,100,1)},
  {flags:'--offset <count>',description:'Skip items before this page',defaultValue:0,parse:(value:string)=>number(value,2147483647)},
];
const fields=[
  ['java','--java <path>','Java 21 JDK executable'],
  ['ghidraHome','--ghidra-home <path>','Ghidra 12.1.2 installation'],
  ['mcpJar','--mcp-jar <path>','Optional override of the packaged verified GhidraMCP runtime'],
  ['mcpJarSha256','--mcp-jar-sha256 <sha>','Expected runtime artifact digest'],
  ['server','--server <origin>','External Ghidra Server origin (omit for local startup)'],
  ['repository','--repository <name>','Repository on the external server'],
  ['readerUser','--reader-user <name>','Read-only external account'],
  ['publisherUser','--publisher-user <name>','External publication account'],
  ['maxContexts','--max-contexts <count>','Concurrent contexts (default 4, maximum 16)'],
  ['debuggerPython','--debugger-python <path>','Optional Python executable for a configured debugger offer'],
  ['windbgDir','--windbg-dir <path>','Optional Windows debugger runtime directory'],
  ['archiveUrl','--archive-url <url>','Explicit archive service base URL (disabled by default)'],
];
const mode=(value:unknown):ToolMode|undefined=>{
  if(value===undefined)return;
  if(value!=='headless'&&value!=='gui')fail('invalid','Mode must be headless or gui.');return value;
};
const targetView=(target:ReturnType<Workspace['target']>)=>({target:target.id,name:target.name,binarySha256:target.binarySha256,size:target.size,createdAt:target.createdAt});
function scopedFailures(entry:CommandDefinition,owner:Owner,parents:string[]=[]):CommandDefinition {
  const path=[...parents,entry.name.split(' ')[0]!],name=path.join(' ');
  const run=entry.run;
  return {...entry,...(entry.children?{children:entry.children.map(child=>scopedFailures(child,owner,path))}:{}),...(run?{run:async(input,c)=>{
    try{
      let selected;try{selected=scope(input.options);if(selected.session==='new')selected=undefined;}catch{}
      if(!selected)return await run(input,c);
      const services=owner.selected(c);
      // First open of an already known target reserves its context inside Research.open.
      // Existing contexts still use the command boundary to order automatic sync phases.
      if(path[1]==='open')try{services.workspace.context(selected);}catch(error){
        if(error instanceof CliError&&error.code==='coordinator.notFound')return await run(input,c);throw error;
      }
      return await services.research.boundary(selected,async()=>{
        const excluded=['open','merge','refresh','sync-policy','close','changes','debugger','ui','version-tracking','archive','projects','repository','server','formats','libraries','plugins'];
        const eligible=entry.permission!==Permission.ReadOnly&&entry.permission!==undefined&&!excluded.includes(path[1]!)&&!['ghidra types archive-export','ghidra documentation transfer'].includes(name);
        return eligible?services.synchronization.execute(selected,name,{...input.options,commandArguments:input.args},async requestId=>run({...input,options:{...input.options,...(requestId?{requestId}:{})}},c)):run(input,c);
      });
    }catch(error){
      let selected;try{selected=scope(input.options);}catch{throw error;}
      if(!(error instanceof CliError))throw error;
      const result=error.result&&typeof error.result==='object'&&!Array.isArray(error.result)?error.result:{};
      throw new CliError(error.message,{code:error.code,exitCode:error.exitCode,next:error.next,result:{...result,...selected}});
    }
  }}:{})};
}

export function createDefinition(options: Options = {}): CliDefinition {
  const owner=new Owner(options);
  const definition:CliDefinition={
    name:'insight-cli',applicationId:'insight-cli',version:packageVersion,description:'Isolated research contexts and coordinated Ghidra analysis',
    resources:[owner],permissions:{categories:[{name:'Destructive',description:'Explicit deletion or replacement of retained research data',enabledByDefault:false}]},...(options.runtime?{runtime:options.runtime}:{}),
    profile:{fields:fields.map(([name,flags,description])=>({name:name!,flags:flags!,description:description!,
      ...(name==='maxContexts'?{normalize:(value:unknown)=>number(value,16,1)}:{})}))},
    auth:{
      loginOptions:[{flags:'--role <role>',description:'External reader, publisher or archive role',defaultValue:'reader'},
        {flags:'--password-stdin',description:'Read the password from stdin'}],
      async login(c,o) {
        const role=text(o.role);if(!['reader','publisher','archive'].includes(role))fail('invalid','Role must be reader, publisher or archive.');
        if(role!=='archive'&&!c.profile.values.server)fail('configuration','Local server credentials are managed automatically.');
        if(role==='archive'&&!c.profile.values.archiveUrl)fail('configuration','Configure an archive URL before storing its token.');
        if(!o.passwordStdin||!c.stdinAvailable)fail('credentials','Supply --password-stdin for this role.');
        let candidate='';for await(const chunk of c.io.input){candidate+=chunk.toString();if(candidate.length>4096)fail('limit','Password input exceeds 4096 characters.');}
        candidate=candidate.replace(/\r?\n$/,'');if(!candidate||/[\r\n\0]/.test(candidate))fail('credentials','Password must be one nonempty line.');
        await c.secrets.set(role==='archive'?'archiveToken':role+'Password',candidate);
        return {authenticated:true,identity:{role,...(role==='archive'?{}:{user:c.profile.values[role+'User']}),validation:'stored; authority verified at connection'}};
      },
      async status(c) {
        let reader='readerPassword',publisher='publisherPassword';const external=Boolean(c.profile.values.server);
        if(!external) {
          try {const local=JSON.parse(await readFile(join(c.appArguments.AppDataDirectory,'workspace/server/local.json'),'utf8'));reader=local.readerSecret;publisher=local.publisherSecret;}
          catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;return {authenticated:false,identity:{mode:'local',validation:'managed on first open'}};}
        }
        const readerStored=Boolean(await c.secrets.get(reader)),publisherStored=Boolean(await c.secrets.get(publisher));
        return {authenticated:readerStored&&publisherStored,identity:{mode:external?'external':'local',readerStored,publisherStored}};
      },
      async logout(c) {
        await c.secrets.delete('archiveToken');
        if(!c.profile.values.server)return;
        await c.secrets.delete('readerPassword');await c.secrets.delete('publisherPassword');
      },
    },
    builtins:[skillCommand()],
    commands:[
      ...artifactsCommands(),
      ...diagnosticsCommands(c=>owner.selected(c).workspace),
      ...llvmCommands(c=>owner.selected(c).workspace),
      ...dieCommands(c=>owner.selected(c).workspace),
      ...lldbCommands(c=>owner.selected(c).workspace),
      ...fridaCommands(c=>owner.selected(c).workspace),
      ...sevenzipCommands(c=>owner.selected(c).workspace),
      ...ilspyCommands(c=>owner.selected(c).workspace),
      ...toolProcessCommands({ghidra:ghidraProcessHooks(c=>owner.selected(c).workspace,(scope,c)=>owner.selected(c).lifecycle.change(scope,'close'))},toolboxCommands()),
      command('targets','Inspect immutable inputs',[
        command('add <input>','Consume input without starting a tool',async({args},c)=>targetView(await owner.selected(c).workspace.importTarget(resolve(c.cwd,text(args.input,4096)))),{permission:Permission.Update}),
        command('list','List known inputs',({options:o},c)=>{
          const items=owner.selected(c).workspace.targets(number(o.limit,100,1),number(o.offset,2147483647));
          return {items:items.map(targetView),offset:o.offset,limit:o.limit,truncated:items.length===o.limit};
        },{permission:Permission.ReadOnly,options:paged}),
        command('show <target>','Show an input identity',({args},c)=>targetView(owner.selected(c).workspace.target(id(args.target))),{permission:Permission.ReadOnly}),
      ]),
      command('sessions','Inspect durable sessions',[
        command('list','List independent sessions',({options:o},c)=>{const items=owner.selected(c).workspace.sessions(number(o.limit,100,1),number(o.offset,2147483647));return {items,offset:o.offset,limit:o.limit,truncated:items.length===Number(o.limit)};},{permission:Permission.ReadOnly,options:paged}),
        command('status <session>','Inspect saved work and unresolved outcomes',({args,options:o},c)=>{
          const selected=owner.selected(c),session=id(args.session);selected.workspace.session(session);
          if(o.target)return selected.research.status({session,target:id(o.target)});
          const limit=number(o.limit,100,1),offset=number(o.offset,2147483647),contexts=selected.workspace.contexts(session,limit,offset);
          return {session,contexts:contexts.map(context=>selected.research.status(context)),limit,offset,truncated:contexts.length===limit};
        },{permission:Permission.ReadOnly,options:[{flags:'--target <id>',description:'Inspect one target context'},...paged]}),
      ]),
      command('ghidra','Research through an isolated saved context',[
        command('refresh','Receive safe shared changes while retaining local conflicts',({options:o},c)=>owner.selected(c).research.refresh(scope(o),o.requestId===undefined?undefined:id(o.requestId)),
          {permission:Permission.Update,options:[...scoped,request]}),
        command('merge','Publish the complete selected context or retain every conflict',({options:o},c)=>owner.selected(c).research.merge(scope(o),o.requestId===undefined?undefined:id(o.requestId)),
          {permission:Permission.Update,options:[...scoped,request]}),
        command('open [input]','Start independent work or continue a context',async({args,options:o},c)=>{
          if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');
          const selected=owner.selected(c),target=args.input?(await selected.workspace.importTarget(resolve(c.cwd,text(args.input,4096)))).id:id(o.target);
          let previous;
          try{previous=selected.workspace.model(target).settings;}catch(error){if(!String((error as {code?:string}).code).endsWith('.notFound'))throw error;}
          const settings={...previous,autoAnalyze:o.analysis===false?false:previous?.autoAnalyze??true,
            ...(o.language?{language:text(o.language)}:{}),...(o.compilerSpec?{compilerSpec:text(o.compilerSpec)}:{}),
            ...(o.imageBase?{imageBase:text(o.imageBase)}:{}),...(o.loader?{loader:text(o.loader,512)}:{}),
            ...(o.loaderOptions!==undefined?{loaderOptions:object(parseDomainJson(text(o.loaderOptions,16000))) as Record<string,string|number|boolean>}:{})};
          return selected.research.open(target,text(o.session),settings,o.requestId===undefined?undefined:id(o.requestId),mode(o.mode));
        },{permission:Permission.Update,options:[{flags:'--session <id>',description:'Use new for independent work, or an existing session',required:true},
          {flags:'--target <id>',description:'Continue existing input instead of supplying a file'},request,
          {flags:'--mode <mode>',description:'Request headless or gui; continuation preserves current mode'},
          {flags:'--no-analysis',description:'Skip initial automatic analysis'},
          {flags:'--language <id>',description:'Explicit initial loader language'},
          {flags:'--compiler-spec <id>',description:'Explicit initial compiler specification'},
          {flags:'--image-base <address>',description:'Initial image base'},
          {flags:'--loader <name>',description:'Explicit installed loader name/ID from formats loaders'},
          {flags:'--loader-options <json>',description:'Named primitive SDK loader options, requiring --loader'}]}),
        command('strings','Read defined strings',[
          command('search','Find literal text and usable addresses',({options:o},c)=>owner.selected(c).research.strings(scope(o),text(o.contains,4096),number(o.limit,100,1),number(o.offset,2147483647)),
            {permission:Permission.ReadOnly,options:[...scoped,{flags:'--contains <text>',description:'Literal case-insensitive substring',required:true},...paged]}),
        ]),
        command('xrefs','Follow cross references',[
          command('to','Find incoming references and their functions',({options:o},c)=>owner.selected(c).research.xrefs(scope(o),address(o.address),number(o.limit,100,1),number(o.offset,2147483647)),
            {permission:Permission.ReadOnly,options:[...scoped,at,...paged]}),
        ]),
        command('types','Read and edit data types',[
          command('struct-layout','Read a structure layout',({options:o},c)=>owner.selected(c).research.read(scope(o),'/get_struct_layout',{struct_name:text(o.name,512)})
            .then(value=>({...scope(o),value})),{permission:Permission.ReadOnly,options:[...scoped,{flags:'--name <name>',description:'Structure name',required:true}]}),
          command('create-struct','Create and save a private structure',({options:o},c)=>{
            const selected=owner.selected(c),who=scope(o),name=text(o.name,512),fields=structureFields(o.fields);
            if(o.replacePlaceholder){
              const parameters={path:name.startsWith('/')?name:'/'+name,fields,packing:-1,alignment:0,replace_placeholder:true};
              return selected.research.mutate(who,'/sdk/type-structure',parameters,async()=>({}),o.requestId===undefined?undefined:id(o.requestId),
                (backend,snapshot,response)=>verifyMutation(backend,snapshot,'/sdk/type-structure',parameters,response));
            }
            return selected.research.mutate(who,'/create_struct',{name,fields},async(backend)=>{
              const result=object(await backend.call(who,'/get_struct_layout',{struct_name:name}));
              if(result.name!==name||!Array.isArray(result.fields)||result.fields.length!==fields.length)fail('partial','Structure readback omitted fields or changed its name.');
              for(let i=0;i<fields.length;i++)if(object(result.fields[i]).name!==fields[i]!.name)fail('partial','Structure readback changed a field name.');
              return result;
            },o.requestId===undefined?undefined:id(o.requestId));
          },{permission:Permission.Update,options:[...scoped,{flags:'--name <name>',description:'New structure name',required:true},
            {flags:'--fields <json>',description:'Array of {name,type,offset?}',required:true},{flags:'--replace-placeholder',description:'Replace only an existing empty structure, with independently verified saved layout'},request]}),
        ]),
        command('memory','Read or edit memory blocks',[
          command('list','Read bounded memory blocks',({options:o},c)=>owner.selected(c).research.read(scope(o),'/list_program_items',{kind:'segments',limit:number(o.limit,100,1),offset:number(o.offset,2147483647)})
            .then(value=>({...scope(o),value})),{permission:Permission.ReadOnly,options:[...scoped,...paged]}),
          command('create-block','Create a saved initialized/uninitialized or overlay block with verified content',({options:o},c)=>{
            const selected=owner.selected(c),who=scope(o),parameters:Record<string,unknown>={name:text(o.name,512),address:address(o.address),
              ...(o.size===undefined?{}:{size:number(o.size,16777216,1)}),read:o.read!==false,write:o.write!==false,execute:Boolean(o.execute),
              initialized:o.initialized!==false,overlay:Boolean(o.overlay),volatile:Boolean(o.volatile),comment:o.comment===undefined?'':text(o.comment,16000),
              fill_byte:o.fillByte===undefined?0:number(o.fillByte,255),...(o.bytesHex===undefined?{}:{bytes_hex:o.bytesHex}),...(o.bytesBase64===undefined?{}:{bytes_base64:o.bytesBase64})};
            const expected=blockContent(parameters);parameters.size=expected.size;
            return selected.research.mutate(who,'/create_memory_block',parameters,async()=>({}),o.requestId===undefined?undefined:id(o.requestId),
              (backend,snapshot,response)=>verifyMutation(backend,snapshot,'/create_memory_block',parameters,response));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--name <name>',description:'Memory block name',required:true},
            {flags:'--size <bytes>',description:'Positive size up to 16 MiB; defaults to content length'},
            {flags:'--bytes-hex <hex>',description:'Initial bytes in hexadecimal; remainder uses fill-byte'},
            {flags:'--bytes-base64 <base64>',description:'Initial bytes as canonical padded base64'},
            {flags:'--fill-byte <byte>',description:'Fill byte from 0 to 255',defaultValue:0},
            {flags:'--initialized <boolean>',description:'false creates uninitialized memory',defaultValue:true,parse:(v:string)=>{if(v!=='true'&&v!=='false')fail('invalid','initialized must be true or false.');return v==='true';}},
            {flags:'--overlay',description:'Create a distinct overlay address space'},
            {flags:'--volatile',description:'Mark memory volatile'},{flags:'--comment <text>',description:'Block comment'},
            {flags:'--no-read',description:'Disable read permission'},{flags:'--no-write',description:'Disable write permission'},
            {flags:'--execute',description:'Enable execution permission'},request]}),
        ]),
        command('functions','Read or name functions',[
          command('set-function-prototype','Set a C prototype and optional explicit compiler-supported calling convention',({options:o},c)=>{
            const selected=owner.selected(c),who=scope(o),parameters={function_address:address(o.address),prototype:text(o.prototype,16000),
              ...(o.callingConvention===undefined?{}:{calling_convention:text(o.callingConvention,512)})};
            return selected.research.mutate(who,'/set_function_prototype',parameters,async()=>({}),o.requestId===undefined?undefined:id(o.requestId),
              (backend,snapshot,response)=>verifyMutation(backend,snapshot,'/set_function_prototype',parameters,response));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--prototype <signature>',description:'Complete C prototype',required:true},
            {flags:'--calling-convention <name>',description:'Explicit convention supported by the selected compiler specification'},request]}),
          command('get','Read a function and entry comments',({options:o},c)=>owner.selected(c).research.function(scope(o),address(o.address)),{permission:Permission.ReadOnly,options:[...scoped,at]}),
          command('decompile','Read decompiled function text',({options:o},c)=>owner.selected(c).research.function(scope(o),address(o.address),true),{permission:Permission.ReadOnly,options:[...scoped,at]}),
          command('rename','Record a saved private name',({options:o},c)=>{
            const name=text(o.name,512);if(name!==name.trim())fail('invalid','Function name may not have leading or trailing whitespace.');
            return owner.selected(c).research.edit(scope(o),address(o.address),'function.name',name,o.requestId===undefined?undefined:id(o.requestId),resolution(o));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--name <name>',description:'Desired function name',required:true},request,...resolveOptions]}),
        ]),
        command('comments','Read or edit listing comments',[
          command('get','Read one kind or all five fields',({options:o},c)=>owner.selected(c).research.comment(scope(o),address(o.address),o.kind===undefined?undefined:commentKind(o.kind)),
            {permission:Permission.ReadOnly,options:[...scoped,at,{flags:'--kind <kind>',description:'eol, pre, post, plate or repeatable'}]}),
          command('set','Record a saved private comment or clear it',({options:o},c)=>{
            if(Boolean(o.clear)===(o.text!==undefined))fail('invalid','Supply exactly one --text or --clear.');
            return owner.selected(c).research.edit(scope(o),address(o.address),'comment.'+commentKind(o.kind) as 'comment.eol',
              o.clear?null:scalarText(o.text),o.requestId===undefined?undefined:id(o.requestId),resolution(o));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--kind <kind>',description:'eol, pre, post, plate or repeatable',required:true},
            {flags:'--text <text>',description:'Desired text; empty text clears to null'},{flags:'--clear',description:'Clear this comment to null'},request,...resolveOptions]}),
        ]),
      ]),
    ],
  };
  return {...definition,commands:definition.commands?.map(entry=>entry.name==='ghidra'?
    scopedFailures({...entry,children:extendQueries(extendQueries(extendQueries(entry.children??[],queryCommands(c=>owner.selected(c).research)),
      mutationCommands(c=>owner.selected(c).research)),[...sdkCommands(c=>owner.selected(c).research),...sdkFileCommands(c=>owner.selected(c).sdkFiles),...trackingCommands(c=>owner.selected(c).tracking),...crossCommands(c=>owner.selected(c).research),...administrationCommands(c=>owner.selected(c).administration,options.backend?undefined:async c=>{const status=await new RuntimeManager(c).status();return status.state==='not_ready'?{...status.server,connected:false,state:'runtime_not_ready',missing:status.missing}:undefined;}),
        ...extensionCommands(c=>new Extensions(join(c.appArguments.AppDataDirectory,'workspace'))),...extensionInventoryCommands(c=>owner.selected(c).backend),...pluginCommands(c=>owner.selected(c).ui),...synchronizationCommands(c=>owner.selected(c).synchronization),...utilityCommands(),...runtimeCommands((c,action,quiescent)=>owner.runtime(c,action,quiescent)),...lifecycleCommands(c=>owner.selected(c).lifecycle,c=>new RuntimeManager(c).status()),...projectCommands(c=>owner.selected(c).projects),...uiCommands(c=>owner.selected(c).ui),...debuggerCommands(c=>owner.selected(c).debugger),...archiveCommands(c=>owner.selected(c).archive)])},owner):entry)};
}
export const createInsightCli=(options:Options={})=>createCli(createDefinition(options));
