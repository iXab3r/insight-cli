import { command, createCli, Permission, type CliDefinition, type CliRuntime, type CommandContext, type IAppArguments } from '@eyeauras/cli-factory';
import { join, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Workspace } from './workspace.js';
import { GhidraContexts, type ToolMode } from './contexts.js';
import { nativeInputs } from './native-inputs.js';
import { Research, type ResearchBackend, scope, address, commentKind, scalarText, number } from './research.js';
import { fail, id, text, digest } from './model.js';

export interface Options {
  runtime?: CliRuntime;
  /** Offline fixture seam; production uses owned native Ghidra contexts. */
  backend?: (workspace: Workspace, context: CommandContext)=>ResearchBackend|Promise<ResearchBackend>;
}
interface ProfileOwner {
  workspace: Workspace; tasks: Map<string,Promise<unknown>>; backend?: Promise<ResearchBackend>; configuration: string;
}
const bindingFields=['java','ghidraHome','mcpJar','mcpJarSha256','server','repository','readerUser','publisherUser','maxContexts'];
class Owner {
  private readonly profiles=new Map<string,ProfileOwner>();
  constructor(private readonly options: Options) {}
  selected(c: CommandContext) {
    const directory=c.appArguments.AppDataDirectory;
    const configuration=digest(Object.fromEntries(bindingFields.map(key=>[key,c.profile.values[key]])));
    let profile=this.profiles.get(directory);
    if(!profile) {
      profile={workspace:new Workspace(join(directory,'workspace'),c.profile.name),tasks:new Map(),configuration};
      this.profiles.set(directory,profile);
    }
    if(profile.configuration!==configuration)fail('binding','Runtime profile changed; stop the IPC owner before reopening its saved workspace.');
    const selected=profile;
    const backend=async()=>{
      if(!selected.backend)selected.backend=Promise.resolve(this.options.backend?
        this.options.backend(selected.workspace,c):nativeInputs(c.profile.values).then(inputs=>new GhidraContexts(selected.workspace,inputs,c)))
        .catch(error=>{selected.backend=undefined;throw error;});
      const result=await selected.backend;
      return result instanceof GhidraContexts?result.fork(c):result;
    };
    return {workspace:profile.workspace,research:new Research(profile.workspace,backend,profile.tasks),backend};
  }
  async invalidateProfile(app: IAppArguments) {
    const directory=app.AppDataDirectory,profile=this.profiles.get(directory);
    if(existsSync(join(directory,'workspace','workspace.sqlite')))
      fail('blocked','Profile has retained research state; preserve its workspace before deleting the profile.');
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
const paged=[
  {flags:'--limit <count>',description:'Maximum items in this page (1–100)',defaultValue:50,parse:(value:string)=>number(value,100,1)},
  {flags:'--offset <count>',description:'Skip items before this page',defaultValue:0,parse:(value:string)=>number(value,2147483647)},
];
const fields=[
  ['java','--java <path>','Java 21 JDK executable'],
  ['ghidraHome','--ghidra-home <path>','Ghidra 12.1.2 installation'],
  ['mcpJar','--mcp-jar <path>','Verified pinned GhidraMCP runtime jar'],
  ['mcpJarSha256','--mcp-jar-sha256 <sha>','Expected runtime artifact digest'],
  ['server','--server <origin>','External Ghidra Server origin (omit for local startup)'],
  ['repository','--repository <name>','Repository on the external server'],
  ['readerUser','--reader-user <name>','Read-only external account'],
  ['publisherUser','--publisher-user <name>','External publication account'],
  ['maxContexts','--max-contexts <count>','Concurrent contexts (default 4, maximum 16)'],
];
const mode=(value:unknown):ToolMode|undefined=>{
  if(value===undefined)return;
  if(value!=='headless'&&value!=='gui')fail('invalid','Mode must be headless or gui.');return value;
};
const targetView=(target:ReturnType<Workspace['target']>)=>({target:target.id,name:target.name,binarySha256:target.binarySha256,size:target.size,createdAt:target.createdAt});

export function createDefinition(options: Options = {}): CliDefinition {
  const owner=new Owner(options);
  return {
    name:'insight-cli',applicationId:'insight-cli',version:'0.1.0',description:'Isolated research contexts and coordinated Ghidra analysis',
    resources:[owner],permissions:{},...(options.runtime?{runtime:options.runtime}:{}),
    profile:{fields:fields.map(([name,flags,description])=>({name:name!,flags:flags!,description:description!,
      ...(name==='maxContexts'?{normalize:(value:unknown)=>number(value,16,1)}:{})}))},
    auth:{
      loginOptions:[{flags:'--role <role>',description:'External reader or publisher role',defaultValue:'reader'},
        {flags:'--password-stdin',description:'Read the password from stdin'}],
      async login(c,o) {
        if(!c.profile.values.server)fail('configuration','Local credentials are managed automatically; login configures an external server profile.');
        const role=text(o.role);if(!['reader','publisher'].includes(role))fail('invalid','Role must be reader or publisher.');
        if(!o.passwordStdin||!c.stdinAvailable)fail('credentials','Supply --password-stdin for this role.');
        let candidate='';for await(const chunk of c.io.input){candidate+=chunk.toString();if(candidate.length>4096)fail('limit','Password input exceeds 4096 characters.');}
        candidate=candidate.replace(/\r?\n$/,'');if(!candidate||/[\r\n\0]/.test(candidate))fail('credentials','Password must be one nonempty line.');
        await c.secrets.set(role+'Password',candidate);
        return {authenticated:true,identity:{role,user:c.profile.values[role+'User'],validation:'stored; authority verified at connection'}};
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
        if(!c.profile.values.server)fail('configuration','Local credentials remain bound to retained owned storage.');
        await c.secrets.delete('readerPassword');await c.secrets.delete('publisherPassword');
      },
    },
    builtins:[command('skill','Locate the installed workflow skill',()=>({version:'0.1.0',path:fileURLToPath(new URL('../../SKILL.md',import.meta.url))}))],
    commands:[
      command('targets','Inspect immutable inputs',[
        command('add <input>','Consume input without starting a tool',async({args},c)=>targetView(await owner.selected(c).workspace.importTarget(resolve(c.cwd,text(args.input,4096)))),{permission:Permission.Update}),
        command('list','List known inputs',({options:o},c)=>{
          const items=owner.selected(c).workspace.targets(number(o.limit,100,1),number(o.offset,2147483647));
          return {items:items.map(targetView),offset:o.offset,limit:o.limit,truncated:items.length===o.limit};
        },{permission:Permission.ReadOnly,options:paged}),
        command('show <target>','Show an input identity',({args},c)=>targetView(owner.selected(c).workspace.target(id(args.target))),{permission:Permission.ReadOnly}),
      ]),
      command('sessions','Inspect durable sessions',[
        command('list','List independent sessions',({options:o},c)=>({items:owner.selected(c).workspace.sessions(number(o.limit,100,1),number(o.offset,2147483647)),offset:o.offset,limit:o.limit}),{permission:Permission.ReadOnly,options:paged}),
        command('status <session>','Inspect saved work and unresolved outcomes',({args,options:o},c)=>{
          const selected=owner.selected(c),session=id(args.session);selected.workspace.session(session);
          if(o.target)return selected.research.status({session,target:id(o.target)});
          return {session,contexts:selected.workspace.contexts(session).map(context=>selected.research.status(context))};
        },{permission:Permission.ReadOnly,options:[{flags:'--target <id>',description:'Inspect one target context'}]}),
      ]),
      command('ghidra','Research through an isolated saved context',[
        command('open [input]','Start independent work or continue a context',async({args,options:o},c)=>{
          if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');
          const selected=owner.selected(c),target=args.input?(await selected.workspace.importTarget(resolve(c.cwd,text(args.input,4096)))).id:id(o.target);
          let previous;
          try{previous=selected.workspace.model(target).settings;}catch(error){if(!String((error as {code?:string}).code).endsWith('.notFound'))throw error;}
          const settings={...previous,autoAnalyze:o.analysis===false?false:previous?.autoAnalyze??true,
            ...(o.language?{language:text(o.language)}:{}),...(o.compilerSpec?{compilerSpec:text(o.compilerSpec)}:{}),
            ...(o.imageBase?{imageBase:text(o.imageBase)}:{})};
          return selected.research.open(target,text(o.session),settings,o.requestId===undefined?undefined:id(o.requestId),mode(o.mode));
        },{permission:Permission.Update,options:[{flags:'--session <id>',description:'Use new for independent work, or an existing session',required:true},
          {flags:'--target <id>',description:'Continue existing input instead of supplying a file'},request,
          {flags:'--mode <mode>',description:'Request headless or gui; continuation preserves current mode'},
          {flags:'--no-analysis',description:'Skip initial automatic analysis'},
          {flags:'--language <id>',description:'Explicit initial loader language'},
          {flags:'--compiler-spec <id>',description:'Explicit initial compiler specification'},
          {flags:'--image-base <address>',description:'Initial image base'}]}),
        command('strings','Read defined strings',[
          command('search','Find literal text and usable addresses',({options:o},c)=>owner.selected(c).research.strings(scope(o),text(o.contains,4096),number(o.limit,100,1),number(o.offset,2147483647)),
            {permission:Permission.ReadOnly,options:[...scoped,{flags:'--contains <text>',description:'Literal case-insensitive substring',required:true},...paged]}),
        ]),
        command('xrefs','Follow cross references',[
          command('to','Find incoming references and their functions',({options:o},c)=>owner.selected(c).research.xrefs(scope(o),address(o.address),number(o.limit,100,1),number(o.offset,2147483647)),
            {permission:Permission.ReadOnly,options:[...scoped,at,...paged]}),
        ]),
        command('functions','Read or name functions',[
          command('get','Read a function and entry comments',({options:o},c)=>owner.selected(c).research.function(scope(o),address(o.address)),{permission:Permission.ReadOnly,options:[...scoped,at]}),
          command('decompile','Read decompiled function text',({options:o},c)=>owner.selected(c).research.function(scope(o),address(o.address),true),{permission:Permission.ReadOnly,options:[...scoped,at]}),
          command('rename','Record a saved private name',({options:o},c)=>{
            const name=text(o.name,512);if(name!==name.trim())fail('invalid','Function name may not have leading or trailing whitespace.');
            return owner.selected(c).research.edit(scope(o),address(o.address),'function.name',name,o.requestId===undefined?undefined:id(o.requestId));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--name <name>',description:'Desired function name',required:true},request]}),
        ]),
        command('comments','Read or edit listing comments',[
          command('get','Read one kind or all five fields',({options:o},c)=>owner.selected(c).research.comment(scope(o),address(o.address),o.kind===undefined?undefined:commentKind(o.kind)),
            {permission:Permission.ReadOnly,options:[...scoped,at,{flags:'--kind <kind>',description:'eol, pre, post, plate or repeatable'}]}),
          command('set','Record a saved private comment or clear it',({options:o},c)=>{
            if(Boolean(o.clear)===(o.text!==undefined))fail('invalid','Supply exactly one --text or --clear.');
            return owner.selected(c).research.edit(scope(o),address(o.address),'comment.'+commentKind(o.kind) as 'comment.eol',
              o.clear?null:scalarText(o.text),o.requestId===undefined?undefined:id(o.requestId));
          },{permission:Permission.Update,options:[...scoped,at,{flags:'--kind <kind>',description:'eol, pre, post, plate or repeatable',required:true},
            {flags:'--text <text>',description:'Desired text; empty text clears to null'},{flags:'--clear',description:'Clear this comment to null'},request]}),
        ]),
      ]),
    ],
  };
}
export const createInsightCli=(options:Options={})=>createCli(createDefinition(options));
