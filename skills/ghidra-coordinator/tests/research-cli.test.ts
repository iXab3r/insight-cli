import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {join} from 'node:path';
import {writeFile,readFile,stat} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {createInsightCli} from '../src/cli.js';
import {Workspace,type Scope} from '../src/workspace.js';
import {type ResearchBackend} from '../src/research.js';
import {address} from '../src/research.js';
import type {ToolMode} from '../src/contexts.js';
import {CliError} from '@eyeauras/cli-factory';

const entry='140001000';
interface View {name:string;comments:Record<string,string|null>}
const empty=():View=>({name:'first',comments:{eol:null,pre:null,post:null,plate:null,repeatable:null}});
class Fake implements ResearchBackend {
  views=new Map<string,View>();modes=new Map<string,ToolMode>();calls=0;edits=0;partial=false;lose=false;
  constructor(private workspace:Workspace){}
  private view(scope:Scope){return this.views.get(this.workspace.context(scope).id)!;}
  private async snapshot(value:View){const path=join(this.workspace.directory,'fixture-'+randomUUID()+'.gzf');await writeFile(path,JSON.stringify(value));return this.workspace.captureSnapshot(path);}
  async open(scope:Scope,request?:string){
    if(this.workspace.unresolved(scope).some(item=>item.id!==request))throw Error('Unresolved fixture effect');
    let context=this.workspace.context(scope);if(this.views.has(context.id))return context;
    let model=this.workspace.model(scope.target);
    if(!model.sharedSnapshot){const snapshot=await this.snapshot(empty());model=this.workspace.establishModel(scope.target,1,snapshot);}
    const saved=context.workingSnapshot??model.sharedSnapshot!;
    this.views.set(context.id,JSON.parse(await readFile(await this.workspace.artifacts.verify(saved),'utf8')));
    this.modes.set(context.id,'headless');
    context=this.workspace.saveContext(scope,context.generation,{state:'ready',baseRevision:context.baseRevision??model.sharedRevision!,
      baseSnapshot:context.baseSnapshot??model.sharedSnapshot!,workingSnapshot:saved});return context;
  }
  async call(scope:Scope,operation:string,parameters:Record<string,unknown>={}):Promise<unknown>{
    this.calls++;const view=this.view(scope),at=String(parameters.address??parameters.functions??entry);
    if(operation==='/get_program_options')return {};
    if(operation==='/get_comment')return {address:at,...view.comments};
    if(operation==='/get_functions')return {functions:{[at]:{name:view.name,entry_point:entry,signature:'int '+view.name+'(int x)',
      ...(String(parameters.fields).includes('decompiled_code')?{decompiled_code:'int '+view.name+'(int x) { return x + 17; }'}:{})}}};
    if(operation==='/search_strings')return {matches:[{address:'140008000',value:'config.json'}],total:1,offset:parameters.offset,limit:parameters.limit};
    if(operation==='/get_xrefs_to')return {references:[{from_address:entry,type:'DATA',from_function:view.name}],count:1,total:1,offset:parameters.offset,limit:parameters.limit};
    if(operation==='/set_comment'||operation==='/rename_function'){
      this.edits++;if(!this.partial){if(operation==='/set_comment')view.comments[String(parameters.type)]=parameters.comment===''?null:String(parameters.comment);
        else view.name=String(parameters.new_name);}
      if(this.lose)throw Error('Synthetic response lost after local effect');return {status:'success'};
    }
    throw Error('Unsupported fixture operation');
  }
  async saved(scope:Scope){return this.snapshot(this.view(scope));}
  async mode(scope:Scope,mode:ToolMode){this.modes.set(this.workspace.context(scope).id,mode);}
  async close(scope:Scope){const context=this.workspace.context(scope);this.workspace.saveContext(scope,context.generation,{state:'stopped',workingSnapshot:await this.saved(scope)});this.views.delete(context.id);}
  async dispose(){this.views.clear();}
}
type Opened={session:string;target:string;state:string};
test('xref traversal preserves external-entry metadata and navigable references',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
 let malformed=false;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
  const backend=new Fake(workspace),call=backend.call.bind(backend);
  backend.call=async(scope,operation,parameters={})=>operation==='/get_xrefs_to'?{
   references:[{from_address:'Entry Point',type:malformed?'DATA':'EXTERNAL'},{from_address:entry,type:'DATA',from_function:'first'}],
   count:2,total:2,offset:parameters.offset,limit:parameters.limit}:call(scope,operation,parameters);
  return backend;
 }}));
 const exe=join(f.root,'export.exe');await writeFile(exe,'exported fixture');
 const scope=await f.json(app,['ghidra','open',exe,'--session','new']) as Opened;
 const args=['ghidra','xrefs','to','--session',scope.session,'--target',scope.target,'--address','140008000'];
 const found=await f.json(app,args) as {items:unknown[];total:number};
 assert.equal(found.total,2);assert.deepEqual(found.items,[{from:null,to:'0x140008000',kind:'EXTERNAL',source:'entry-point'},
  {from:'0x'+entry,to:'0x140008000',kind:'DATA',function:{address:'0x'+entry,name:'first'}}]);
 malformed=true;assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);
});
test('reconciled first open returns the public ready envelope and preserves its original scope',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let attempts=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
   const backend=new Fake(workspace),open=backend.open.bind(backend);
   backend.open=async(selected,request)=>{if(attempts++===0)throw Error('Interrupted initial import');return open(selected,request);};
   return Object.assign(backend,{recoverModel:async()=>true});
 }}));
 const exe=join(f.root,'resume.exe');await writeFile(exe,'synthetic interrupted input');
 const args=['ghidra','open',exe,'--session','new','--request-id','resume'];
 const first=await f.run(app,[...args,'--json']);assert.notEqual(first.exitCode,0);const retained=JSON.parse(first.stdout);
 const ready=await f.json(app,args) as Opened;assert.equal(ready.session,retained.session);assert.equal(ready.target,retained.target);assert.equal(ready.state,'ready');
 assert.deepEqual(Object.keys(ready).sort(),['session','target','state','baseRevision','sharedRevision','pendingChanges'].sort());
 assert.deepEqual(await f.json(app,args),ready);assert.equal(attempts,2);
});
test('failed initial open exposes retained scope and continuation; retry is nonzero without reimport',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let attempts=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
   const backend=new Fake(workspace);backend.open=async()=>{attempts++;throw new CliError('Ghidra request /import_file exceeded 600 seconds.',{code:'coordinator.timeout',result:{operation:'/import_file',timeoutMilliseconds:600000}});};
   return Object.assign(backend,{recoverModel:async()=>false});
 }}));
 const exe=join(f.root,'slow.exe');await writeFile(exe,'synthetic slow import');
 const args=['ghidra','open',exe,'--session','new','--request-id','slow-open','--json'];
 const failed=await f.run(app,args);assert.notEqual(failed.exitCode,0);
 const result=JSON.parse(failed.stdout) as Opened&{requestId:string;detail:{operation:string}};
 assert.match(result.session,/^s_/);assert.match(result.target,/^t_/);assert.equal(result.state,'unknown');assert.equal(result.requestId,'slow-open');assert.equal(result.detail.operation,'/import_file');
 assert.match(failed.stderr,/sessions.*status/);assert.match(failed.stderr,/ghidra.*open/);
 const retried=await f.run(app,args);assert.notEqual(retried.exitCode,0);assert.equal(JSON.parse(retried.stdout).session,result.session);assert.equal(attempts,1);
});
test('public help and skill are local; missing selectors and permissions reject before input or native state',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli'});let started=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{started++;return new Fake(workspace);}}));
  assert.match((await f.run(app,['--help'])).stdout,/ghidra/);
  const skill=await f.json(app,['skill']) as {path:string};assert.ok(skill.path.endsWith('SKILL.md'));
  await assert.rejects(stat(f.appArguments.AppDataDirectory));
  const denied=await f.run(app,['ghidra','open','missing.exe','--session','new','--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);
  const missing=await f.run(app,['ghidra','functions','get','--session','s_missing','--address',entry,'--json']);assert.notEqual(missing.exitCode,0);assert.match(missing.stderr,/target/);
  await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'workspace')));assert.equal(started,0);
});

test('CLI/API walkthrough preserves isolated scopes, normal edits, clear/null and installed-style reconnect',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>new Fake(workspace)}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'synthetic input');
  const a=await f.json(app,['ghidra','open',exe,'--session','new','--request-id','open-A']) as Opened;
  const b=await f.json(app,['ghidra','open',exe,'--session','new']) as Opened;
  assert.equal(a.target,b.target);assert.notEqual(a.session,b.session);assert.equal(a.state,'ready');
  assert.deepEqual(await f.json(app,['ghidra','open',exe,'--session','new','--request-id','open-A']),a);
  const selectors=['--session',a.session,'--target',a.target];
  const strings=await f.json(app,['ghidra','strings','search',...selectors,'--contains','config.json','--limit','10']) as {session:string;items:{address:string}[]};
  assert.equal(strings.session,a.session);assert.equal(strings.items[0]?.address,'0x140008000');
  const xrefs=await f.json(app,['ghidra','xrefs','to',...selectors,'--address',strings.items[0]!.address]) as {items:{function:{address:string}}[]};
  const at=xrefs.items[0]!.function.address;assert.equal(at,'0x'+entry);
  await f.json(app,['ghidra','functions','rename',...selectors,'--address',at,'--name','LoadConfig']);
  await f.json(app,['ghidra','comments','set',...selectors,'--address',at,'--kind','eol','--text','Private A']);
  const replies=await f.rpc(app,[['ghidra','functions','get',...selectors,'--address',at],
    ['ghidra','comments','get','--session',b.session,'--target',b.target,'--address',at,'--kind','eol']]) as {result:{session:string;target:string;name?:string;comments?:{eol:string};text?:string|null}}[];
  assert.equal(replies[0]!.result.name,'LoadConfig');assert.equal(replies[0]!.result.comments?.eol,'Private A');
  assert.equal(replies[1]!.result.text,null);assert.equal(replies[1]!.result.session,b.session);
  const decompiled=await f.json(app,['ghidra','functions','decompile',...selectors,'--address',at]) as {code:string};assert.match(decompiled.code,/LoadConfig/);
  await f.json(app,['ghidra','comments','set',...selectors,'--address',at,'--kind','eol','--clear']);
  assert.equal((await f.json(app,['ghidra','comments','get',...selectors,'--address',at,'--kind','eol']) as {text:unknown}).text,null);
  const status=await f.json(app,['sessions','status',a.session,'--target',a.target]) as {ghidra:{pendingChanges:number}};
  assert.equal(status.ghidra.pendingChanges,1,'Clear back to original must remove that pending field');
  const resumed=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>new Fake(workspace)}));
  const after=await f.json(resumed,['ghidra','functions','get',...selectors,'--address',at]) as {name:string};assert.equal(after.name,'LoadConfig');
  const helper=join(f.root,'helper.exe');await writeFile(helper,'another owned input');
  const ah=await f.json(app,['ghidra','open',helper,'--session',a.session]) as Opened;
  const page=await f.json(app,['sessions','status',a.session,'--limit','1','--offset','1']) as {contexts:{target:string}[];offset:number;truncated:boolean};
  assert.equal(page.contexts.length,1);assert.equal(page.contexts[0]!.target,ah.target);assert.equal(page.offset,1);assert.equal(page.truncated,true);
  assert.equal((await f.json(app,['sessions','status',a.session,'--limit','1','--offset','2']) as {truncated:boolean}).truncated,false);
});

test('request ID distinguishes mode and normalized input; duplicate changing requests execute once',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let fake:Fake;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(fake=new Fake(workspace))}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'synthetic input');
  const opened=await f.json(app,['ghidra','open',exe,'--session','new','--mode','headless','--request-id','open']) as Opened;
  const wrongMode=await f.run(app,['ghidra','open',exe,'--session','new','--mode','gui','--request-id','open','--json']);
  assert.notEqual(wrongMode.exitCode,0);assert.match(wrongMode.stderr,/different effective input/);
  const args=['ghidra','comments','set','--session',opened.session,'--target',opened.target,'--address','0x'+entry,'--kind','eol','--text','once','--request-id','set-1'];
  const [one,two]=await Promise.all([f.json(app,args),f.json(app,args)]);assert.deepEqual(one,two);assert.equal(fake!.edits,1);
  const bad=await f.run(app,[...args.slice(0,-3),'different','--request-id','set-1','--json']);assert.notEqual(bad.exitCode,0);
  assert.equal(fake!.edits,1);
});

test('partial or lost editing response stays unresolved and retry never repeats the mutation',async t=>{
  for(const failure of ['partial','lose'] as const){
    const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let fake:Fake;
    const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(fake=new Fake(workspace))}));
    const exe=join(f.root,failure+'.exe');await writeFile(exe,'synthetic '+failure);
    const opened=await f.json(app,['ghidra','open',exe,'--session','new']) as Opened;fake![failure]=true;
    const args=['ghidra','comments','set','--session',opened.session,'--target',opened.target,'--address',entry,'--kind','eol','--text','uncertain','--request-id','uncertain'];
    const failed=await f.run(app,[...args,'--json']);assert.notEqual(failed.exitCode,0);
    const retry=await f.json(app,args) as {state:string};assert.equal(retry.state,'unknown');assert.equal(fake!.edits,1);
    const status=await f.json(app,['sessions','status',opened.session,'--target',opened.target]) as {ghidra:{state:string;unresolvedRequests:unknown[]}};
    assert.equal(status.ghidra.state,'needs_recovery');assert.equal(status.ghidra.unresolvedRequests.length,1);
  }
});

test('address parsing preserves named spaces and rejects ambiguous non-hex input',()=>{
  assert.equal(address('EXTERNAL:00AB'),'EXTERNAL:ab');assert.equal(address('0x0000ab'),'ab');
  assert.throws(()=>address('current'));assert.throws(()=>address('ram:xyz'));
});

test('continuation inherits original loader settings and negated analysis option is effective',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let workspace:Workspace;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:stored=>{workspace=stored;return new Fake(stored);}}));
  const exe=join(f.root,'raw.bin');await writeFile(exe,'synthetic raw bytes');
  const opened=await f.json(app,['ghidra','open',exe,'--session','new','--no-analysis','--language','ARM:LE:32:default']) as Opened;
  assert.equal(workspace!.model(opened.target).settings.autoAnalyze,false);
  const continued=await f.json(app,['ghidra','open','--session',opened.session,'--target',opened.target]) as Opened;
  assert.equal(continued.session,opened.session);assert.equal(continued.state,'ready');
  assert.equal(workspace!.model(opened.target).settings.language,'ARM:LE:32:default');
});
