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
import {createHash} from 'node:crypto';

const entry='140001000';
test('decode uses ReadOnly scope and the same bounded native operation over CLI and RPC',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});const calls:unknown[]=[];let saves=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
  const backend=new Fake(workspace);backend.saved=async()=>{saves++;throw Error('Decode must never save');};
  backend.call=async(_s,operation,p={})=>{calls.push({operation,p});return {address:entry,input_bytes:'c3',input_sha256:createHash('sha256').update(Buffer.from('c3','hex')).digest('hex'),instructions:[{address:entry,bytes:'c3',length:1,mnemonic:'RET',operands:[],direct_targets:[],computed_flow:false}],consumed_bytes:1,language:'x86:LE:64:default',stop_reason:'terminal_flow',read_only:{modification_unchanged:true,modification:'1'}};};return backend;
 }}));
 const input=join(f.root,'decode.exe');await writeFile(input,'owned decode');const s=await f.json(app,['ghidra','open',input,'--session','new']) as Opened;
 await f.profileStore.setPermissions('default',['ReadOnly']);const args=['ghidra','functions','decode','--session',s.session,'--target',s.target,'--address',entry,'--max-bytes','1','--max-instructions','1'];
 const result=await f.json(app,args) as any;assert.equal(result.value.consumed_bytes,1);const [rpc]=await f.rpc(app,[args]) as any[];assert.deepEqual(rpc.result,result);assert.equal(saves,0);assert.equal(calls.length,2);assert.deepEqual(calls[0],{operation:'/decode_instructions',p:{address:entry,max_bytes:1,max_instructions:1}});
 for(const option of [['--max-bytes','4097'],['--max-instructions','257']])assert.notEqual((await f.run(app,[...args,...option,'--json'])).exitCode,0);assert.equal(calls.length,2);
});
test('function diagnostics survive one-shot and cli.execute without a mutation or comment read',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let response:unknown,reads=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
  const backend=new Fake(workspace);backend.call=async(_scope,operation)=>{assert.equal(operation,'/get_functions');reads++;return response;};return backend;
 }}));
 const input=join(f.root,'diagnostic.exe');await writeFile(input,'owned diagnostic');const s=await f.json(app,['ghidra','open',input,'--session','new']) as Opened;
 const argv=['ghidra','functions','decompile','--session',s.session,'--target',s.target,'--address',entry];
 const cases:[unknown,string][]=[
  [{functions:{[entry]:{error:'Function not found: no function at or containing that address\u0000'+ 'x'.repeat(600)}}},'function_not_found'],
  [{functions:{[entry]:{error:'Decompiler failed'}}},'native_function_failure'],
  [{functions:{other:{name:'f',entry_point:entry}}},'selector_mismatch'],
  [{functions:{[entry]:null}},'invalid_native_shape'],
  [{functions:{[entry]:{name:'f',entry_point:entry,signature:'void f()'}}},'missing_decompiler_text']
 ];
 for(const [value,reason]of cases){response=value;const one=await f.run(app,[...argv,'--json']);assert.notEqual(one.exitCode,0);const result=JSON.parse(one.stdout);assert.equal(result.reason,reason);assert.equal(result.selector,entry);assert.equal(result.session,s.session);
  if(result.nativeDiagnostic){assert.ok(Array.from(result.nativeDiagnostic).length<=500);assert.ok(!result.nativeDiagnostic.includes('\0'));}
  const [rpc]=await f.rpc(app,[argv]) as any[];assert.equal(rpc.error.data.result.reason,reason);
 }
 assert.equal(reads,cases.length*2);
});

test('bulk function windows preserve mixed outcomes, Unicode hashes, view guards and exact saved files',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let workspace!:Workspace,modification=0,changeDuringRead=false;
 const source='a😀б'.repeat(20),short='return 1;';
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{
  workspace=w;const backend=new Fake(w);backend.call=async(_s,op,p={})=>{assert.equal(op,'/get_functions');if(changeDuringRead)modification++;return {functions:Object.fromEntries(String(p.functions).split(',').map(selector=>[selector,selector==='missing'?{error:'Function not found: fixture'}:{name:selector,entry_point:entry,signature:'void f()',decompiled_code:selector==='short'?short:source,truncation:{decompiled_code:selector==='prefix'}}])),requested:4,count:3};};return Object.assign(backend,{observation:async()=>({modification})});
 }}));
 const input=join(f.root,'bulk.exe');await writeFile(input,'owned bulk');const s=await f.json(app,['ghidra','open',input,'--session','new']) as Opened;
 const args=['ghidra','functions','inspect','--session',s.session,'--target',s.target,'--functions','short,long,missing,prefix','--fields','entry_point,signature,decompiled_code','--limit-chars','4','--total-chars','7'];
 const first=await f.json(app,args) as any;assert.equal(first.value.functions.short.decompiled_code,'retu');assert.equal(first.value.functions.long.decompiled_code,'a😀б');assert.equal(first.value.functions.missing.reason,'function_not_found');assert.equal(first.value.textBudget.returnedCharacters,7);
 const page=await f.json(app,[...args,'--offset-chars','3','--expect-view',first.value.view.identity]) as any;assert.equal(page.value.functions.long.text.textSha256,first.value.functions.long.text.textSha256);
 const directory=join(f.root,'saved');const saved=await f.json(app,[...args,'--save-owner-directory',directory]) as any;assert.ok(!('decompiled_code'in saved.value.functions.long));assert.equal(await readFile(saved.value.functions.long.savedText.file,'utf8'),source);assert.equal(await readFile(saved.value.functions.short.savedText.file,'utf8'),short);assert.equal(JSON.parse(await readFile(join(directory,'manifest.json'),'utf8')).value.view.identity,first.value.view.identity);
 const end=await f.json(app,[...args,'--offset-chars','60']) as any;assert.equal(end.value.functions.prefix.text.sourceTruncated,true);assert.equal(end.value.functions.prefix.text.truncated,true);
 const before=workspace.context(s);workspace.saveContext(s,before.generation,{viewEpoch:1});const changed=await f.run(app,[...args,'--expect-view',first.value.view.identity,'--json']);assert.notEqual(changed.exitCode,0);assert.equal(JSON.parse(changed.stdout).reason,'changed_view');
 assert.notEqual((await f.run(app,[...args,'--fields','invented','--json'])).exitCode,0);
 const single=await f.json(app,['ghidra','functions','inspect','--session',s.session,'--target',s.target,'--function','short','--fields','decompiled_code']) as any;assert.equal(single.value.name,'short');assert.equal(single.value.decompiled_code,short);
 changeDuringRead=true;const raced=await f.run(app,[...args,'--json']);assert.notEqual(raced.exitCode,0);assert.equal(JSON.parse(raced.stdout).reason,'changed_view');
});
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

test('an existing session can first open targets already consumed by another tool through CLI and API',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]}),app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>new Fake(w)}));
 const files=['first.exe','managed.dll','third.exe'].map(name=>join(f.root,name));for(const [i,path]of files.entries())await writeFile(path,'distinct executable '+i);
 const first=await f.json(app,['ghidra','open',files[0]!,'--session','new']) as Opened;
 const second=await f.json(app,['targets','add',files[1]!]) as any,third=await f.json(app,['targets','add',files[2]!]) as any;
 const opened=await f.json(app,['ghidra','open','--target',second.target,'--session',first.session]) as Opened;assert.equal(opened.session,first.session);assert.equal(opened.target,second.target);assert.equal(opened.state,'ready');
 const rpc=await f.rpc(app,[['ghidra','open','--target',third.target,'--session',first.session]]);assert.equal((rpc[0] as any).result.state,'ready');assert.equal((rpc[0] as any).result.session,first.session);
 assert.equal((await f.json(app,['sessions','status',first.session]) as any).contexts.length,3);
});

test('uncertain script save is not retried or adopted; explicit stopped-worker abandonment retains prior work',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});
 let workspace:Workspace,backend:Fake,stopped=false,saves=0,scripts=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{
  workspace=w;backend=new Fake(w);const call=backend.call.bind(backend),saved=backend.saved.bind(backend);
  backend.call=async(s,op,p)=>{if(op==='/run_script_inline'){scripts++;return {success:true,console_output:'fixture completed'};}return call(s,op,p);};
  backend.saved=async s=>{if(scripts){saves++;throw new CliError('Save deadline exceeded',{code:'coordinator.timeout',result:{phase:'save',timeoutMilliseconds:1000}});}return saved(s);};
  return Object.assign(backend,{closed:async()=>stopped,inspect:async()=>({sha256:'fixture'})});
 }}));
 const exe=join(f.root,'save.exe');await writeFile(exe,'synthetic save input');
 const selected=await f.json(app,['ghidra','open',exe,'--session','new']) as Opened;
 const args=['--session',selected.session,'--target',selected.target],before=workspace!.context(selected).workingSnapshot;
 const run=['ghidra','scripts','run-inline',...args,'--code','generic fixture','--request-id','script-save'];
 assert.notEqual((await f.run(app,[...run,'--json'])).exitCode,0);assert.equal(saves,1);assert.equal(scripts,1);
 let request=workspace!.scopedRequest(selected,'script-save')!;assert.equal(request.state,'unknown');assert.equal((request.result as {phase:string}).phase,'save');assert.ok(!(request.result as {savedSnapshot?:unknown}).savedSnapshot);
 assert.notEqual((await f.run(app,[...run,'--json'])).exitCode,0);assert.equal(scripts,1);assert.equal(saves,1);
 const abandon=['ghidra','abandon',...args,'--request-id','script-save'];
 assert.notEqual((await f.run(app,[...abandon,'--json'])).exitCode,0);
 assert.notEqual((await f.run(app,[...abandon,'--acknowledge-unknown-effects','--json'])).exitCode,0);
 stopped=true;backend!.views.clear();const result=await f.json(app,[...abandon,'--acknowledge-unknown-effects']) as {state:string;outcome:string};
 assert.equal(result.state,'abandoned');assert.equal(result.outcome,'unknown');assert.deepEqual(workspace!.context(selected).workingSnapshot,before);
 assert.deepEqual(await f.json(app,[...abandon,'--acknowledge-unknown-effects']),result);
 request=workspace!.scopedRequest(selected,'script-save')!;assert.equal(request.state,'failed');assert.ok((request.result as {previousResult:unknown}).previousResult);
 assert.notEqual((await f.run(app,[...run,'--json'])).exitCode,0);assert.equal(scripts,1);assert.equal(saves,1);
 assert.equal((await f.json(app,['ghidra','open',...args]) as Opened).state,'ready');assert.deepEqual(workspace!.context(selected).workingSnapshot,before);
});

test('native budget settings can change after a failed import without invalidating saved research or its intent',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update'],values:{java:'fixture-runtime',initialImportSeconds:1}}]});let attempts=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{
  const backend=new Fake(w),open=backend.open.bind(backend);backend.open=async(s,request)=>{if(attempts++===0)throw Error('Interrupted native import');return open(s,request);};return Object.assign(backend,{recoverModel:async()=>true});
 }}));
 const exe=join(f.root,'budget.exe');await writeFile(exe,'budget recovery input');
 const open=['ghidra','open',exe,'--session','new','--request-id','budget-open'];
 const interrupted=await f.run(app,[...open,'--json']);assert.notEqual(interrupted.exitCode,0);const retained=JSON.parse(interrupted.stdout);
 const configured=await f.json(app,['ghidra','budgets','set','--initial-import-seconds','7200','--save-seconds','300']) as {initialImportSeconds:number;saveSeconds:number};
 assert.equal(configured.initialImportSeconds,7200);assert.equal(configured.saveSeconds,300);
 assert.equal((await f.profileStore.get('default')).values.java,'fixture-runtime');assert.deepEqual(await f.profileStore.getPermissions('default'),['ReadOnly','Update']);
 const ready=await f.json(app,open) as Opened;assert.equal(ready.session,retained.session);assert.equal(ready.target,retained.target);assert.equal(ready.state,'ready');
 assert.deepEqual(await f.json(app,open),ready);
 const shown=await f.json(app,['ghidra','budgets','show']) as {initialImportSeconds:number};assert.equal(shown.initialImportSeconds,7200);
 assert.notEqual((await f.run(app,['ghidra','budgets','set','--save-seconds','0','--json'])).exitCode,0);
 assert.equal((await f.profileStore.get('default')).values.saveSeconds,300);
 await Promise.all([f.json(app,['ghidra','budgets','set','--initial-import-seconds','1800']),f.json(app,['ghidra','budgets','set','--save-seconds','60'])]);
 const concurrent=await f.profileStore.get('default');assert.equal(concurrent.values.initialImportSeconds,1800);assert.equal(concurrent.values.saveSeconds,60);assert.equal(concurrent.values.java,'fixture-runtime');
});
