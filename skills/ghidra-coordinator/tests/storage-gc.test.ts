import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,mkdir,link,access,readdir,symlink,utimes}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{randomUUID}from'node:crypto';
import{Workspace,type GhidraContext}from'../src/workspace.js';import{collectStorage,type CollectionPort}from'../src/storage-gc.js';
import{GhidraContexts}from'../src/contexts.js';import type{NativeInputs}from'../src/native-inputs.js';import type{CommandContext}from'@eyeauras/cli-factory';
import{createCliFixture}from'@eyeauras/cli-factory/testing';import{createInsightCli}from'../src/cli.js';import{SessionBackend}from'./fixtures/session-backend.js';
const exists=(path:string)=>access(path).then(()=>true,()=>false);
async function fixture(t:test.TestContext){
 const root=await mkdtemp(join(tmpdir(),'storage-gc-')),workspace=new Workspace(join(root,'workspace'),'default');t.after(()=>workspace.close());
 const input=join(root,'input.bin');await writeFile(input,'owned gc fixture');const target=await workspace.importTarget(input);
 const snapshot=async(text:string)=>{const path=join(root,randomUUID());await writeFile(path,text);return workspace.captureSnapshot(path);};
 const base=await snapshot('base'),working=await snapshot('working');
 const open=()=>{const {context,request}=workspace.reserveOpen(target.id,'new',{autoAnalyze:false});workspace.recordRequest(request.id,'failed',{state:'not_opened'});
  return workspace.saveContext(context,context.generation,{state:'stopped',baseRevision:1,baseSnapshot:base,workingSnapshot:working});};
 const context=open();workspace.establishModel(target.id,1,base);
 /** One abandoned detached working root as the superseded engine left it. */
 const stage=async(owner:GhidraContext,options:{stopped?:boolean;pid?:number;programs?:number;native?:boolean;mode?:string;reason?:string;kind?:string}={})=>{
  const at=join(workspace.directory,'ghidra-native',options.kind??'context',options.kind?owner.target:owner.id,randomUUID()),pid=options.pid??999999;
  await mkdir(join(at,'view.rep','idata','00'),{recursive:true});await mkdir(join(at,'exports'));await mkdir(join(at,'ghidra'));
  await writeFile(join(at,'process.json'),JSON.stringify({pid,tokenSecret:'owned',mode:options.mode??'headless',kind:options.kind??'context',...(options.kind?{}:{context:owner.id}),target:owner.target}));
  if(options.stopped!==false)await writeFile(join(at,'stopped.json'),JSON.stringify({pid,tokenSecret:'owned',reason:options.reason??'explicit_close'}));
  if(options.native)await writeFile(join(at,'native-owner.json'),'{}');
  for(let i=0;i<(options.programs??1);i++)await writeFile(join(at,'view.rep','idata','00','0000000'+i+'.prp'),'program');
  await writeFile(join(at,'view.rep','idata','00','db.1.gbf'),'database');await writeFile(join(at,'view.gpr'),'');
  await writeFile(join(at,'exports','saved-'+randomUUID()+'.gzf'),'duplicate');await writeFile(join(at,'exports','user-notes.txt'),'user output');
  await writeFile(join(at,'ghidra','ghidra1.cache'),'cache');await writeFile(join(at,'runtime.log'),'log');
  await link(await workspace.artifacts.verify(owner.workingSnapshot!),join(at,'saved.gzf'));return at;
 };
 const released:string[]=[];
 const port:CollectionPort={closed:async()=>true,release:async c=>{released.push(c.id);return true;}};
 return {root,workspace,target,context,base,working,snapshot,stage,open,port,released};
}
async function request(f:Awaited<ReturnType<typeof fixture>>,state:'applied'|'unknown'|'failed',before:unknown,result:unknown){
 const r=f.workspace.reserveRequest(f.context,'/set_function_prototype',{name:randomUUID()}).request;f.workspace.startRequest(r.id,{kind:'program',workingSnapshot:before});
 if(state==='applied')f.workspace.completeSavedRequest(f.context,r.id,f.workspace.context(f.context).generation,{},result);else f.workspace.recordRequest(r.id,state,result);
 return r;
}
test('superseded before-images, duplicate exports and stopped detached projects are reclaimed; live views and user output stay',async t=>{
 const f=await fixture(t),old=await f.snapshot('superseded before-image'),shown=await f.snapshot('reported to the caller'),stage=await f.stage(f.context);
 await request(f,'applied',old,{state:'applied'});await request(f,'applied',f.working,{discardedSnapshot:shown});
 const before=await readdir(stage),planned=await collectStorage(f.workspace,f.port,true);
 assert.equal(planned.state,'planned');assert.deepEqual(await readdir(stage),before);assert.ok(await exists(f.workspace.artifacts.path(old)));
 assert.equal(await exists(join(f.workspace.directory,'gc')),false);
 const done=await collectStorage(f.workspace,f.port,false);assert.equal(done.bytes,planned.bytes);assert.deepEqual(done.categories,planned.categories);
 assert.equal(await exists(f.workspace.artifacts.path(old)),false);await f.workspace.artifacts.verify(shown);await f.workspace.artifacts.verify(f.working);await f.workspace.artifacts.verify(f.base);await f.workspace.artifacts.verify(f.target.input);
 for(const gone of ['view.rep','view.gpr','saved.gzf','ghidra/ghidra1.cache'])assert.equal(await exists(join(stage,gone)),false,gone);
 for(const kept of ['process.json','stopped.json','runtime.log','exports/user-notes.txt'])assert.ok(await exists(join(stage,kept)),kept);
 assert.deepEqual(await readdir(join(stage,'exports')),['user-notes.txt']);
 const again=await collectStorage(f.workspace,f.port,false);assert.equal(again.bytes,0);assert.deepEqual(again.categories,{});
 const receipt=JSON.parse(await readFile(join(f.workspace.directory,'gc',(done as {id:string}).id+'.json'),'utf8'));assert.equal(receipt.state,'complete');
});
test('hard links are counted only when their last name is removed',async t=>{
 const f=await fixture(t);await f.stage(f.context);const planned=await collectStorage(f.workspace,f.port,true);
 assert.equal(planned.categories['duplicate-exports']!.bytes,'duplicate'.length);
});
const uncertain:Record<string,(f:Awaited<ReturnType<typeof fixture>>)=>Promise<void>>={
 'unresolved operation':async f=>{await request(f,'unknown',f.working,{state:'unknown'});},
 'abandoned unknown effect':async f=>{await request(f,'failed',f.working,{outcome:'unknown'});},
 'debugger traces':async f=>{const c=f.workspace.context(f.context);f.workspace.saveContext(c,c.generation,{debugger:{connected:false,traces:[{id:'trace_'+randomUUID(),name:'t',snapshot:f.working,snap:'0',modules:0,threads:0,connected:false}]}} as never);},
 'unproved worker':async f=>{f.port.closed=async()=>false;},
 'changed worker receipt':async f=>{f.port.closed=async()=>{throw Error('moved');};},
 'damaged private snapshot':async f=>{f.workspace.artifacts.verify=async()=>{throw Error('changed');};},
};
for(const [name,prepare] of Object.entries(uncertain))test('context with '+name+' keeps its working root',async t=>{
 const f=await fixture(t),stage=await f.stage(f.context),before=await readdir(stage);await prepare(f);
 const result=await collectStorage(f.workspace,f.port,false);assert.deepEqual(await readdir(stage),before);assert.ok(result.retained.some(r=>r.path.endsWith(f.context.id)));
 assert.ok(await exists(f.workspace.artifacts.path(f.working)));assert.deepEqual(f.released,[]);
});
test('unknown and failed intents keep their complete snapshot evidence',async t=>{
 const f=await fixture(t),unknown=await f.snapshot('unknown before'),failed=await f.snapshot('failed before');
 await request(f,'failed',failed,{state:'rejected'});await request(f,'unknown',unknown,{state:'unknown'});await collectStorage(f.workspace,f.port,false);
 await f.workspace.artifacts.verify(unknown);await f.workspace.artifacts.verify(failed);
});
test('live workers, extra project files, foreign receipts and native checkout roots are retained',async t=>{
 const f=await fixture(t),live=await f.stage(f.context,{stopped:false,pid:process.pid}),many=await f.stage(f.context,{programs:2}),native=await f.stage(f.context,{native:true}),foreign=await f.stage(f.context);
 await writeFile(join(foreign,'process.json'),JSON.stringify({pid:999999,tokenSecret:'owned',kind:'context',context:'c_other',target:f.target.id}));
 await collectStorage(f.workspace,f.port,false);
 for(const root of [live,many,native,foreign])assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')),root);
 assert.ok(await exists(join(live,'saved.gzf')));assert.ok(await exists(join(foreign,'saved.gzf')));
});
async function nativeContext(f:Awaited<ReturnType<typeof fixture>>,local:string,baseFingerprint:string){
 const c=f.open(),root=join(f.workspace.directory,'ghidra-native','context',c.id,'w-owned');await mkdir(join(root,'view.rep'),{recursive:true});await writeFile(join(root,'view.rep','db.gbf'),'native database');await writeFile(join(root,'native-owner.json'),'{}');
 const receipt=async(v:unknown)=>{const p=join(f.root,randomUUID());await writeFile(p,JSON.stringify(v));return f.workspace.captureNative(p);};
 return f.workspace.saveContext(c,c.generation,{baseSnapshot:await receipt({source:'server',fingerprint:baseFingerprint}),workingSnapshot:await receipt({source:'checkout',fingerprint:local}),
  nativeCheckout:{schema:1,context:c.id,root,fileId:'file',checkoutId:3,baseVersion:1,origin:'ghidra://127.0.0.1:1',repository:'owned',path:'/'+f.target.id+'.bin',runtimeFingerprint:'d'.repeat(64),state:'active'}});
}
test('clean native checkouts are only released through native verification; dirty or refused ones stay',async t=>{
 const f=await fixture(t),clean=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),refused=await nativeContext(f,'a'.repeat(64),'a'.repeat(64));
 const dirty=await nativeContext(f,'b'.repeat(64),'a'.repeat(64));f.workspace.saveContext(dirty,dirty.generation,{complexChanges:['q_'+randomUUID()]});
 const planned=await collectStorage(f.workspace,f.port,true);assert.deepEqual(f.released,[]);assert.equal(planned.categories['native-checkouts']!.items,2);
 f.port.release=async c=>{if(c.id===refused.id)throw Error('server unavailable');f.released.push(c.id);return true;};
 const done=await collectStorage(f.workspace,f.port,false);assert.deepEqual(f.released,[clean.id]);assert.equal(done.categories['native-checkouts']!.items,1);
 for(const c of [clean,refused,dirty])assert.ok(await exists(join(c.nativeCheckout!.root,'view.rep','db.gbf')));
 assert.ok(done.retained.some(r=>r.reason.includes('server unavailable')));
});
test('collection requires Destructive only for execution',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly']}]});const calls:boolean[]=[];
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{collect:async(dryRun:boolean)=>{calls.push(dryRun);return{state:'planned'}}})}));
 const refused=await f.run(app,['ghidra','gc','--json']);assert.equal(refused.exitCode,1);assert.match(refused.stderr,/Destructive/);assert.deepEqual(calls,[]);
 assert.equal((await f.json(app,['ghidra','gc','--dry-run']) as {state:string}).state,'planned');assert.deepEqual(calls,[true]);
});
for(const outcome of ['released','retained','refused'] as const)test('close reports an unchanged checkout as '+outcome+' without changing the close outcome',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{releaseUnchanged:async()=>{if(outcome==='refused')throw Error('native refusal');return outcome==='released';}})}));
 const input=join(f.root,'owned.bin');await writeFile(input,'close fixture');const s=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string};
 const closed=await f.json(app,['ghidra','close','--session',s.session,'--target',s.target]) as {state:string;checkout:string};
 assert.equal(closed.state,'closed');assert.equal(closed.checkout,outcome==='released'?'released':'retained');
});

test('a project without proof that its last save was captured is retained',async t=>{
 const f=await fixture(t),crashed=await f.stage(f.context,{stopped:false}),gui=await f.stage(f.context,{mode:'gui',reason:'owner_dispose'}),closedGui=await f.stage(f.context,{mode:'gui'});
 const dispose=await f.stage(f.context,{reason:'owner_dispose'});
 const result=await collectStorage(f.workspace,f.port,false);
 for(const root of [crashed,gui]){assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')),root);assert.ok(result.retained.some(r=>r.path===join(root,'view.rep')));}
 for(const root of [closedGui,dispose])assert.equal(await exists(join(root,'view.rep')),false);
});
test('a context without a saved or migrated view keeps its project',async t=>{
 const f=await fixture(t),stage=await f.stage(f.context);f.workspace.saveContext(f.context,f.workspace.context(f.context).generation,{workingSnapshot:undefined,baseSnapshot:undefined,baseRevision:undefined});
 await collectStorage(f.workspace,f.port,false);assert.ok(await exists(join(stage,'view.rep')));
 const journal=join(f.workspace.directory,'legacy-migrations',f.target.id);await mkdir(journal,{recursive:true});await writeFile(join(journal,f.context.id+'-detached.json'),'{}');
 await collectStorage(f.workspace,f.port,false);assert.equal(await exists(join(stage,'view.rep')),false);
});
test('candidates of a target with an unsettled context keep their merge evidence',async t=>{
 const f=await fixture(t),candidate=await f.stage(f.context,{kind:'candidate'}),shared=await f.stage(f.context,{kind:'shared'});
 const r=f.workspace.reserveRequest(f.context,'ghidra.merge',{}).request;f.workspace.startRequest(r.id);f.workspace.recordRequest(r.id,'unknown',{state:'unknown'});
 await collectStorage(f.workspace,f.port,false);
 assert.ok(await exists(join(candidate,'view.rep')));assert.equal((await readdir(join(candidate,'exports'))).length,2);assert.equal(await exists(join(shared,'view.rep')),false);
});
test('a checkout referenced by another unresolved operation is not released',async t=>{
 const f=await fixture(t),a=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),b=f.open();
 const path=join(f.root,randomUUID());await writeFile(path,JSON.stringify({source:'checkout',checkout:a.nativeCheckout}));const receipt=await f.workspace.captureNative(path);
 const r=f.workspace.reserveRequest(b,'/merge_program_documentation',{}).request;f.workspace.startRequest(r.id,{kind:'transfer',sourceSnapshot:receipt});f.workspace.recordRequest(r.id,'unknown',{});
 assert.equal(f.workspace.checkoutReferenced(a),true);const result=await collectStorage(f.workspace,f.port,false);
 assert.deepEqual(f.released,[]);assert.ok(result.retained.some(x=>x.path===a.nativeCheckout!.root));
 f.workspace.recordRequest(r.id,'failed',{});assert.equal(f.workspace.checkoutReferenced(a),false);
});
test('linked owned subdirectories are never followed',async t=>{
 const f=await fixture(t),stage=await f.stage(f.context),outside=join(f.root,'outside');await mkdir(outside);await writeFile(join(outside,'shared.gzf'),'foreign');
 const root=join(f.workspace.directory,'ghidra-native','context',f.context.id,randomUUID());await mkdir(root);
 await writeFile(join(root,'process.json'),await readFile(join(stage,'process.json')));await writeFile(join(root,'stopped.json'),await readFile(join(stage,'stopped.json')));
 await symlink(outside,join(root,'exports'),'junction');await collectStorage(f.workspace,f.port,false);assert.equal(await readFile(join(outside,'shared.gzf'),'utf8'),'foreign');
});
test('recent pending captures are left to their owner; stale ones are reclaimed',async t=>{
 const f=await fixture(t),at=join(f.workspace.directory,'artifacts'),fresh=join(at,'pending-'+randomUUID()),stale=join(at,'pending-'+randomUUID()),unrowed=join(at,'c'.repeat(64)+'.gzf');
 for(const path of [fresh,stale,unrowed])await writeFile(path,'capture');await utimes(stale,new Date(0),new Date(0));
 await collectStorage(f.workspace,f.port,false);assert.ok(await exists(fresh));assert.ok(await exists(unrowed));assert.equal(await exists(stale),false);
});
test('version-tracking owners and unfinished publications root their snapshots',async t=>{
 const f=await fixture(t),vt=await f.snapshot('vt'),published=await f.snapshot('published');
 const at=join(f.workspace.directory,'version-tracking','v_owned');await mkdir(at,{recursive:true});await writeFile(join(at,'owner.json'),JSON.stringify({source:vt}));
 await collectStorage(f.workspace,f.port,false);await f.workspace.artifacts.verify(vt);assert.equal(await exists(f.workspace.artifacts.path(published)),false);
});
test('native release verifies Ghidra status, local files, recovery data and uncertainty before disposal',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),path=join(f.root,randomUUID());
 await writeFile(path,JSON.stringify({source:'server',version:1,fileId:'file',fingerprint:'a'.repeat(64)}));const base=await f.workspace.captureNative(path);
 const current=f.workspace.saveContext(c,f.workspace.context(c).generation,{baseSnapshot:base});
 const backend=new GhidraContexts(f.workspace,{} as NativeInputs,{} as CommandContext);let closed=true;const operations:string[]=[];
 const clean={state:'ready',checkedOut:true,modified:false,recoverable:false,fileId:'file',checkoutId:3,baseVersion:1,saved:{fingerprint:'a'.repeat(64)},projectFiles:[c.target+'.bin']};
 let observed:Record<string,unknown>=clean;
 Object.assign(backend,{closed:async()=>closed,nativeOperation:async(_c:unknown,op:string)=>{operations.push(op);return op==='status'?observed:{state:op==='release'?'released':'dropped'};}});
 for(const changed of [{modified:true},{recoverable:true},{recoverable:undefined},{checkoutId:4},{baseVersion:2},{checkedOut:false},{state:'unknown'},{saved:{fingerprint:'b'.repeat(64)}},{projectFiles:[c.target+'.bin','Traces/owned']},{projectFiles:undefined}]){
  observed={...clean,...changed};assert.equal(await backend.releaseUnchanged(c),false,JSON.stringify(changed));
 }
 observed=clean;closed=false;assert.equal(await backend.releaseUnchanged(c),false);closed=true;
 const r=f.workspace.reserveRequest(c,'debugger.launch',{}).request;f.workspace.startRequest(r.id);f.workspace.recordRequest(r.id,'failed',{outcome:'unknown'});
 assert.equal(await backend.releaseUnchanged(c),false);assert.ok(operations.every(op=>op==='status'));
 f.workspace.uncertainOutcome=()=>false;operations.length=0;
 assert.equal(await backend.releaseUnchanged(c),true);assert.deepEqual(operations,['status','release','drop']);
 assert.equal(f.workspace.context(current).nativeCheckout!.state,'dropped');assert.equal(await backend.releaseUnchanged(c),false);
});
test('an interrupted disposal stays verified and resumes on the next release',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),path=join(f.root,randomUUID());
 await writeFile(path,JSON.stringify({source:'server',version:1,fileId:'file',fingerprint:'a'.repeat(64)}));const base=await f.workspace.captureNative(path);
 f.workspace.saveContext(c,f.workspace.context(c).generation,{baseSnapshot:base,workingSnapshot:base,nativeCheckout:{...c.nativeCheckout!,state:'verified'}});
 const backend=new GhidraContexts(f.workspace,{} as NativeInputs,{} as CommandContext);let drop='unknown';
 Object.assign(backend,{closed:async()=>true,nativeOperation:async(_c:unknown,op:string)=>({state:op==='release'?'released':drop})});
 await assert.rejects(backend.releaseUnchanged(c),/deletion remains unproved/);assert.equal(f.workspace.context(c).nativeCheckout!.state,'verified');
 drop='dropped';assert.equal(await backend.releaseUnchanged(c),true);assert.equal(f.workspace.context(c).nativeCheckout!.state,'dropped');
});
