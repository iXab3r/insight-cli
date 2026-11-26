import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile,readFile,mkdir,link,access,readdir,symlink,utimes}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{randomUUID}from'node:crypto';
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
  await writeFile(join(at,'process.json'),JSON.stringify({pid,root:at,program:'program',tokenSecret:'owned',mode:options.mode??'headless',kind:options.kind??'context',...(options.kind?{}:{context:owner.id}),target:owner.target}));
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
for(const phase of ['active-dirty','active-clean','verified','dropped'] as const)test('missing native owner retains '+phase+' project without detached deletion',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),root=c.nativeCheckout!.root;
 const state=phase==='active-dirty'||phase==='active-clean'?'active':phase;
 const current=f.workspace.saveContext(c,c.generation,{nativeCheckout:{...c.nativeCheckout!,state},...(phase==='active-dirty'?{complexChanges:['q_'+randomUUID()]}:{})});
 const worker={pid:999999,tokenSecret:'owned',kind:'context',context:c.id,target:c.target,root,mode:'headless',program:c.target+'.bin'};
 await writeFile(join(root,'process.json'),JSON.stringify(worker));await writeFile(join(root,'stopped.json'),JSON.stringify({...worker,reason:'explicit_close'}));
 await rm(join(root,'native-owner.json'));const privateFile=join(root,'view.rep','db.gbf');await writeFile(privateFile,'ONLY SAVED PRIVATE PROGRAM BYTES');
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.equal(await readFile(privateFile,'utf8'),'ONLY SAVED PRIVATE PROGRAM BYTES');
  assert.equal(result.categories['detached-projects'],undefined);assert.ok(result.retained.some(r=>r.path===root&&/native.*(?:owner|ownership)/i.test(r.reason)));
 }
 assert.deepEqual(f.released,[]);assert.equal(f.workspace.context(current).nativeCheckout!.state,state);await f.workspace.artifacts.verify(current.workingSnapshot!);
});

test('historical native receipts survive GC and prevent later detached deletion after owner loss',async t=>{
 const f=await fixture(t),root=await f.stage(f.context),path=join(f.root,randomUUID());
 await writeFile(path,JSON.stringify({source:'checkout',checkout:{root,context:f.context.id}}));const history=await f.workspace.captureNative(path);
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.equal(await readFile(join(root,'view.rep','idata','00','db.1.gbf'),'utf8'),'database');
  assert.ok(result.retained.some(r=>r.path===root&&/native.*ownership/i.test(r.reason)));await f.workspace.artifacts.verify(history);
 }
 assert.deepEqual(f.released,[]);
});

for(const invalid of ['malformed','directory'])test('unverifiable native ownership is retained before native release: '+invalid,async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),root=c.nativeCheckout!.root,path=join(root,'native-owner.json');
 await rm(path);if(invalid==='directory')await mkdir(path);else await writeFile(path,'{invalid');
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.equal(await readFile(join(root,'view.rep','db.gbf'),'utf8'),'native database');
  assert.ok(result.retained.some(r=>r.path===root&&/ownership receipt.*(?:unverifiable|could not be verified)/i.test(r.reason)));
 }
 assert.deepEqual(f.released,[]);
});

test('interrupted native creation without owner metadata cannot inherit an older detached capture',async t=>{
 const f=await fixture(t),root=await f.stage(f.context),path=join(f.workspace.directory,'ghidra-native','context',f.context.id,'checkout.json');
 const intent=JSON.stringify({root,owner:{schema:1,protocol:'native-checkout-v1',context:f.context.id,target:f.target.id}});await writeFile(path,intent);
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')));
  assert.ok(result.retained.some(r=>r.path===root&&/native.*ownership/i.test(r.reason)));assert.equal(await readFile(path,'utf8'),intent);
 }
 assert.deepEqual(f.released,[]);
});

test('a native JSON working receipt is not a full detached program capture',async t=>{
 const f=await fixture(t),path=join(f.root,randomUUID());await writeFile(path,JSON.stringify({source:'server',fingerprint:'a'.repeat(64)}));
 const receipt=await f.workspace.captureNative(path),c=f.workspace.saveContext(f.context,f.context.generation,{workingSnapshot:receipt}),root=await f.stage(c);
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')));
  assert.ok(result.retained.some(r=>r.path===root&&/full detached program capture/.test(r.reason)));await f.workspace.artifacts.verify(receipt);
 }
 assert.deepEqual(f.released,[]);
});

for(const control of ['missing-export','changed-export','native-program','foreign-worker-root'])test('detached project needs positive root and full-capture proof: '+control,async t=>{
 const f=await fixture(t),root=await f.stage(f.context);
 if(control==='missing-export')await rm(join(root,'saved.gzf'));
 else if(control==='changed-export'){await rm(join(root,'saved.gzf'));await writeFile(join(root,'saved.gzf'),'uncaptured different bytes');}
 else{const path=join(root,'process.json'),worker=JSON.parse(await readFile(path,'utf8'));if(control==='native-program')worker.program=f.target.id+'.bin';else worker.root=f.root;await writeFile(path,JSON.stringify(worker));}
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')));
  assert.ok(result.retained.some(r=>r.path===root&&/full detached program capture/.test(r.reason)));
 }
 await f.workspace.artifacts.verify(f.working);
});

test('unreadable detached capture retains the program and reports instead of aborting GC',async t=>{
 const f=await fixture(t),root=await f.stage(f.context),saved=join(root,'saved.gzf'),fs=(await import('node:fs')).default;
 const {syncBuiltinESMExports}=await import('node:module'),original=fs.createReadStream;
 const mocked=t.mock.method(fs,'createReadStream',(...args:unknown[])=>{if(String(args[0])===saved)throw Object.assign(Error('fixture capture unreadable'),{code:'EACCES'});return Reflect.apply(original,fs,args);});
 syncBuiltinESMExports();t.after(()=>{mocked.mock.restore();syncBuiltinESMExports();});
 for(const dry of [true,false,false]){
  const result=await collectStorage(f.workspace,f.port,dry);assert.ok(await exists(join(root,'view.rep','idata','00','db.1.gbf')));
  assert.ok(result.retained.some(r=>r.path===root&&/full detached program capture/.test(r.reason)));
 }
});

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
 const journal=join(f.workspace.directory,'legacy-migrations',f.target.id);await mkdir(journal,{recursive:true});
 const recaptured=await f.workspace.captureSnapshot(join(stage,'saved.gzf'));
 await writeFile(join(journal,f.context.id+'-detached.json'),JSON.stringify({schema:1,original:{...f.context,workingSnapshot:recaptured}}));
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
 await symlink(outside,join(root,'exports'),'junction');const result=await collectStorage(f.workspace,f.port,false);assert.ok(result.retained.some(r=>r.path===join(root,'exports')));assert.equal(await readFile(join(outside,'shared.gzf'),'utf8'),'foreign');
});
test('recent pending captures are left to their owner; stale ones are reclaimed',async t=>{
 const f=await fixture(t),at=join(f.workspace.directory,'artifacts'),fresh=join(at,'pending-'+randomUUID()),stale=join(at,'pending-'+randomUUID()),unrowed=join(at,'c'.repeat(64)+'.gzf');
 for(const path of [fresh,stale,unrowed])await writeFile(path,'capture');await utimes(stale,new Date(0),new Date(0));
 await collectStorage(f.workspace,f.port,false);assert.ok(await exists(fresh));assert.ok(await exists(unrowed));assert.equal(await exists(stale),false);
});
test('version-tracking owners root their snapshots',async t=>{
 const f=await fixture(t),vt=await f.snapshot('vt'),orphan=await f.snapshot('orphan');
 const at=join(f.workspace.directory,'version-tracking','v_owned');await mkdir(at,{recursive:true});await writeFile(join(at,'owner.json'),JSON.stringify({source:vt}));
 await collectStorage(f.workspace,f.port,false);await f.workspace.artifacts.verify(vt);assert.equal(await exists(f.workspace.artifacts.path(orphan)),false);
});
test('native release verifies Ghidra status, local files, recovery data and uncertainty before disposal',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64)),path=join(f.root,randomUUID());
 await writeFile(path,JSON.stringify({source:'server',version:1,fileId:'file',fingerprint:'a'.repeat(64)}));const base=await f.workspace.captureNative(path);
 const current=f.workspace.saveContext(c,f.workspace.context(c).generation,{baseSnapshot:base});
 const backend=new GhidraContexts(f.workspace,{} as NativeInputs,{} as CommandContext);let closed=true;const operations:string[]=[];
 const clean={state:'ready',checkedOut:true,modified:false,recoverable:false,fileId:'file',checkoutId:3,baseVersion:1,saved:{fingerprint:'a'.repeat(64)},projectFiles:[c.target+'.bin']};
 await writeFile(join(f.workspace.directory,'ghidra-native','context',c.id,'current.json'),'{}');
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

test('a discarded legacy context loses its work, journals it, and gc reclaims its uncertain projects',async t=>{
 const f=await fixture(t),before=await f.snapshot('unknown before'),shown=await f.snapshot('reported result'),old=await f.snapshot('abandoned before');
 const stage=await f.stage(f.context,{stopped:false}),live=await f.stage(f.context,{stopped:false,pid:process.pid}),many=await f.stage(f.context,{programs:2});
 const other=f.open(),otherStage=await f.stage(other,{stopped:false});
 await request(f,'applied',old,{shown});await request(f,'failed',old,{outcome:'unknown'});const pending=await request(f,'unknown',before,{state:'unknown'});
 const c=f.workspace.context(f.context);f.workspace.saveContext(c,c.generation,{state:'needs_recovery',complexChanges:[pending.id],debugger:{connected:false,traces:[{id:'trace_'+randomUUID(),name:'t',snapshot:f.working,snap:'0',modules:0,threads:0,connected:false}]}} as never);
 await collectStorage(f.workspace,f.port,false);assert.ok(await exists(join(stage,'view.rep')));
 const {Lifecycle}=await import('../src/lifecycle.js');let stopped=false,opened=0;
 const backend={detachedStopped:async()=>stopped,open:async()=>{opened++;},dispose:async()=>{}};
 const life=new Lifecycle(f.workspace,{ordered:async(_:unknown,a:()=>Promise<unknown>)=>a()} as never,async()=>backend as never);
 await assert.rejects(life.discardLegacy(f.context,false),/acknowledge-lost-work/);
 await assert.rejects(life.discardLegacy(f.context,true,'drop'),/must be stopped/);assert.equal(f.workspace.request(pending.id).state,'unknown');
 const late=await f.snapshot('closed after the refusal');await request(f,'failed',late,{outcome:'unknown'});const reserved=f.workspace.reserveRequest(f.context,'/set_function_prototype',{name:'reserved'}).request;
 for(let i=0;i<101;i++)await request(f,'unknown',before,{state:'unknown'});
 const model=f.workspace.model(f.target.id),read=f.workspace.model.bind(f.workspace);f.workspace.model=()=>({...model,state:'unknown'});stopped=true;await assert.rejects(life.discardLegacy(f.context,true,'drop'),/Initial publication/);f.workspace.model=read;
 const result=await life.discardLegacy(f.context,true,'drop') as Record<string,unknown>;
 assert.equal(result.state,'discarded');assert.equal(result.discardedChanges,1);assert.deepEqual(await life.discardLegacy(f.context,true,'drop'),result);assert.equal(opened,0);
 const after=f.workspace.context(f.context);assert.equal(after.state,'stopped');assert.equal(after.workingSnapshot,undefined);assert.equal(after.debugger,undefined);assert.deepEqual(after.complexChanges,[]);
 const settled=f.workspace.request(pending.id);assert.equal(settled.state,'failed');assert.equal((settled.result as {state:string}).state,'discarded');
 const journals=await readdir(join(f.workspace.directory,'legacy-migrations',f.target.id));assert.equal(journals.length,1);
 const journal=JSON.parse(await readFile(join(f.workspace.directory,'legacy-migrations',f.target.id,journals[0]!),'utf8'));
 assert.equal(journal.original.workingSnapshot.id,f.working.id);assert.equal(journal.unresolved.find((q:{id:string})=>q.id===pending.id).result.state,'unknown');
 await collectStorage(f.workspace,f.port,false);
 assert.equal(await exists(join(stage,'view.rep')),false);assert.equal(await exists(f.workspace.artifacts.path(before)),false);assert.equal(await exists(f.workspace.artifacts.path(old)),false);assert.equal(await exists(f.workspace.artifacts.path(late)),false);assert.equal(f.workspace.uncertainOutcome(f.context),false);
 await f.workspace.artifacts.verify(shown);await f.workspace.artifacts.verify(f.working);
 for(const kept of [live,many,otherStage])assert.ok(await exists(join(kept,'view.rep')),kept);
 const native=await nativeContext(f,'a'.repeat(64),'a'.repeat(64));await assert.rejects(life.discardLegacy(native,true),/native checkout/);
 assert.equal(f.workspace.request(reserved.id).state,'failed');assert.throws(()=>f.workspace.startRequest(reserved.id),/already started/);
 const evidence=await f.snapshot('later evidence');await request(f,'failed',evidence,{outcome:'unknown'});assert.equal(f.workspace.uncertainOutcome(f.context),true);
 await request(f,'unknown',evidence,{state:'unknown'});assert.ok(f.workspace.unresolved(f.context).length);
 const later=await collectStorage(f.workspace,f.port,false);assert.ok(later.retained.some(r=>r.path.endsWith(f.context.id)));await f.workspace.artifacts.verify(evidence);
});
test('a pending native checkout is never discarded as detached work',async t=>{
 const f=await fixture(t),backend=new GhidraContexts(f.workspace,{} as NativeInputs,{} as CommandContext),parent=join(f.workspace.directory,'ghidra-native','context',f.context.id);
 await mkdir(parent,{recursive:true});assert.equal(await backend.detachedStopped(f.context),true);
 await writeFile(join(parent,'checkout.json'),'{}');await assert.rejects(backend.detachedStopped(f.context),/native checkout belongs/);
});
test('a checkout whose worker never started is released natively instead of failing on its missing receipt',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64));
 const contexts=Object.create(GhidraContexts.prototype) as GhidraContexts;Object.assign(contexts,{workspace:f.workspace,directory:()=>join(f.workspace.directory,'ghidra-native'),
  nativeOperation:async()=>({state:'ready',checkedOut:true,modified:true})});
 assert.equal(await contexts.releaseUnchanged(c),false);
});

test('a checkout Ghidra rewrote on open is released only as the exact bytes a pristine open produced',async t=>{
 const f=await fixture(t),base='a'.repeat(64),opened='c'.repeat(64),other='e'.repeat(64);
 const receipt=async(v:unknown)=>{const p=join(f.root,randomUUID());await writeFile(p,JSON.stringify(v));return f.workspace.captureNative(p);};
 const make=async(local:string)=>{const c=await nativeContext(f,local,base);return f.workspace.saveContext(c,c.generation,{baseSnapshot:await receipt({source:'server',version:1,fileId:'file',fingerprint:base,origin:'ghidra://127.0.0.1:1',repository:'owned'})});};
 const references=join(f.workspace.directory,'ghidra-native','shared-views',f.target.id,'opened');
 const reference=async(fileId:string,from=base,repository='owned',schema=2)=>{await mkdir(references,{recursive:true});await writeFile(join(references,'v1-'+opened+'.json'),JSON.stringify({schema,target:f.target.id,origin:'ghidra://127.0.0.1:1',repository,version:1,fileId,base:from,opened,
  preOpen:{fingerprint:from,fileId,baseVersion:1,checkoutId:3}}));};
 const calls:Record<string,unknown>[]=[];let seen=opened;
 const backend=(c:{nativeCheckout?:{path:string}})=>{const contexts=Object.create(GhidraContexts.prototype) as GhidraContexts;Object.assign(contexts,{workspace:f.workspace,directory:()=>join(f.workspace.directory,'ghidra-native'),
  nativeOperation:async(_:unknown,operation:string,parameters:Record<string,unknown>={})=>{calls.push({operation,...parameters});
   if(operation==='status')return {state:'ready',checkedOut:true,modified:true,recoverable:false,fileId:'file',checkoutId:3,baseVersion:1,saved:{fingerprint:seen,version:1,fileId:'file'},projectFiles:[c.nativeCheckout!.path.slice(1)]};
   return {state:operation==='release'?'released':'dropped'};}});return contexts;};
 const rewritten=await make(opened),stale=await make(base);
 // No proved pristine open: a rewritten checkout is private work.
 assert.equal(f.workspace.unchangedNative(rewritten),false);assert.equal(await backend(rewritten).releaseUnchanged(rewritten),false);
 await reference('file',base,'owned',1);assert.equal(f.workspace.unchangedNative(rewritten),false);
 for(const [fileId,from,repository] of [['another-file',base,'owned'],['file',other,'owned'],['file',base,'another-repository']]){await reference(fileId!,from,repository);assert.equal(f.workspace.unchangedNative(rewritten),false);}
 await reference('file');assert.equal(f.workspace.unchangedNative(rewritten),true);
 assert.equal((await collectStorage(f.workspace,f.port,true)).categories['native-checkouts']!.items,2);
 // Observed bytes decide, not the receipt.
 seen=other;assert.equal(await backend(stale).releaseUnchanged(stale),false);assert.equal(calls.some(c=>c.operation==='release'),false);
 seen=opened;assert.equal(await backend(stale).releaseUnchanged(stale),true);
 const released=calls.filter(c=>c.operation==='release');assert.equal(released.length,1);assert.equal(released[0]!.fingerprint,base);assert.equal(released[0]!.opened,opened);
 assert.equal(f.workspace.context(stale).nativeCheckout!.state,'dropped');assert.equal(f.workspace.context(stale).nativeCheckout!.opened,opened);
 assert.equal(await backend(rewritten).releaseUnchanged(rewritten),true);assert.equal(f.workspace.context(rewritten).nativeCheckout!.state,'dropped');
});

test('a checkout whose project disappeared is reported without a native release or a false saving',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'a'.repeat(64),'a'.repeat(64));await rm(c.nativeCheckout!.root,{recursive:true});
 for(const dry of [true,false]){const result=await collectStorage(f.workspace,f.port,dry);assert.ok(result.retained.some(r=>r.path===c.nativeCheckout!.root&&/project is missing/.test(r.reason)));assert.equal(result.categories['native-checkouts'],undefined);}
 assert.deepEqual(f.released,[]);
});

test('a checkout whose project is lost is given up with a journal and only its server checkout ends',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'b'.repeat(64),'a'.repeat(64)),backend=new GhidraContexts(f.workspace,{} as NativeInputs,{appArguments:{AppDataDirectory:f.root}} as CommandContext);
 const {Lifecycle}=await import('../src/lifecycle.js');let ended=0,lose=true;
 let refuse=true;const port={missingCheckout:(s:never)=>backend.missingCheckout(s),abandonMissing:async(_:never,check:boolean)=>{if(check){if(refuse)throw Error('server mismatch');return;}ended++;if(lose)throw Error('lost response');}};
 const life=new Lifecycle(f.workspace,{ordered:async(_:unknown,a:()=>Promise<unknown>)=>a()} as never,async()=>port as never);
 const parent=join(f.workspace.directory,'ghidra-native','context',c.id),root=c.nativeCheckout!.root;
 await assert.rejects(life.discardMissing(c,false),/acknowledge-lost-work/);await assert.rejects(life.discardMissing(f.context,true),/no retained native checkout/);
 await assert.rejects(life.discardMissing(c,true),/still exists/);
 await rm(root,{recursive:true});await mkdir(join(parent,'w-other'));await assert.rejects(life.discardMissing(c,true),/Other retained data/);await rm(join(parent,'w-other'),{recursive:true});
 await writeFile(join(parent,'checkout.json'),JSON.stringify({root:join(parent,'w-new')}));await assert.rejects(life.discardMissing(c,true),/another project/);await writeFile(join(parent,'checkout.json'),JSON.stringify({root}));
 await writeFile(join(parent,'current.json'),JSON.stringify({root,pid:process.pid}));await assert.rejects(life.discardMissing(c,true),/not proved stopped/);await writeFile(join(parent,'current.json'),JSON.stringify({root,pid:999999}));
 const moved=join(f.workspace.directory,'ghidra-native','context','renamed');await mkdir(join(moved,'w-owned'),{recursive:true});await writeFile(join(moved,'w-owned','native-owner.json'),JSON.stringify({context:c.id}));
 await assert.rejects(life.discardMissing(c,true),/under another name/);await rm(moved,{recursive:true});
 await assert.rejects(life.discardMissing(c,true,'refused'),/server mismatch/);refuse=false;assert.equal(f.workspace.unresolved(c).length,0);assert.equal(ended,0);
 await assert.rejects(life.discardMissing(c,true,'refused'),/new request/);
 const live=f.open(),at=join(f.workspace.directory,'ghidra-native','context',live.id,'w-live');await mkdir(at,{recursive:true});
 f.workspace.saveContext(c,f.workspace.context(c).generation,{complexChanges:['q_'+randomUUID()],debugger:{connected:false,traces:[{id:'trace_'+randomUUID(),name:'t',snapshot:f.working,snap:'0',modules:0,threads:0,connected:false}]}} as never);
 const pending=f.workspace.reserveRequest(c,'/set_function_prototype',{name:'pending'}).request;
 const other=f.workspace.checkoutReferenced.bind(f.workspace);f.workspace.checkoutReferenced=()=>true;await assert.rejects(life.discardMissing(c,true),/another context/);f.workspace.checkoutReferenced=other;
 await assert.rejects(life.discardMissing(c,true,'lost'),/lost response/);assert.equal(f.workspace.context(c).nativeCheckout!.state,'active');assert.equal(f.workspace.request(pending.id).state,'accepted');
 lose=false;const result=await life.discardMissing(c,true,'lost') as Record<string,unknown>;assert.equal(result.state,'discarded');assert.equal(result.discardedChanges,1);assert.equal(result.checkoutId,3);
 assert.deepEqual(await life.discardMissing(c,true,'lost'),result);assert.equal(ended,2);
 const after=f.workspace.context(c);assert.equal(after.nativeCheckout!.state,'dropped');assert.equal(after.workingSnapshot,undefined);assert.equal(after.debugger!.traces.length,1);assert.deepEqual(after.complexChanges,[]);assert.equal(f.workspace.request(pending.id).state,'failed');
 const journals=await readdir(join(f.workspace.directory,'native-discards',f.target.id));assert.equal(journals.length,1);
 assert.equal(JSON.parse(await readFile(join(f.workspace.directory,'native-discards',f.target.id,journals[0]!),'utf8')).original.nativeCheckout.root,root);
 const collected=await collectStorage(f.workspace,f.port,false);assert.ok(!collected.retained.some(r=>/project is missing/.test(r.reason)));
 await assert.rejects(life.discardMissing(c,true,'again'),/no retained native checkout/);
});

test('ending a missing checkout archives its stale receipts after the server proof only',async t=>{
 const f=await fixture(t),c=await nativeContext(f,'b'.repeat(64),'a'.repeat(64)),root=c.nativeCheckout!.root,parent=join(root,'..');
 await rm(root,{recursive:true});await writeFile(join(parent,'current.json'),JSON.stringify({root,pid:999999}));
 const backend=new GhidraContexts(f.workspace,{} as NativeInputs,{appArguments:{AppDataDirectory:f.root}} as CommandContext),calls:Record<string,unknown>[]=[];
 let origin='ghidra://127.0.0.1:2',state='unknown';
 (backend as unknown as {server:unknown}).server=()=>({ensure:async()=>({origin,repository:'owned'}),nativeCheckout:async(_:unknown,q:Record<string,unknown>)=>{calls.push(q);return {state:state==='ok'?q.check?'endable':'abandoned':state};}});
 await assert.rejects(backend.abandonMissing(c,true),/server binding changed/);assert.equal(calls.length,0);origin='ghidra://127.0.0.1:1';
 await assert.rejects(backend.abandonMissing(c,false),/not proved ended/);assert.ok(await exists(join(parent,'current.json')));
 state='ok';await backend.abandonMissing(c,true);assert.ok(await exists(join(parent,'current.json')));
 await backend.abandonMissing(c,false);await backend.abandonMissing(c,false);assert.equal(await exists(parent),false);
 assert.equal((await readdir(join(f.workspace.directory,'native-discards',f.target.id))).length,1);
 assert.deepEqual(calls.at(-1),{root,operation:'abandon',check:false,fileId:'file',checkoutId:3,baseVersion:1,owner:{protocol:'native-checkout-v1',context:c.id,target:f.target.id,path:'/'+f.target.id+'.bin',repository:'owned'}});
});
