import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,mkdir}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';
import{Workspace,type ResearchTarget}from'../src/workspace.js';
import{migrateLegacy,migrationDurable,migrationProcessBlockers,type MigrationPort}from'../src/legacy-migration.js';
import{retireReusedServer}from'../src/server.js';import{processIdentity}from'../src/tool-runtime/identity.js';
import{spawn}from'node:child_process';import{once}from'node:events';
import{createCliFixture}from'@eyeauras/cli-factory/testing';import{createInsightCli}from'../src/cli.js';import{SessionBackend}from'./fixtures/session-backend.js';
import{digest}from'../src/model.js';import{resolve}from'node:path';
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done;});return{promise,resolve};}
async function fixture(t:test.TestContext){
 const root=await mkdtemp(join(tmpdir(),'legacy-migration-')),workspace=new Workspace(join(root,'workspace'),'default');t.after(()=>workspace.close());
 const path=join(root,'input.bin');await writeFile(path,'owned migration fixture');const target=await workspace.importTarget(path);
 const {context}=workspace.reserveOpen(target.id,'new',{autoAnalyze:false});
 const snapshot=await workspace.captureSnapshot(path);workspace.establishModel(target.id,1,snapshot);
 let engine='',version=1,fileId='file-owned',checkouts:unknown[]=[],runs=0,releases=0,adoptions=0,conversions=0,lose=false,verify=true,closed=true;
 const oldFingerprint='a'.repeat(64),fingerprint='b'.repeat(64),programIdentity='c'.repeat(64);
 const port:MigrationPort={binding:async()=>({origin:'ghidra://localhost:1234',repository:'owned',runtimeFingerprint:'d'.repeat(64)}),
  probe:async()=>({state:'verified',version,fileId,fingerprint:engine?fingerprint:oldFingerprint,programIdentity,engine,checkouts,language:'x86:LE:64:default',compiler:'gcc',imageBase:'1000'}),
  write:async q=>{if(q.operation==='snapshot')return{state:'verified',fingerprint:oldFingerprint,programIdentity,sourceSha:target.binarySha256};
   if(q.operation==='run'){runs++;await migrationDurable(join(String(q.root),'native-migration.json'),{phase:'commit_intent',fingerprint,checkoutId:5});if(lose){engine='native-checkout-v1';version=2;throw Error('lost after check-in');}engine='native-checkout-v1';version=2;return{phase:'checked_in'};}
   releases++;return{phase:'released'};},
  verify:async()=>{if(!verify)throw Error('unresolved marker');},adopt:async()=>{adoptions++;},closed:async()=>closed,convert:async()=>{conversions++;}};
 return{workspace,port,target,context,snapshot,root,get runs(){return runs},get releases(){return releases},get adoptions(){return adoptions},get conversions(){return conversions},set engine(v:string){engine=v},set fileId(v:string){fileId=v},set checkouts(v:unknown[]){checkouts=v},set lose(v:boolean){lose=v},set verify(v:boolean){verify=v},set closed(v:boolean){closed=v}};
}
test('dry run reserves no migration, performs no checkout/check-in and preserves contexts',async t=>{const f=await fixture(t),before=f.workspace.context(f.context);const r=await migrateLegacy(f.workspace,f.port,f.target.id,true);assert.equal(r.state,'planned');assert.equal(f.runs+f.releases+f.adoptions,0);assert.deepEqual(f.workspace.context(f.context),before);await assert.rejects(readFile(join(f.workspace.directory,'legacy-migrations',f.target.id,'migration.json')));});
test('normal native check-in, independent verification, no-work recovery and idempotent repeat',async t=>{const f=await fixture(t);const q=f.workspace.reserveRequest(f.context,'ghidra.open',{}).request;f.workspace.startRequest(q.id);f.workspace.recordRequest(q.id,'unknown',{reason:'old legacy open'});const r=await migrateLegacy(f.workspace,f.port,f.target.id,false);assert.equal(r.items[0]!.state,'migrated');assert.equal(f.workspace.request(q.id).state,'failed');assert.equal(f.workspace.context(f.context).state,'stopped');await migrateLegacy(f.workspace,f.port,f.target.id,false);assert.equal(f.runs,1);assert.equal(f.releases,1);});
test('lost check-in reply resumes by independent readback without a second check-in',async t=>{const f=await fixture(t);f.lose=true;await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false),/lost after/);f.lose=false;await migrateLegacy(f.workspace,f.port,f.target.id,false);assert.equal(f.runs,1);assert.equal(f.releases,1);});
test('unproved native intent stays blocked and is never retried or released',async t=>{const f=await fixture(t);f.lose=true;await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false));f.verify=false;for(let i=0;i<2;i++)await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false),/unresolved marker/);assert.equal(f.runs,1);assert.equal(f.releases,0);});
test('identity mismatch on continuation preserves journal and refuses a foreign item',async t=>{const f=await fixture(t);f.lose=true;await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false));f.fileId='foreign';await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false),/identity changed/);assert.equal(f.runs,1);assert.equal(f.releases,0);});
test('native target is unchanged and no legacy writer runs',async t=>{const f=await fixture(t);f.engine='native-checkout-v1';const before=f.workspace.model(f.target.id);assert.equal((await migrateLegacy(f.workspace,f.port,undefined,false)).items[0]!.state,'native_unchanged');assert.equal(f.runs+f.adoptions+f.releases,0);assert.deepEqual(f.workspace.model(f.target.id),before);});
test('live context and existing checkout gates prevent migration',async t=>{const f=await fixture(t);f.closed=false;await assert.rejects(migrateLegacy(f.workspace,f.port,undefined,false),/original context/);f.closed=true;f.checkouts=[{id:11}];await assert.rejects(migrateLegacy(f.workspace,f.port,undefined,false),/existing checkouts/);assert.equal(f.runs,0);});
test('load identity mismatch prevents reserving a migration',async t=>{const f=await fixture(t);const original=f.port.probe;f.port.probe=async t=>({...await original(t),state:'unknown'});await assert.rejects(migrateLegacy(f.workspace,f.port,undefined,false),/readback is incomplete/);assert.equal(f.runs,0);});
test('detached private changes and unknown effects are refused with original bytes and request retained',async t=>{const f=await fixture(t);const c=f.workspace.context(f.context);f.workspace.saveContext(c,c.generation,{workingSnapshot:f.snapshot,baseSnapshot:f.snapshot,baseRevision:1,complexChanges:['q_11111111-1111-1111-1111-111111111111']});const before=f.workspace.context(c);const result=await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal(result.retainedContexts,1);assert.equal(f.conversions,0);assert.deepEqual(f.workspace.context(c),before);await f.workspace.artifacts.verify(f.snapshot);});
test('exactly unchanged detached buffers can convert with the original context retained in a journal',async t=>{const f=await fixture(t);const c=f.workspace.context(f.context);f.workspace.saveContext(c,c.generation,{workingSnapshot:f.snapshot,baseSnapshot:f.snapshot,baseRevision:1});const result=await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal((result.items[0]!.contexts as {state:string}[])[0]!.state,'converted_unchanged');assert.equal(f.conversions,1);assert.ok(JSON.parse(await readFile(join(f.workspace.directory,'legacy-migrations',f.target.id,c.id+'-detached.json'),'utf8')).original.workingSnapshot);});
test('migration requires Destructive only for execution; dry-run works with ReadOnly',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly']}]});let calls=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{migrate:async()=>{calls++;return{state:'planned'}}})}));
 assert.equal((await f.run(app,['ghidra','migrate','--all','--json'])).exitCode,1);assert.equal(calls,0);
 assert.equal((await f.json(app,['ghidra','migrate','--all','--dry-run']) as {state:string}).state,'planned');assert.equal(calls,1);
 assert.notEqual((await f.run(app,['ghidra','migrate','--json'])).exitCode,0);
});

test('all-target inventory explicitly skips inputs without a Ghidra model',async t=>{const f=await fixture(t);const path=join(f.root,'other.bin');await writeFile(path,'registered only');const other=await f.workspace.importTarget(path);const result=await migrateLegacy(f.workspace,f.port,undefined,true);assert.equal(result.items.find(item=>item.target===other.id)!.state,'no_ghidra_model');assert.equal(f.runs,0);});

test('a legacy open reports migration and a terminal no-work failure instead of freezing an unknown request',async t=>{const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend!:SessionBackend;const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{backend=new SessionBackend(workspace);backend.open=async()=>{const {CliError}=await import('@eyeauras/cli-factory');throw new CliError('Legacy model requires explicit migration',{code:'coordinator.migration'});};return backend;}}));const path=join(f.root,'legacy.bin');await writeFile(path,'legacy source');const result=await f.run(app,['ghidra','open',path,'--session','new','--request-id','legacy-open','--json']);assert.notEqual(result.exitCode,0);assert.match(result.stderr,/coordinator.migration/);assert.match(result.stderr,/migrate/);const request=backend.workspace.requestByCaller('legacy-open')!;assert.equal(request.state,'failed');assert.equal((request.result as {state:string}).state,'blocked');assert.equal(backend.workspace.unresolved(backend.workspace.contextById(request.context)).length,0);});

test('target metadata cannot substitute another source SHA for its immutable input artifact',async t=>{const f=await fixture(t),get=f.workspace.target.bind(f.workspace);f.workspace.target=id=>({...get(id),binarySha256:'f'.repeat(64)});await assert.rejects(migrateLegacy(f.workspace,f.port,f.target.id,false),/input artifact and target source identity differ/);assert.equal(f.runs,0);});

test('dry-run lists old no-work open recovery while retaining the original unresolved intent',async t=>{const f=await fixture(t),q=f.workspace.reserveRequest(f.context,'ghidra.open',{}).request;f.workspace.startRequest(q.id);f.workspace.recordRequest(q.id,'unknown',{reason:'legacy'});const result=await migrateLegacy(f.workspace,f.port,undefined,true);assert.ok((result.items[0]!.contexts as {state:string}[]).some(c=>c.state==='would_recover_open'));assert.equal(f.workspace.request(q.id).state,'unknown');assert.equal(f.runs,0);});
test('unknown non-open work is explicitly retained and never completed by no-work recovery',async t=>{const f=await fixture(t),q=f.workspace.reserveRequest(f.context,'script',{}).request;f.workspace.startRequest(q.id);f.workspace.recordRequest(q.id,'unknown',{reason:'unproved'});const before=f.workspace.request(q.id),result=await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal(result.retainedContexts,1);assert.deepEqual(f.workspace.request(q.id),before);});

test('no-work recovery retires its failed creation intent before completing the request',async t=>{const f=await fixture(t),q=f.workspace.reserveRequest(f.context,'ghidra.open',{}).request;f.workspace.startRequest(q.id);let retained=0;f.port.recoverOpen=async c=>{assert.equal(f.workspace.request(q.id).state,'running');assert.equal(c.id,f.context.id);retained++;};await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal(retained,1);assert.equal(f.workspace.request(q.id).state,'failed');});
test('known native checkouts allow no-work recovery; an unowned checkout does not',async t=>{const f=await fixture(t);await migrateLegacy(f.workspace,f.port,undefined,false);f.checkouts=[{id:11}];const q=f.workspace.reserveRequest(f.context,'ghidra.open',{}).request;f.workspace.startRequest(q.id);await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal(f.workspace.request(q.id).state,'running');f.port.knownCheckouts=async()=>true;await migrateLegacy(f.workspace,f.port,undefined,false);assert.equal(f.workspace.request(q.id).state,'failed');assert.equal(f.runs,1);});

for(const state of ['starting','running','unverified'])test('migration refuses retained '+state+' native helper before recovering an open without current.json',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Destructive']}]});let calls=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{migrate:async()=>{calls++;return{state:'complete'}}})}));
 const directory=f.appArguments.AppDataDirectory,workspace=new Workspace(join(directory,'workspace'),'default');try{
 const input=join(f.root,'input.bin');await writeFile(input,'held before native checkout');const target=await workspace.importTarget(input),{context}=workspace.reserveOpen(target.id,'new',{autoAnalyze:false});
 const request=workspace.reserveRequest(context,'ghidra.open',{}).request;workspace.startRequest(request.id);const before=workspace.request(request.id);
 const pending=join(workspace.directory,'ghidra-native','context',context.id,'checkout.json');await mkdir(join(pending,'..'),{recursive:true});await writeFile(pending,'retained creation intent');
 const id='11111111-1111-1111-1111-111111111111',root=join(directory,'runtime/runs',id);await mkdir(root,{recursive:true});await mkdir(join(directory,'runtime/processes'),{recursive:true});
 await writeFile(join(directory,'runtime/processes',id+'.json'),JSON.stringify({schema:1,id,tool:'ghidra',role:'native-checkout',state,root,ownerPid:process.pid,profileBinding:digest(resolve(directory)),createdAt:new Date().toISOString()}));
 const result=await f.run(app,['ghidra','migrate','--all','--json']);assert.notEqual(result.exitCode,0);assert.match(result.stderr,/coordinator.busy/);assert.equal(calls,0);
 assert.deepEqual(workspace.request(request.id),before);assert.equal(await readFile(pending,'utf8'),'retained creation intent');
 }finally{workspace.close();}
});

test('migration refuses a live retained bootstrap even without supervisor or current receipts',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Destructive']}]});let calls=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{migrate:async()=>{calls++;return{state:'complete'}}})}));
 const root=join(f.appArguments.AppDataDirectory,'workspace/ghidra-native/bootstrap/t_held/w-held');await mkdir(root,{recursive:true});await writeFile(join(root,'process.json'),JSON.stringify({pid:process.pid,kind:'bootstrap',target:'t_held',tokenSecret:'retained-owner'}));
 const result=await f.run(app,['ghidra','migrate','--all','--json']);assert.notEqual(result.exitCode,0);assert.match(result.stderr,/coordinator.busy/);assert.equal(calls,0);
});

test('migration cannot pass admission while an open is still importing its input',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let migrations=0,opens=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
  const backend=new SessionBackend(workspace),open=backend.open.bind(backend);return Object.assign(backend,{open:async(...args:Parameters<typeof open>)=>{opens++;return open(...args);},migrate:async()=>{migrations++;return{state:'complete'};}});
 }}));
 const input=join(f.root,'slow-input.bin');await writeFile(input,'open paused during immutable input import');
 const entered=deferred(),release=deferred(),original=Workspace.prototype.importTarget;
 Workspace.prototype.importTarget=async function(path){if(path===input){entered.resolve();await release.promise;}return original.call(this,path);};
 const opening=f.run(app,['ghidra','open',input,'--session','new','--json']);
 try{
  await entered.promise;
  const migration=await f.run(app,['ghidra','migrate','--all','--json']);assert.notEqual(migration.exitCode,0);assert.match(migration.stderr,/coordinator.busy/);assert.equal(migrations,0);assert.equal(opens,0);
 }finally{release.resolve();Workspace.prototype.importTarget=original;await opening;}
 assert.equal((await opening).exitCode,0);assert.equal(opens,1);
 assert.equal((await f.run(app,['ghidra','migrate','--all','--json'])).exitCode,0);assert.equal(migrations,1);
});

test('an open arriving during migration is rejected before importing its input',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});
 const entered=deferred(),release=deferred();let imports=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{migrate:async()=>{entered.resolve();await release.promise;return{state:'complete'};}})}));
 const input=join(f.root,'blocked-input.bin');await writeFile(input,'must not import during migration');const original=Workspace.prototype.importTarget;
 Workspace.prototype.importTarget=async function(path){if(path===input)imports++;return original.call(this,path);};
 const migration=f.run(app,['ghidra','migrate','--all','--json']);
 try{await entered.promise;const opening=await f.run(app,['ghidra','open',input,'--session','new','--json']);assert.notEqual(opening.exitCode,0);assert.match(opening.stderr,/coordinator.busy/);assert.equal(imports,0);}
 finally{release.resolve();Workspace.prototype.importTarget=original;await migration;}
});

test('failed input import releases whole-open migration admission',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let migrations=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{migrate:async()=>{migrations++;return{state:'complete'};}})}));
 assert.notEqual((await f.run(app,['ghidra','open',join(f.root,'absent.bin'),'--session','new','--json'])).exitCode,0);
 assert.equal((await f.run(app,['ghidra','migrate','--all','--json'])).exitCode,0);assert.equal(migrations,1);
});

test('moved terminal direct-helper receipts require both absent PIDs and acknowledged completion',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),directory=f.appArguments.AppDataDirectory,id='22222222-2222-2222-2222-222222222222';
 const child=spawn(process.execPath,['-e',''],{windowsHide:true,stdio:'ignore'}),pid=child.pid!;await once(child,'close');
 await mkdir(join(directory,'runtime/processes'),{recursive:true});const path=join(directory,'runtime/processes',id+'.json');
 const record={schema:1,id,tool:'ghidra',role:'native-checkout',root:join(f.root,'old-control/runtime/runs',id),profileBinding:'old-binding',state:'exited',phase:'direct_child_only',pid,ownerPid:pid,outcome:'completed',exitCode:0,signal:null,endedAt:new Date().toISOString()};
 const bytes=JSON.stringify(record);await writeFile(path,bytes);assert.deepEqual(await migrationProcessBlockers(directory),[]);assert.equal(await readFile(path,'utf8'),bytes);
 for(const changed of [{state:'running'},{pid:process.pid},{ownerPid:process.pid},{endedAt:null},{outcome:'unknown'},{metadata:{nativeChildDeadlines:true}},{exitCode:1}]){
  await writeFile(path,JSON.stringify({...record,...changed}));assert.equal((await migrationProcessBlockers(directory)).length,1);
 }
});

test('a strongly proved reused server PID is never signaled and its binding is retained',async t=>{
 const identity=await processIdentity(process.pid);if(!identity?.strong){t.skip('Requires strong OS birth identity');return;}
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),control=f.appArguments.AppDataDirectory,directory=join(control,'workspace'),id='33333333-3333-3333-3333-333333333333';
 await mkdir(join(control,'runtime/processes'),{recursive:true});await mkdir(join(directory,'server'),{recursive:true});
 const local={mode:'local' as const,instance:'server_fixture',origin:'ghidra://127.0.0.1:1234',repository:'retained',readerUser:'reader',publisherUser:'publisher',readerSecret:'reader-ref',publisherSecret:'publisher-ref',keySecret:'key-ref',tokenSecret:'token-ref',port:1234,identityPort:1237,phase:'running' as const,pid:process.pid,toolProcessId:id};
 const path=join(control,'runtime/processes',id+'.json'),record={schema:1,id,tool:'ghidra',role:'server',root:join(control,'runtime/runs',id),profileBinding:digest(resolve(control)),state:'running',pid:process.pid,ownerPid:process.pid,identity:identity.birth,strongIdentity:true,metadata:{serverDirectory:directory}};
 await writeFile(path,JSON.stringify(record));assert.equal(await retireReusedServer(directory,control,{...local}),false);
 await writeFile(path,JSON.stringify({...record,identity:'different-original-server-birth'}));const before=await readFile(path,'utf8');
 const retained={...local};assert.equal(await retireReusedServer(directory,control,retained),true);assert.equal(await readFile(path,'utf8'),before);process.kill(process.pid,0);
 assert.equal(retained.repository,local.repository);assert.equal(retained.origin,local.origin);assert.equal('pid' in retained,false);
 assert.equal(JSON.parse(await readFile(join(directory,'server/local.json'),'utf8')).phase,'stopped');
});
