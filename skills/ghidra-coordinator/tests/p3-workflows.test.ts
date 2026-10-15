import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {join} from 'node:path';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {Extensions,inspectExtension,managedExtensions,extensionState} from '../src/extensions.js';
import {fail} from '../src/model.js';
import {Workspace,type Scope} from '../src/workspace.js';
const selectors=(s:Scope)=>['--session',s.session,'--target',s.target];
async function setup(t:Parameters<typeof createCliFixture>[0]){
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend!:SessionBackend;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>(backend=new SessionBackend(w))}));const exe=join(f.root,'owned.exe');await writeFile(exe,'owned input');
 const a=await f.json(app,['ghidra','open',exe,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',exe,'--session','new']) as Scope;
 const policy=(s:Scope,publish:string,refresh='manual')=>f.json(app,['ghidra','sync-policy','set',...selectors(s),'--publish',publish,'--refresh',refresh]);
 const set=(s:Scope,at:string,value:string,extra:string[]=[])=>f.json(app,['ghidra','comments','set',...selectors(s),'--address',at,'--kind','eol','--text',value,...extra]);
 const get=(s:Scope,at:string)=>f.json(app,['ghidra','comments','get',...selectors(s),'--address',at,'--kind','eol']) as Promise<{text:string|null}>;
 return {f,app,a,b,backend,policy,set,get};
}
test('opt-in policies publish after edit/save, refresh before edit; manual/read behavior and policy survive reopening',async t=>{
 const {f,app,a,b,backend,policy,set,get}=await setup(t);
 await set(a,'1000','manual');assert.equal(backend.publications,0);
 await policy(a,'after-save');await set(a,'1100','saved later');assert.equal(backend.publications,0);
 const saved=await f.json(app,['ghidra','save',...selectors(a),'--request-id','save-auto']) as any;assert.equal(saved.pendingChanges,0);assert.equal(saved.automatic.publication.state,'merged');
 assert.equal((await get(b,'1000')).text,null,'read-only commands never refresh implicitly');
 await policy(b,'after-edit','before-edit');const result=await set(b,'1100','B', ['--request-id','edit-auto']) as any;
 assert.equal(result.automatic.refresh.state,'updated');assert.equal(result.automatic.publication.state,'merged');assert.equal((await get(b,'1000')).text,'manual');
 assert.deepEqual(await set(b,'1100','B',['--request-id','edit-auto']),result);assert.equal(backend.publications,2);
 const w=new Workspace(backend.workspace.directory,'default');try{assert.deepEqual(w.context(b).syncPolicy,{publish:'after-edit',refresh:'before-edit'});}finally{w.close();}
 assert.notEqual((await f.run(app,['ghidra','comments','set',...selectors(b),'--address','1100','--kind','eol','--text','different','--request-id','edit-auto','--json'])).exitCode,0);
});
test('automatic conflict preserves entire local work and stops incoming-conflicted edits before dispatch',async t=>{
 const {f,app,a,b,backend,policy,set,get}=await setup(t);await set(b,'1000','B');await set(b,'1100','B second');
 await policy(a,'after-edit');await set(a,'1000','A');await policy(b,'after-save');const before=backend.publications;
 const conflict=await f.run(app,['ghidra','save',...selectors(b),'--request-id','conflicted-save','--json']);assert.notEqual(conflict.exitCode,0);assert.equal(JSON.parse(conflict.stdout).localApplied,true);assert.equal(JSON.parse(conflict.stdout).local.state,'saved');assert.equal(backend.publications,before);
 assert.equal((await get(b,'1000')).text,'B');assert.equal((await get(b,'1100')).text,'B second');
 await policy(b,'after-edit','before-edit');const edits=backend.edits;assert.notEqual((await f.run(app,['ghidra','comments','set',...selectors(b),'--address','1100','--kind','pre','--text','not dispatched','--json'])).exitCode,0);assert.equal(backend.edits,edits);
});
test('automatic lost publication response reconciles one actual publication; local setter and shared check-in never replay',async t=>{
 const {f,app,a,backend,policy,set}=await setup(t);await policy(a,'after-edit');backend.losePublication=true;backend.cannotVerify=true;
 const args=['ghidra','comments','set',...selectors(a),'--address','1000','--kind','eol','--text','retained','--request-id','lost-auto','--json'];
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(backend.edits,1);assert.equal(backend.publications,1);
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(backend.edits,1);assert.equal(backend.publications,1);
 assert.notEqual((await f.run(app,['ghidra','sync-policy','set',...selectors(a),'--publish','manual','--refresh','manual','--json'])).exitCode,0);
 backend.cannotVerify=false;await f.json(app,['ghidra','open',...selectors(a)]);await policy(a,'manual');const result=await f.json(app,args) as any;assert.equal(result.automatic.publication.state,'merged');assert.equal(backend.edits,1);assert.equal(backend.publications,1);
});
test('concurrent automatic commands keep each local result and publication within its own ordered boundary',async t=>{
 const {f,app,a,backend,policy,set}=await setup(t);await policy(a,'after-edit');
 const results=await Promise.all([set(a,'1000','one'),set(a,'1100','two')]) as any[];assert.deepEqual(results.map(r=>r.automatic.publication.applied),[1,1]);assert.equal(backend.publications,2);
});
test('module consumption pins all files, ignores caller directory after install, rejects changes, symlinks and incompatible SDK versions',async t=>{
 const root=await mkdtemp(join(tmpdir(),'insight-extensions-'));t.after(()=>rm(root,{recursive:true,force:true}));const directory=join(root,'OwnedModule');await mkdir(directory);await writeFile(join(directory,'Module.manifest'),'');await writeFile(join(directory,'extension.properties'),'name=OwnedModule\nversion=12.1.2\n');
 await mkdir(join(directory,'data'));await writeFile(join(directory,'data','owned'),'first');const inspected=await inspectExtension(directory),service=new Extensions(join(root,'profile'));
 await service.install(directory,inspected.sha256);await service.install(directory,inspected.sha256);assert.equal(service.list().items.length,1);
 await writeFile(join(directory,'data','owned'),'caller changed');const [managed]=await managedExtensions(service.directory);assert.ok(managed);assert.equal(await readFile(join(managed.root,'data','owned'),'utf8'),'first');
 await assert.rejects(service.install(directory,inspected.sha256));await chmod(join(managed.root,'data','owned'),0o600);await writeFile(join(managed.root,'data','owned'),'modified installed');await assert.rejects(managedExtensions(service.directory));
 await service.enable('OwnedModule',false);assert.deepEqual(await managedExtensions(service.directory),[]);await assert.rejects(service.enable('OwnedModule',true));
 await writeFile(join(directory,'extension.properties'),'name=OwnedModule\nversion=12.0\n');await assert.rejects(inspectExtension(directory));
 if(process.platform!=='win32'){await writeFile(join(directory,'extension.properties'),'name=OwnedModule\nversion=12.1.2\n');await symlink(join(root,'outside'),join(directory,'data','link'));await assert.rejects(inspectExtension(directory));}
 assert.equal(extensionState(service.directory).modules[0]!.enabled,false);
});

test('a manual request retry does not retroactively publish after a policy change',async t=>{
 const {a,backend,policy,set}=await setup(t);const first=await set(a,'1000','manual',['--request-id','original-manual']);await policy(a,'after-edit');
 assert.deepEqual(await set(a,'1000','manual',['--request-id','original-manual']),first);assert.equal(backend.publications,0);
});

test('a lost local setter reply stays uncertain on retry; continuation proves it before automatic publication',async t=>{
 const {f,app,a,backend,policy}=await setup(t);await policy(a,'after-edit');backend.loseSetter=true;
 const args=['ghidra','comments','set',...selectors(a),'--address','1000','--kind','eol','--text','saved native effect','--request-id','lost-local-auto','--json'];
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(backend.edits,1);assert.equal(backend.publications,0);
 backend.loseSetter=false;await f.json(app,['ghidra','open',...selectors(a)]);const result=await f.json(app,args) as any;assert.equal(result.automatic.publication.state,'merged');assert.equal(backend.edits,1);assert.equal(backend.publications,1);
});
test('request identity is independent of output format and the manual mode retains 128-character IDs',async t=>{
 const {f,app,a,backend,policy,set}=await setup(t);await set(a,'1000','long manual',['--request-id','x'.repeat(128)]);await policy(a,'after-edit');
 const args=['ghidra','comments','set',...selectors(a),'--address','1100','--kind','eol','--text','format-independent','--request-id','output-mode'];assert.equal((await f.run(app,args)).exitCode,0);
 await f.json(app,args);assert.equal(backend.publications,1);assert.equal(backend.edits,2);
});

test('automatic policy leaves archive exports explicit and is shared by the Factory API',async t=>{
 const {f,app,a,backend,policy}=await setup(t);await policy(a,'after-edit','before-edit');
 const rpc=await f.rpc(app,[['ghidra','sync-policy','get',...selectors(a)]]);assert.equal((rpc[0] as any).result.publish,'after-edit');
 backend.latest=async()=>{throw Error('An export must not trigger refresh or publication');};
 Object.assign(backend,{sdkFile:async(operation:string,p:Record<string,unknown>)=>{
   const bytes=Buffer.from('synthetic GDT export'),value={state:'exported',format:'GDT'};await writeFile(String(p.output),bytes);
   const {createHash}=await import('node:crypto'),{basename}=await import('node:path');await writeFile(String(p.receipt),JSON.stringify({request:p.request_id,operation,value,files:[{name:basename(String(p.output)),sha256:createHash('sha256').update(bytes).digest('hex'),size:bytes.length}]}));return value;
 }});
 const result=await f.json(app,['ghidra','types','archive-export',...selectors(a),'--types','["/Owned"]','--output-directory',join(f.root,'gdt')]) as any;assert.equal(result.state,'exported');assert.equal(result.automatic,undefined);assert.equal(backend.publications,0);
});
test('policies are per tool context: another EXE in the same root session retains the manual default',async t=>{
 const {f,app,a,backend,policy}=await setup(t);await policy(a,'after-edit');const exe=join(f.root,'second.exe');await writeFile(exe,'different owned input');const other=await f.json(app,['ghidra','open',exe,'--session',a.session]) as Scope;
 assert.notEqual(other.target,a.target);const result=await f.json(app,['ghidra','sync-policy','get',...selectors(other)]) as any;assert.equal(result.publish,'manual');
 await f.json(app,['ghidra','comments','set',...selectors(other),'--address','1000','--kind','eol','--text','private second EXE']);assert.equal(backend.publications,0);
});

test('an automatic request reserves the common caller ID before refresh, even if the edit never starts',async t=>{
 const {f,app,a,b,policy,set}=await setup(t);await set(b,'1000','B local');await policy(a,'after-edit');await set(a,'1000','A shared');await policy(b,'after-edit','before-edit');
 const args=['ghidra','comments','set',...selectors(b),'--address','1100','--kind','eol','--text','not started','--request-id','incoming-conflict','--json'];
 const failed=await f.run(app,args);assert.notEqual(failed.exitCode,0);assert.equal(JSON.parse(failed.stdout).localApplied,false);
 const reused=await f.run(app,['ghidra','close',...selectors(b),'--request-id','incoming-conflict','--json']);assert.notEqual(reused.exitCode,0);assert.match(reused.stderr,/idempotency/);
});
test('automatic request IDs retain the standard 128-character bound',async t=>{
 const {a,backend,policy,set}=await setup(t);await policy(a,'after-edit');const result=await set(a,'1000','long automatic',['--request-id','a'.repeat(128)]) as any;assert.equal(result.automatic.publication.state,'merged');assert.equal(backend.publications,1);
});

test('automatic invalid input is a known rejection and never becomes an unproved program effect',async t=>{
 const {f,app,a,backend,policy}=await setup(t);await policy(a,'after-edit');
 const args=['ghidra','functions','rename',...selectors(a),'--address','1000','--name',' leading-space','--request-id','invalid-auto','--json'];
 for(let i=0;i<2;i++){const result=await f.run(app,args);assert.notEqual(result.exitCode,0);assert.equal(JSON.parse(result.stdout).state,'rejected');assert.equal(JSON.parse(result.stdout).localApplied,false);assert.match(result.stderr,/coordinator.invalid/);}
 assert.equal(backend.edits,0);assert.equal(backend.publications,0);
});

test('revoking Factory Update prevents automatic publication through a Destructive edit; known rollback remains a terminal rejection',async t=>{
 const {f,app,a,backend,policy}=await setup(t);await f.json(app,['permissions','grant','Destructive']);await policy(a,'after-edit');
 let calls=0;const original=backend.call.bind(backend);backend.call=async(s,op,p)=>{if(op.startsWith('/sdk/')){calls++;fail('rejected','Fixture SDK transaction rolled back.');}return original(s,op,p);};
 await f.json(app,['permissions','revoke','Update']);const args=['ghidra','memory','patch-bytes',...selectors(a),'--address','1000','--expect-hex','00','--bytes-hex','01','--request-id','permission-auto','--json'];
 const denied=await f.run(app,args);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission.denied/);assert.equal(calls,0);assert.equal(backend.publications,0);
 await f.json(app,['permissions','grant','Update']);const rejected=await f.run(app,args);assert.notEqual(rejected.exitCode,0);assert.equal(JSON.parse(rejected.stdout).state,'rejected');assert.equal(JSON.parse(rejected.stdout).localApplied,false);assert.match(rejected.stderr,/coordinator.rejected/);assert.equal(calls,1);
 await f.json(app,['permissions','revoke','Update']);assert.match((await f.run(app,args)).stderr,/coordinator.rejected/);assert.equal(calls,1);
});
