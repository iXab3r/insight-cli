import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import type {CommandContext} from '@eyeauras/cli-factory';
import {mkdir,readFile,writeFile,lstat,realpath,rm,symlink,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {AnalysisStorage} from '../src/analysis-storage.js';
import {createInsightCli} from '../src/cli.js';
import {Workspace} from '../src/workspace.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {GhidraContexts} from '../src/contexts.js';
import type {NativeInputs} from '../src/native-inputs.js';
import {runtimeSelection} from '../src/runtime-selection.js';
import {atomicWrite} from '../src/tool-runtime/store.js';
import {runTool} from '../src/tool-runtime/run.js';

async function setup(t:Parameters<typeof createCliFixture>[0],checkpoint?:(phase:string)=>Promise<void>){
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']},{name:'other',permissions:['ReadOnly','Update']}]});
  const c={appArguments:f.appArguments,profile:await f.profileStore.get(),signal:new AbortController().signal,cwd:f.root,environment:{},fetch:globalThis.fetch} as unknown as CommandContext;
  const storage=new AnalysisStorage(f.profileStore,async()=>{},checkpoint),source=f.appArguments.AppDataDirectory;
  await mkdir(join(source,'workspace','native database'),{recursive:true});
  await writeFile(join(source,'workspace','native database','program.db'),'native database bytes');
  await mkdir(join(source,'runtime','checks'),{recursive:true});await writeFile(join(source,'runtime','checks','candidate'),'retained validation');
  const base=join(f.root,'new volume Ω'),destination=join(base,'insight-cli','default');
  return {f,c,storage,source,base,destination};
}
test('public configuration preserves Factory profile isolation, old defaults and exact artifact readback',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']},{name:'other',permissions:['ReadOnly']}]});
  const app=f.createApplication(runtime=>createInsightCli({runtime})),base=join(f.root,'storage Ω');
  assert.equal((await f.json(app,['storage','show']) as {directory:string}).directory,f.appArguments.AppDataDirectory);
  const denied=await f.run(app,['--profile','other','storage','configure','--directory',base,'--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);
  const configured=await f.json(app,['storage','configure','--directory',base]) as {state:string};assert.equal(configured.state,'committed');
  const profile=await f.profileStore.get();assert.equal(profile.values.analysisDirectory,join(base,'insight-cli','default'));
  assert.equal((await f.profileStore.get('other')).values.analysisDirectory,undefined);
  const input=join(f.root,'finding');await writeFile(input,'exact finding');
  const saved=await f.json(app,['artifacts','save',input]) as {path:string};assert.ok(saved.path.startsWith(join(base,'insight-cli','default','materials')));assert.equal(await readFile(saved.path,'utf8'),'exact finding');
  assert.equal(await realpath(join(f.appArguments.AppDataDirectory,'materials')),join(base,'insight-cli','default','materials'));
  await rm(join(base,'insight-cli','default','.insight-analysis.json'));
  assert.notEqual((await f.run(app,['artifacts','save',input,'--json'])).exitCode,0,'An unavailable volume never falls back');
});
test('dry-run makes no migration; paths, nesting and existing destination are rejected before copying',async t=>{
  const {c,storage,source,base,destination}=await setup(t);
  const plan=await storage.migrate(c,base,true) as {state:string;bytes:number};assert.equal(plan.state,'preflight');assert.ok(plan.bytes>0);
  await assert.rejects(lstat(destination));await assert.rejects(lstat(join(source,'storage/migration.json')));
  await assert.rejects(storage.migrate(c,'relative',true),/absolute/);
  await assert.rejects(storage.migrate(c,source,true),/non-nested/);
  await mkdir(destination,{recursive:true});await writeFile(join(destination,'foreign'),'foreign data');
  await assert.rejects(storage.migrate(c,base,true),/empty/);assert.equal(await readFile(join(destination,'foreign'),'utf8'),'foreign data');
});
for(const phase of ['reserved','copied','source-retained','aliases-installed','profile-switched'])test('durable migration resumes after interruption at '+phase,async t=>{
  let stopped=false;const {f,c,storage,source,base,destination}=await setup(t,async at=>{if(at===phase&&!stopped){stopped=true;throw Error('disposable interruption');}});
  await assert.rejects(storage.migrate(c,base),/disposable interruption/);
  const app=f.createApplication(runtime=>createInsightCli({runtime}));
  assert.notEqual((await f.run(app,['targets','list','--json'])).exitCode,0,'Ordinary commands freeze during partial copy/activation');
  const resumed=await storage.resume({...c,profile:await f.profileStore.get()});assert.equal((resumed as {state:string}).state,'committed');
  assert.equal(await readFile(join(destination,'workspace/native database/program.db'),'utf8'),'native database bytes');
  assert.equal(await realpath(join(source,'workspace')),join(destination,'workspace'));
  const j=JSON.parse(await readFile(join(source,'storage/migration.json'),'utf8'));
  assert.equal(await readFile(join(source,'.storage-retained',j.id,'workspace/native database/program.db'),'utf8'),'native database bytes');
  assert.equal((await f.json(app,['storage','show']) as {availability:string}).availability,'available');
});
test('copy failure retains source and unknown intents; rollback never replays scripts/publications',async t=>{
  let once=true;const {f,c,storage,source,base}=await setup(t,async at=>{if(at==='copied'&&once){once=false;throw Error('partial-copy failure');}});
  const original=await readFile(join(source,'workspace/native database/program.db'));
  await assert.rejects(storage.migrate(c,base),/partial-copy/);assert.equal((await f.profileStore.get()).values.analysisDirectory,undefined);
  await storage.rollback(c);assert.deepEqual(await readFile(join(source,'workspace/native database/program.db')),original);
  assert.equal((await lstat(join(source,'workspace'))).isDirectory(),true);
});
test('verified copy detects tampering before resume and rollback refuses post-switch data loss',async t=>{
  let once=true;const {f,c,storage,source,base,destination}=await setup(t,async at=>{if(at==='aliases-installed'&&once){once=false;throw Error('lost activation reply');}});
  await assert.rejects(storage.migrate(c,base),/lost activation/);
  await writeFile(join(destination,'workspace/native database/program.db'),'tampered');
  await assert.rejects(storage.resume(c),/differ/);assert.equal((await f.profileStore.get()).values.analysisDirectory,undefined);
  await writeFile(join(destination,'workspace/native database/program.db'),'native database bytes');await storage.resume(c);
  const selected={...c,profile:await f.profileStore.get()};
  await writeFile(join(destination,'workspace/native database/new.db'),'new private work');
  await assert.rejects(storage.rollback(selected),/differ/);assert.equal(await readFile(join(source,'workspace/native database/new.db'),'utf8'),'new private work');
});
test('rollback after switch restores original paths when unchanged; cleanup is resumable and idempotent',async t=>{
  const first=await setup(t);await first.storage.migrate(first.c,first.base);await first.storage.rollback({...first.c,profile:await first.f.profileStore.get()});
  assert.equal((await first.f.profileStore.get()).values.analysisDirectory,null);assert.equal((await lstat(join(first.source,'workspace'))).isDirectory(),true);
  let once=true;const second=await setup(t,async at=>{if(at==='cleanup-reserved'&&once){once=false;throw Error('cleanup interrupted');}});
  await second.storage.migrate(second.c,second.base);const selected={...second.c,profile:await second.f.profileStore.get()};
  await assert.rejects(second.storage.cleanup(selected),/cleanup interrupted/);assert.equal((await second.storage.resume(selected) as {state:string}).state,'cleaned');
  assert.equal((await second.storage.cleanup(selected) as {state:string}).state,'cleaned');
  assert.equal(await readFile(join(second.source,'workspace/native database/program.db'),'utf8'),'native database bytes');
});
test('pending private snapshots and unknown request/publication identities survive migration byte-for-byte',async t=>{
  const {f,c,storage,source,base,destination}=await setup(t),w=new Workspace(join(source,'workspace'),'default');
  const input=join(f.root,'generic.exe');await writeFile(input,'generic disposable input');const target=await w.importTarget(input);
  const opened=w.reserveOpen(target.id,'new',{autoAnalyze:false},'open-original'),who={session:opened.context.session,target:target.id};
  const backend=new SessionBackend(w);w.startRequest(opened.request.id,{kind:'open'});await backend.open(who,opened.request.id);w.recordRequest(opened.request.id,'applied',{...who,state:'ready'});
  const request=w.reserveRequest(who,'ghidra.script.run',{script:'generic fixture'},'unknown-script').request;
  const candidate=await backend.encode({names:{'1000':'retained'},comments:{},opaque:'candidate'});
  w.startRequest(request.id,{kind:'program',operation:'/run_script',candidateSnapshot:candidate});w.recordRequest(request.id,'unknown',{state:'unknown',candidateSnapshot:candidate});
  const pubRequest=w.reserveRequest(who,'ghidra.merge',{},'unknown-publication').request;
  w.startRequest(pubRequest.id,{kind:'publication'});
  const publication=w.beginPublication(who,pubRequest.id,1,candidate);w.publicationIntent(publication.id);w.unknownPublication(publication.id,{state:'unknown'});
  const beforeRequest=w.request(request.id),beforePublication=w.activePublication(target.id),beforeContext=w.context(who);w.close();
  const dbBefore=await readFile(join(source,'workspace/workspace.sqlite'));
  await storage.migrate(c,base);
  assert.deepEqual(await readFile(join(destination,'workspace/workspace.sqlite')),dbBefore,'Migration does not rewrite durable research state');
  const reopened=new Workspace(join(destination,'workspace'),'default');
  try{
    assert.deepEqual(reopened.request(request.id),beforeRequest);assert.deepEqual(reopened.activePublication(target.id),beforePublication);assert.deepEqual(reopened.context(who),beforeContext);
    assert.equal(await readFile(await reopened.artifacts.verify(candidate),'utf8'),JSON.stringify({names:{'1000':'retained'},comments:{},opaque:'candidate'}));
    assert.equal((await f.profileStore.get()).values.analysisDirectory,destination);
  }finally{reopened.close();}
});
test('resume binds the destination filesystem anchor and never recreates an unmounted location',async t=>{
  const {c,storage,base,destination}=await setup(t,async phase=>{if(phase==='reserved')throw Error('interrupted');});
  await mkdir(base);await assert.rejects(storage.migrate(c,base),/interrupted/);
  await rename(base,base+'-original');await mkdir(base);
  await assert.rejects(storage.resume(c),/volume|directory/);await assert.rejects(lstat(destination));
  await storage.rollback(c);
});
test('changed source before activation can roll back without losing the new bytes',async t=>{
  const {c,storage,source,base}=await setup(t,async phase=>{if(phase==='reserved')throw Error('interrupted');});
  await assert.rejects(storage.migrate(c,base),/interrupted/);
  await writeFile(join(source,'workspace/native database/program.db'),'new source bytes');
  await assert.rejects(storage.resume(c),/Source changed/);
  assert.equal((await storage.rollback(c) as {state:string}).state,'rolled_back');
  assert.equal(await readFile(join(source,'workspace/native database/program.db'),'utf8'),'new source bytes');
});
test('the normal native launch gate accepts configured runtime storage without weakening child containment',async t=>{
  const {f,c,storage,base}=await setup(t);await storage.migrate(c,base);
  const result=await runTool(c,{tool:'fixture',role:'storage-test',executable:process.execPath,arguments:['-e','process.stdout.write("owned native readback")'],timeoutMs:10000});
  assert.equal(result.stdout,'owned native readback');
});
test('resume rejects replaced destination roots and parents before making a write', {skip:process.platform==='win32'},async t=>{
  const {f,c,storage,base,destination}=await setup(t,async phase=>{if(phase==='reserved')throw Error('interrupted');});
  await assert.rejects(storage.migrate(c,base),/interrupted/);
  const unrelated=join(f.root,'unrelated destination');await mkdir(unrelated);
  await mkdir(join(destination,'..'),{recursive:true});await symlink(unrelated,destination,'dir');
  await assert.rejects(storage.resume(c),/ordinary directory|replaced/);
  assert.deepEqual(await import('node:fs/promises').then(fs=>fs.readdir(unrelated)),[]);
  await storage.rollback(c);
});
test('interrupted cleanup never follows a replaced retained-source ancestor', {skip:process.platform==='win32'},async t=>{
  const {f,c,storage,source,base}=await setup(t,async phase=>{if(phase==='cleanup-reserved')throw Error('interrupted');});
  await storage.migrate(c,base);const selected={...c,profile:await f.profileStore.get()};
  await assert.rejects(storage.cleanup(selected),/interrupted/);
  const j=JSON.parse(await readFile(join(source,'storage/migration.json'),'utf8')),parent=join(source,'.storage-retained');
  await rename(parent,parent+'-original');const foreign=join(f.root,'unrelated backups');await mkdir(join(foreign,j.id),{recursive:true});
  await writeFile(join(foreign,j.id,'important'),'unrelated preserved bytes');await symlink(foreign,parent,'dir');
  await assert.rejects(storage.resume(selected),/replaced/);assert.equal(await readFile(join(foreign,j.id,'important'),'utf8'),'unrelated preserved bytes');
});
test('retained-source corruption prevents rollback and cleanup intent permanently disables rollback',async t=>{
  const first=await setup(t);await first.storage.migrate(first.c,first.base);
  const j=JSON.parse(await readFile(join(first.source,'storage/migration.json'),'utf8'));
  await writeFile(join(first.source,'.storage-retained',j.id,'workspace/native database/program.db'),'changed retained source');
  await assert.rejects(first.storage.rollback({...first.c,profile:await first.f.profileStore.get()}),/Retained source bytes changed/);
  const second=await setup(t,async phase=>{if(phase==='cleanup-reserved')throw Error('interrupted cleanup');});
  await second.storage.migrate(second.c,second.base);const selected={...second.c,profile:await second.f.profileStore.get()};
  await assert.rejects(second.storage.cleanup(selected),/interrupted/);await assert.rejects(second.storage.rollback(selected),/cleanup has begun/);
  await second.storage.resume(selected);assert.equal(await readFile(join(second.source,'workspace/native database/program.db'),'utf8'),'native database bytes');
});
test('internal absolute and relative links preserve their bytes and continue through permanent aliases', {skip:process.platform==='win32'},async t=>{
  const {c,storage,source,base,destination}=await setup(t);
  await symlink(join(source,'workspace/native database/program.db'),join(source,'workspace/absolute-link'));
  await symlink('native database/program.db',join(source,'workspace/relative-link'));
  await storage.migrate(c,base);
  for(const name of ['absolute-link','relative-link'])assert.equal(await readFile(join(destination,'workspace',name),'utf8'),'native database bytes');
  await storage.cleanup({...c,profile:{...c.profile,values:{analysisDirectory:destination}}});
  assert.equal(await readFile(join(source,'workspace/absolute-link'),'utf8'),'native database bytes');
});
test('managed runtime authority and a closed native receipt reopen after paths move',async t=>{
  const {f,c,storage,source,base,destination}=await setup(t),w=new Workspace(join(source,'workspace'),'default');
  const input=join(f.root,'native.exe');await writeFile(input,'generic native fixture');const target=await w.importTarget(input),opened=w.reserveOpen(target.id,'new',{autoAnalyze:false});
  const root=join(w.directory,'ghidra-native/context',opened.context.id,'retained-worker');await mkdir(root,{recursive:true});
  const binding={root,target:target.id,context:opened.context.id,kind:'context',mode:'headless',pid:2147483646,tokenSecret:'synthetic-fixture-secret-name',runtimeFingerprint:'a'.repeat(64)};
  await atomicWrite(join(root,'process.json'),binding);await atomicWrite(join(root,'stopped.json'),{pid:binding.pid,tokenSecret:binding.tokenSecret});await atomicWrite(join(root,'../current.json'),binding);
  const id='b'.repeat(64),home=join(source,'runtime/installations',id,'ghidra');await mkdir(home,{recursive:true});
  const selection={schema:1,mode:'managed',id,ghidraHome:home,java:'/synthetic/java',fingerprint:'a'.repeat(64),selectedAt:'fixture'};await atomicWrite(join(source,'runtime/selection.json'),selection);w.close();
  await storage.migrate(c,base);assert.deepEqual(runtimeSelection(source,destination),selection);
  const reopened=new Workspace(join(destination,'workspace'),'default');
  try{
    const backend=new GhidraContexts(reopened,{fingerprint:'a'.repeat(64)} as NativeInputs,{...c,profile:await f.profileStore.get()});
    assert.equal(await backend.closed({session:opened.context.session,target:target.id}),true);
  }finally{reopened.close();}
});
test('active/unverified processes and escaping symlinks prevent migration without changing profile',async t=>{
  const {f,c,storage,source,base}=await setup(t);
  await mkdir(join(source,'workspace/ghidra-native/context/fixture'),{recursive:true});await writeFile(join(source,'workspace/ghidra-native/context/fixture/process.json'),JSON.stringify({pid:process.pid,kind:'context'}));
  await assert.rejects(storage.migrate(c,base,true),/Close the profile/);
  assert.equal((await f.profileStore.get()).values.analysisDirectory,undefined);
  await rm(join(source,'workspace/ghidra-native'),{recursive:true});
  if(process.platform==='win32')return;
  await symlink(f.root,join(source,'workspace/escape'));await assert.rejects(storage.migrate(c,base,true),/escapes/);
});

test('resume reclaims its own incomplete file and preserves the source',async t=>{
  const {c,storage,source,base,destination}=await setup(t,async phase=>{if(phase==='copied')throw Error('interrupted');});
  await assert.rejects(storage.migrate(c,base),/interrupted/);
  const j=JSON.parse(await readFile(join(source,'storage/migration.json'),'utf8')),partial=join(destination,'workspace/native database/program.db.insight-copy-'+j.id);
  await mkdir(join(destination,'workspace/native database'),{recursive:true});await writeFile(partial,'incomplete disposable bytes');
  const replacement=new AnalysisStorage(undefined,async()=>{});await replacement.resume(c);
  await assert.rejects(lstat(partial));assert.equal(await readFile(join(destination,'workspace/native database/program.db'),'utf8'),'native database bytes');
});
test('a pending migration veto cannot persist changed Factory runtime settings',async t=>{
  const {f,c,storage,base}=await setup(t,async phase=>{if(phase==='reserved')throw Error('interrupted');});
  await assert.rejects(storage.migrate(c,base),/interrupted/);
  const app=f.createApplication(runtime=>createInsightCli({runtime}));
  const result=await f.run(app,['profile','set','default','--max-contexts','5','--json']);assert.notEqual(result.exitCode,0);
  assert.equal((await f.profileStore.get()).values.maxContexts,undefined);
});
test('interrupted cleanup rejects an ordinary replacement directory with the same path',async t=>{
  const {f,c,storage,source,base}=await setup(t,async phase=>{if(phase==='cleanup-reserved')throw Error('interrupted');});
  await storage.migrate(c,base);const selected={...c,profile:await f.profileStore.get()};await assert.rejects(storage.cleanup(selected),/interrupted/);
  const j=JSON.parse(await readFile(join(source,'storage/migration.json'),'utf8')),retained=join(source,'.storage-retained',j.id);
  await rename(retained,retained+'-original');await mkdir(retained);await writeFile(join(retained,'foreign'),'preserve unrelated bytes');
  await assert.rejects(storage.resume(selected),/replaced/);assert.equal(await readFile(join(retained,'foreign'),'utf8'),'preserve unrelated bytes');
});
