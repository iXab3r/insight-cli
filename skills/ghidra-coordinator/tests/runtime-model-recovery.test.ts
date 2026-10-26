import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash,randomUUID} from 'node:crypto';
import {Workspace} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import {initialRoot,initialIntent,initializeModel} from '../src/initial-model.js';
import type {GhidraServer,ServerBinding} from '../src/server.js';
import type {NativeInputs} from '../src/native-inputs.js';
import type {CommandContext} from '@eyeauras/cli-factory';
const fingerprint='b'.repeat(64),old='a'.repeat(64);
const binding:ServerBinding={mode:'local',origin:'ghidra://127.0.0.1:25000',repository:'owned',readerUser:'reader',publisherUser:'publisher',readerSecret:'r',publisherSecret:'p'};
const sha=(bytes:string)=>createHash('sha256').update(bytes).digest('hex');
async function fixture(t:{after:(fn:()=>Promise<void>)=>void}){
 const directory=await mkdtemp(join(tmpdir(),'runtime-model-')),workspace=new Workspace(join(directory,'workspace'),'fixture');
 t.after(async()=>{workspace.close();await rm(directory,{recursive:true,force:true});});
 const file=join(directory,'input.exe');await writeFile(file,'synthetic immutable input');const target=await workspace.importTarget(file);
 const a=workspace.reserveOpen(target.id,'new',{autoAnalyze:true},'agent-A'),b=workspace.reserveOpen(target.id,'new',{autoAnalyze:true},'agent-B');
 const root=initialRoot(workspace,target.id);await mkdir(root,{recursive:true});
 await writeFile(join(root,'intent.json'),JSON.stringify({schema:1,id:randomUUID(),target:target.id,sha256:target.binarySha256,input:await workspace.artifacts.verify(target.input),
  settings:workspace.model(target.id).settings,origin:binding.origin,repository:binding.repository,readerUser:binding.readerUser,publisherUser:binding.publisherUser,runtimeFingerprint:old}));
 workspace.beginModelInitialization(target.id);workspace.startRequest(a.request.id);workspace.recordRequest(a.request.id,'unknown',{state:'unknown'});
 const original=await readFile(join(root,'intent.json'),'utf8');let imports=0,publications=0,probes=0;
 const snapshot='latest R3 with committed annotation',name='canonical-'+randomUUID()+'.gzf',receipt=name.replace('.gzf','.json');await writeFile(join(root,name),snapshot);
 const server={fork:(_c:CommandContext)=>server,ensure:async()=>binding,
  initialRecovery:async(_binding:ServerBinding,_root:string,_fp:string,proof=''):Promise<Record<string,unknown>>=>{probes++;return {state:proof?'verified':'candidate',version:3,snapshot:name,snapshotSha256:sha(snapshot),receipt,snapshotBuffersVerified:!!proof};},
  initialImport:async(at:string)=>{imports++;await writeFile(join(at,'attempt-00000000-0000-0000-0000-000000000000.gzf'),'new private seed');
   await writeFile(join(at,'import.json'),JSON.stringify({snapshot:'attempt-00000000-0000-0000-0000-000000000000.gzf',snapshotSha256:sha('new private seed')}));return {state:'prepared'};},
  initialPublication:async(_binding:ServerBinding,_root:string,operation='stage')=>{publications++;return {state:operation==='verify'?'verified':'published',version:1,snapshotBuffersVerified:true};}
 };
 const c={profile:{values:{}},signal:new AbortController().signal} as CommandContext;
 const backend=new GhidraContexts(workspace,{fingerprint} as NativeInputs,c,undefined,undefined,server as unknown as GhidraServer);
 return {workspace,target,root,original,a,b,server,backend,c,counts:()=>({imports,publications,probes})};
}
test('bridge upgrade recovers latest canonical R3 for concurrent agents, preserving original request and private pending edits',async t=>{
 const f=await fixture(t),file=join(f.root,'private.gzf');await writeFile(file,'private pending changes');const privateSnapshot=await f.workspace.captureSnapshot(file);
 f.workspace.saveContext(f.b.context,0,{workingSnapshot:privateSnapshot,baseSnapshot:privateSnapshot,baseRevision:2,scalars:[{address:'1000',field:'comment.eol',original:null,local:'private'}]});
 const before=f.workspace.context(f.b.context),request=f.workspace.request(f.a.request.id);
 const second=f.backend.fork(f.c);assert.deepEqual(await Promise.all([f.backend.recoverModel(f.target.id),second.recoverModel(f.target.id)]),[true,true]);
 assert.equal(f.workspace.model(f.target.id).sharedRevision,3);assert.deepEqual(f.workspace.context(f.b.context),before);assert.deepEqual(f.workspace.request(request.id),request);
 assert.equal(await readFile(join(f.root,'intent.json'),'utf8'),f.original);assert.deepEqual(f.counts(),{imports:0,publications:0,probes:2});
 assert.equal(await readFile(await f.workspace.artifacts.verify(f.workspace.model(f.target.id).sharedSnapshot!),'utf8'),'latest R3 with committed annotation');
});
test('authoritative absence uses separate current-runtime preparation once for two sessions',async t=>{
 const f=await fixture(t);f.server.initialRecovery=async()=>{const root=join(f.root,'runtime-'+fingerprint);await mkdir(root,{recursive:true});
  const original=await initialIntent(f.workspace,f.target.id);await writeFile(join(root,'intent.json'),JSON.stringify({...original,id:randomUUID(),runtimeFingerprint:fingerprint,recoveryOf:sha(f.original)}));
  return {state:'absent',root:'runtime-'+fingerprint};};
 assert.deepEqual(await Promise.all([f.backend.recoverModel(f.target.id),f.backend.fork(f.c).recoverModel(f.target.id)]),[true,true]);
 assert.equal(f.workspace.model(f.target.id).sharedRevision,1);assert.equal(f.counts().imports,1);assert.equal(await readFile(join(f.root,'intent.json'),'utf8'),f.original);
 assert.equal(f.workspace.request(f.a.request.id).state,'unknown');
});
test('unknown or live native outcomes never import or adopt canonical state',async t=>{
 for(const state of ['unknown','busy']){const f=await fixture(t);f.server.initialRecovery=async()=>({state});
  await assert.rejects(f.backend.recoverModel(f.target.id),/reconciliation|active/);assert.equal(f.workspace.model(f.target.id).state,'unknown');assert.equal(f.counts().imports,0);}
});
test('revision or snapshot proof changes between export and independent readback block recovery',async t=>{
 for(const change of [{version:4},{snapshotBuffersVerified:false},{snapshot:'canonical-'+randomUUID()+'.gzf'},{snapshotSha256:'0'.repeat(64)}]){
  const f=await fixture(t),original=f.server.initialRecovery;f.server.initialRecovery=async(b,r,fp,proof='')=>({...await original(b,r,fp,proof),...(proof?change:{})});
  await assert.rejects(f.backend.recoverModel(f.target.id),/changed|unproved/);assert.equal(f.workspace.model(f.target.id).state,'unknown');assert.equal(f.counts().publications,0);
 }
});
test('changed target, loader settings or repository authority rejects before recovery probes',async t=>{
 for(const change of [{target:'t_'+'0'.repeat(32)},{sha256:'0'.repeat(64)},{settings:{autoAnalyze:false}},{settings:{autoAnalyze:true,loader:'other'}},{repository:'foreign'},{readerUser:'foreign'},{origin:'ghidra://other:25000'}]){
  const f=await fixture(t);await writeFile(join(f.root,'intent.json'),JSON.stringify({...JSON.parse(f.original),...change}));
  await assert.rejects(f.backend.recoverModel(f.target.id),/differs/);assert.deepEqual(f.counts(),{imports:0,publications:0,probes:0});
 }
});
test('unknown shared publication freezes upgrade recovery for every session',async t=>{
 const f=await fixture(t),path=join(f.root,'base.gzf');await writeFile(path,'base');const snapshot=await f.workspace.captureSnapshot(path);f.workspace.establishModel(f.target.id,2,snapshot);
 f.workspace.saveContext(f.b.context,0,{baseRevision:2,baseSnapshot:snapshot,workingSnapshot:snapshot,state:'ready'});
 const request=f.workspace.reserveRequest(f.b.context,'ghidra.merge',{},'merge').request;f.workspace.startRequest(request.id);
 const publication=f.workspace.beginPublication(f.b.context,request.id,2,snapshot);f.workspace.publicationIntent(publication.id);f.workspace.unknownPublication(publication.id,{state:'unknown'});
 assert.equal(await f.backend.recoverModel(f.target.id),false);assert.deepEqual(f.counts(),{imports:0,publications:0,probes:0});assert.equal(f.workspace.activePublication(f.target.id)?.id,publication.id);
});
test('strict initial import still rejects runtime changes outside recovery',async t=>{
 const f=await fixture(t);await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,fingerprint),/differs/);assert.equal(f.counts().imports,0);
});
