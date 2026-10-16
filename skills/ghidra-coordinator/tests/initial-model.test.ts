import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {Workspace} from '../src/workspace.js';
import {initializeModel,initialIntent} from '../src/initial-model.js';
import type {ServerBinding} from '../src/server.js';

const binding:ServerBinding={mode:'local',origin:'ghidra://127.0.0.1:25000',repository:'owned',readerUser:'reader',publisherUser:'publisher',readerSecret:'reader-secret',publisherSecret:'publisher-secret'};
async function fixture(t:{after:(fn:()=>Promise<void>)=>void}){
 const root=await mkdtemp(join(tmpdir(),'initial-model-unit-'));let workspace=new Workspace(join(root,'workspace'),'default');
 t.after(async()=>{workspace.close();await rm(root,{recursive:true,force:true});});
 const input=join(root,'input.exe');await writeFile(input,'synthetic immutable input');
 const target=await workspace.importTarget(input);workspace.reserveOpen(target.id,'new',{autoAnalyze:true},'open');
 const snapshot=Buffer.from('synthetic complete snapshot'),hash=createHash('sha256').update(snapshot).digest('hex');
 let prepared=0,published=0,verified=0;const server={
  async initialImport(root:string){prepared++;await writeFile(join(root,'attempt-00000000-0000-0000-0000-000000000000.gzf'),snapshot);
   await writeFile(join(root,'import.json'),JSON.stringify({snapshot:'attempt-00000000-0000-0000-0000-000000000000.gzf',snapshotSha256:hash}));return {state:'prepared'};},
  async initialPublication(_binding:ServerBinding,_root:string,operation:'stage'|'verify-stage'|'promote'|'verify'='stage'){if(operation.startsWith('verify'))verified++;else published++;return {state:operation==='verify'?'verified':'published',version:1,snapshotBuffersVerified:true};}
 };
 return {root,target,server,get workspace(){return workspace;},restart(){workspace.close();workspace=new Workspace(join(root,'workspace'),'default');},counts:()=>({prepared,published,verified})};
}
test('interrupted private analysis retains intent across workspace restart and never publishes partial input',async t=>{
 const f=await fixture(t),original=f.server.initialImport;
 f.server.initialImport=async()=>{throw Error('Synthetic worker exit during analysis');};
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'runtime'),/worker exit/);
 const intent=await initialIntent(f.workspace,f.target.id);assert.equal(f.workspace.model(f.target.id).state,'unknown');assert.equal(f.counts().published,0);
 f.restart();f.server.initialImport=original;
 await initializeModel(f.workspace,f.target,binding,f.server,'runtime');
 assert.deepEqual(await initialIntent(f.workspace,f.target.id),intent);assert.equal(f.workspace.model(f.target.id).sharedRevision,1);assert.equal(f.counts().verified,1);
});
test('lost initial creation reply reconciles the same bound snapshot before establishing R1',async t=>{
 const f=await fixture(t),original=f.server.initialPublication;let committed=false;
 f.server.initialPublication=async(_binding,_root,operation='stage')=>{if(operation==='stage'){assert.equal(committed,false);committed=true;throw Error('Synthetic lost create reply');}return original(_binding,_root,operation);};
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'runtime'),/lost create reply/);
 const intent=await initialIntent(f.workspace,f.target.id);assert.equal(f.workspace.model(f.target.id).state,'unknown');
 f.restart();f.server.initialPublication=async(_binding,_root,operation='stage')=>{assert.equal(committed,true);return original(_binding,_root,operation);};
 await initializeModel(f.workspace,f.target,binding,f.server,'runtime');
 assert.deepEqual(await initialIntent(f.workspace,f.target.id),intent);assert.equal(f.counts().verified,1);assert.equal(f.workspace.model(f.target.id).state,'ready');
});
test('changed authority/runtime or a mismatched saved snapshot never establishes or publishes a different model',async t=>{
 const f=await fixture(t);f.server.initialImport=async()=>({state:'busy'});
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'runtime'),/still active/);
 await assert.rejects(initializeModel(f.workspace,f.target,{...binding,repository:'other'},f.server,'runtime'),/differs/);
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'changed'),/differs/);assert.equal(f.counts().published,0);
 const root=join(f.workspace.directory,'ghidra-native','initial',f.target.id);
 f.server.initialImport=async()=>{await writeFile(join(root,'attempt-00000000-0000-0000-0000-000000000000.gzf'),'changed');
   await writeFile(join(root,'import.json'),JSON.stringify({snapshot:'attempt-00000000-0000-0000-0000-000000000000.gzf',snapshotSha256:'0'.repeat(64)}));return {state:'prepared'};};
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'runtime'),/changed before/);assert.equal(f.workspace.model(f.target.id).state,'unknown');assert.equal(f.counts().published,0);
});
test('canonical promotion requires independent staging proof followed by independent canonical proof',async t=>{
 const f=await fixture(t),operations:string[]=[];
 f.server.initialPublication=async(_binding,_root,operation='stage')=>{operations.push(operation);return {state:{stage:'staged','verify-stage':'stage_verified',promote:'published',verify:'verified'}[operation],version:1,snapshotBuffersVerified:true};};
 await initializeModel(f.workspace,f.target,binding,f.server,'runtime');
 assert.deepEqual(operations,['stage','verify-stage','promote','verify']);assert.equal(f.workspace.model(f.target.id).state,'ready');
});
test('failed independent staging proof never invokes canonical promotion',async t=>{
 const f=await fixture(t),operations:string[]=[];
 f.server.initialPublication=async(_binding,_root,operation='stage')=>{operations.push(operation);return {state:operation==='stage'?'staged':'unknown',version:1,snapshotBuffersVerified:false};};
 await assert.rejects(initializeModel(f.workspace,f.target,binding,f.server,'runtime'),/Independent initial staging/);
 assert.deepEqual(operations,['stage','verify-stage']);assert.equal(f.workspace.model(f.target.id).state,'unknown');
});
