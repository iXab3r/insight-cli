import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {setTimeout as delay} from 'node:timers/promises';
import {initialProgress,readInitialProgress,progressPhase} from '../src/initial-progress.js';

async function fixture(t:{after:(action:()=>Promise<void>)=>void}){
 const directory=await mkdtemp(join(tmpdir(),'initial-progress-')),target='t_'+'a'.repeat(32),root=join(directory,'ghidra-native','initial',target);
 t.after(()=>rm(directory,{recursive:true,force:true}));await mkdir(root,{recursive:true});return {directory,target,root};
}
test('progress is passive, carries task counters and detects dead/stale workers without claiming completion',async t=>{
 const f=await fixture(t);assert.equal(await readInitialProgress(f.directory,f.target),null);
 await initialProgress(f.root,f.target,'analysis');const file=join(f.root,'progress.json');
 const p=JSON.parse(await readFile(file,'utf8'));await writeFile(file,JSON.stringify({...p,completed:7,total:23,message:'Finding functions',pid:2147483647,updatedAt:new Date(Date.now()-20000).toISOString()}));
 const observed=await readInitialProgress(f.directory,f.target);assert.equal(observed.phase,'analysis');assert.equal(observed.state,'running');assert.equal(observed.observation,'stale');assert.equal(observed.workerAlive,false);assert.equal(observed.completed,7);assert.equal(observed.total,23);assert.equal(observed.percent,undefined);
});
test('prepared and publication share start time; terminal elapsed time freezes',async t=>{
 const f=await fixture(t);await initialProgress(f.root,f.target,'save');const first=await readInitialProgress(f.directory,f.target);
 await delay(10);await initialProgress(f.root,f.target,'snapshot-verification','prepared');await initialProgress(f.root,f.target,'publication-stage');
 await initialProgress(f.root,f.target,'complete','complete');const done=await readInitialProgress(f.directory,f.target);await delay(15);
 const later=await readInitialProgress(f.directory,f.target);assert.equal(done.startedAt,first.startedAt);assert.equal(done.elapsedMs,later.elapsedMs);assert.equal(done.state,'complete');
});
test('phase heartbeat observes a live operation and original failure remains the failure',async t=>{
 const f=await fixture(t);const failure=Error('synthetic native failure');
 await assert.rejects(progressPhase(f.root,f.target,'publication-verify',async()=>{const p=await readInitialProgress(f.directory,f.target);assert.equal(p.phase,'publication-verify');assert.equal(p.workerAlive,true);throw failure;}),error=>error===failure);
 await initialProgress(f.root,f.target,'publication-verify','unknown');const p=await readInitialProgress(f.directory,f.target);assert.equal(p.state,'unknown');assert.equal(p.phase,'publication-verify');
});
