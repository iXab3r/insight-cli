import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {Workspace} from '../src/workspace.js';
import {SessionBackend} from './fixtures/session-backend.js';

test('CLI and RPC progress stay readable while the original open owns the context boundary', {timeout:15000},async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
 let entered!:()=>void,release!:()=>void,workspace!:Workspace,opens=0;
 const started=new Promise<void>(resolve=>{entered=resolve;}),blocked=new Promise<void>(resolve=>{release=resolve;});
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{
  workspace=w;const backend=new SessionBackend(w),open=backend.open.bind(backend);
  backend.open=async(...args)=>{opens++;if(opens>1){entered();await blocked;}return open(...args);};return backend;
 }}));
 const input=join(f.root,'long-analysis.exe');await writeFile(input,'synthetic long analysis input');
 const selected=await f.json(app,['ghidra','open',input,'--session','new','--analysis']) as {session:string;target:string};
 const pending=f.run(app,['ghidra','open','--session',selected.session,'--target',selected.target,'--json']);
 try{
  await started;const root=join(workspace.directory,'ghidra-native','initial',selected.target);
  await mkdir(root,{recursive:true});await writeFile(join(root,'progress.json'),JSON.stringify({schema:1,target:selected.target,phase:'analysis',state:'running',pid:process.pid,
   startedAt:new Date().toISOString(),updatedAt:new Date().toISOString(),message:'Scalar Operand References',completed:173,total:500,indeterminate:false}));
  const before=workspace.context(selected),requests=workspace.unresolved(selected),argv=['ghidra','progress','--session',selected.session,'--target',selected.target];
  const limit=AbortSignal.timeout(5000),timedOut=new Promise<never>((_,reject)=>limit.addEventListener('abort',()=>reject(Error('Progress queued behind initial open')),{once:true}));
  const observed=await Promise.race([f.json(app,argv),timedOut]) as any;
  assert.equal(observed.progress.message,'Scalar Operand References');assert.equal(observed.progress.completed,173);assert.equal(observed.progress.workerAlive,true);
  const [rpc]=await Promise.race([f.rpc(app,[argv]),timedOut]) as any[];assert.equal(rpc.result.progress.completed,173);assert.equal(rpc.result.progress.phase,'analysis');
  assert.equal(opens,2);assert.deepEqual(workspace.context(selected),before);assert.deepEqual(workspace.unresolved(selected),requests);
 }finally{release();await pending;}
});
