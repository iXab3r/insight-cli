import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
test('scoped health/save/close preserve pending private work and repeat close ID without another release',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,releases=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const call=backend.call.bind(backend),close=backend.close.bind(backend);
    backend.call=async(scope,path,p)=>path==='/check_connection'?{status:'ok',server_kind:'headless',version:'7.0.0'}:
      path==='/mcp/health'?{status:'ok',connected:true,server_kind:'headless',version:{plugin_version:'7.0.0'},memory_mb:{used:1}}:call(scope,path,p);
    backend.close=async scope=>{releases++;await close(scope);};return backend;
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','pending private']);
  const health=await f.json(app,['ghidra','status',...select]) as {health:{connected:boolean};ghidra:{pendingChanges:number}};assert.equal(health.health.connected,true);assert.equal(health.ghidra.pendingChanges,1);
  assert.equal((await f.json(app,['ghidra','save',...select]) as {pendingChanges:number}).pendingChanges,1);
  const intent=['ghidra','close',...select,'--request-id','close'];const result=await f.json(app,intent);assert.deepEqual(await f.json(app,intent),result);assert.equal(releases,1);
  await f.json(app,['ghidra','open',...select]);assert.equal((await f.json(app,['ghidra','comments','get',...select,'--address','1000','--kind','eol']) as {text:string}).text,'pending private');
  assert.equal(backend!.publications,0);
});

test('lost close acknowledgment reconciles verified release without closing a second process',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let releases=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace),close=backend.close.bind(backend);
    return Object.assign(backend,{close:async(selected:{session:string;target:string})=>{releases++;await close(selected);throw Error('Synthetic lost close acknowledgment');},
      closed:async(selected:{session:string;target:string})=>!backend.views.has(workspace.context(selected).id)});
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','pending']);
  const args=['ghidra','close',...select,'--request-id','lost-close'];assert.equal((await f.run(app,args)).exitCode,1);assert.equal((await f.run(app,args)).exitCode,1);assert.equal(releases,1);
  await f.json(app,['ghidra','open',...select]);assert.equal((await f.json(app,args) as {state:string}).state,'closed');assert.equal(releases,1);
  assert.equal((await f.json(app,['ghidra','comments','get',...select,'--address','1000','--kind','eol']) as {text:string}).text,'pending');
});

test('lost save acknowledgment adopts only its retained snapshot and preserves pending work',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let failed=false;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const complete=workspace.completeSavedRequest.bind(workspace);
    workspace.completeSavedRequest=(...args:Parameters<typeof complete>)=>{if(workspace.request(args[1]).operation==='ghidra.save'&&!failed){failed=true;throw Error('Synthetic failed local acknowledgment');}return complete(...args);};
    return new SessionBackend(workspace);
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','pending']);
  const args=['ghidra','save',...select,'--request-id','lost-save'];assert.equal((await f.run(app,args)).exitCode,1);
  await f.json(app,['ghidra','open',...select]);assert.equal((await f.json(app,args) as {pendingChanges:number}).pendingChanges,1);
  assert.equal((await f.json(app,['ghidra','comments','get',...select,'--address','1000','--kind','eol']) as {text:string}).text,'pending');
});
