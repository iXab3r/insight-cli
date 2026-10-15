import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import type {Scope} from '../src/workspace.js';
import type {Artifact} from '../src/artifacts.js';

test('local discard retains the former private snapshot, leaves shared/other views alone and recovers a lost local switch',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let backend:SessionBackend,lost=false;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const complete=workspace.completeSavedRequest.bind(workspace);
    workspace.completeSavedRequest=(...args:Parameters<typeof complete>)=>{if(lost&&workspace.request(args[1]).operation==='ghidra.changes.discard'){lost=false;throw Error('Synthetic discard acknowledgment loss');}return complete(...args);};
    return Object.assign(backend,{closed:async(scope:Scope)=>!backend.views.has(workspace.context(scope).id)});
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned discard fixture');
  const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=(who:Scope)=>['--session',who.session,'--target',who.target];
  const edit=(who:Scope,text:string)=>f.json(app,['ghidra','comments','set',...select(who),'--address','1000','--kind','eol','--text',text]);
  await edit(a,'private A');await edit(b,'published B');await f.json(app,['ghidra','merge',...select(b)]);
  const discard=['ghidra','changes','discard',...select(a),'--request-id','discard'];const result=await f.json(app,discard) as {state:string;discardedSnapshot:Artifact};assert.equal(result.state,'discarded');assert.deepEqual(await f.json(app,discard),result);
  const prior=JSON.parse(await readFile(await backend!.workspace.artifacts.verify(result.discardedSnapshot),'utf8'));assert.equal(prior.comments['1000'].eol,'private A');
  await f.json(app,['ghidra','open',...select(a)]);assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','1000','--kind','eol']) as {text:null}).text,null);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address','1000','--kind','eol']) as {text:string}).text,'published B');assert.equal(backend!.publications,1);
  await edit(a,'second private A');lost=true;const uncertain=['ghidra','changes','discard',...select(a),'--request-id','lost-discard'];assert.notEqual((await f.run(app,uncertain)).exitCode,0);
  await f.json(app,['ghidra','open',...select(a)]);assert.equal((await f.json(app,uncertain) as {state:string}).state,'discarded');assert.equal(backend!.publications,1);
});

test('session-wide save selects all and only that session, preserves partial outcomes and does not replay',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let saves=0,failTarget:string|undefined;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace),save=backend.saved.bind(backend);backend.saved=async(scope:Scope)=>{saves++;if(scope.target===failTarget)throw Error('Synthetic selected save failure');return save(scope);};return backend;
  }}));
  const one=join(f.root,'one.exe'),two=join(f.root,'two.exe');await writeFile(one,'one owned input');await writeFile(two,'two owned input');
  const a=await f.json(app,['ghidra','open',one,'--session','new']) as Scope,other=await f.json(app,['ghidra','open',two,'--session',a.session]) as Scope;
  await f.json(app,['ghidra','open',one,'--session','new']);saves=0;
  const all=['ghidra','save-all','--session',a.session,'--request-id','all'];const result=await f.json(app,all) as {saved:number;items:Scope[]};assert.equal(result.saved,2);assert.ok(result.items.every(item=>item.session===a.session));assert.equal(saves,2);assert.deepEqual(await f.json(app,all),result);assert.equal(saves,2);
  failTarget=other.target;const partial=['ghidra','save-all','--session',a.session,'--request-id','partial'];assert.notEqual((await f.run(app,partial)).exitCode,0);assert.equal(saves,4);assert.notEqual((await f.run(app,partial)).exitCode,0);assert.equal(saves,4);
});
