import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {Research} from '../src/research.js';
import type {Scope} from '../src/workspace.js';

test('opaque edits replace tracked scalar values before refresh, preserving the actual local conflict',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned projection fixture');
  const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=(who:Scope)=>['--session',who.session,'--target',who.target];
  const edit=(who:Scope,text:string)=>f.json(app,['ghidra','comments','set',...select(who),'--address','1000','--kind','eol','--text',text]);
  await edit(a,'first scalar');const call=backend!.call.bind(backend!);backend!.call=async(selected,path,p)=>{
    if(path!=='/fixture/complex')return call(selected,path,p);
    backend!.views.get(backend!.workspace.context(selected).id)!.view.comments['1000']!.eol='actual complex value';return {status:'success'};
  };
  await new Research(backend!.workspace,async()=>backend!).mutate(a,'/fixture/complex',{},async(_backend,response)=>response);
  assert.equal(backend!.workspace.context(a).scalars[0]!.local,'actual complex value');
  await edit(b,'shared value');await f.json(app,['ghidra','merge',...select(b)]);const refreshed=await f.json(app,['ghidra','refresh',...select(a)]) as {state:string;conflicts:{local:string}[]};
  assert.equal(refreshed.state,'conflict');assert.ok(refreshed.conflicts.some(conflict=>conflict.local==='actual complex value'));
  assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','1000','--kind','eol']) as {text:string}).text,'actual complex value');
});

test('deleting a renamed function retains a removed field until whole-state publication, without resurrecting its stale name',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned deletion projection');const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=(who:Scope)=>['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','functions','rename',...select(a),'--address','1100','--name','renamed']);
  const call=backend!.call.bind(backend!);backend!.call=async(selected,path,p)=>{
    if(path!=='/fixture/delete')return call(selected,path,p);delete backend!.views.get(backend!.workspace.context(selected).id)!.view.names['1100'];return {status:'success'};
  };
  await new Research(backend!.workspace,async()=>backend!).mutate(a,'/fixture/delete',{},async(_backend,response)=>response);
  const pending=backend!.workspace.context(a).scalars[0]!;assert.equal(pending.removed,true);assert.equal(pending.local,null);
  await f.json(app,['ghidra','merge',...select(a)]);await f.json(app,['ghidra','refresh',...select(b)]);
  assert.notEqual((await f.run(app,['ghidra','functions','get',...select(b),'--address','1100'])).exitCode,0);assert.equal(backend!.publications,1);
});
