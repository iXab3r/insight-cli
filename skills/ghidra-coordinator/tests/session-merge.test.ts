import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {Research} from '../src/research.js';
type Scope={session:string;target:string};
const selectors=(scope:Scope)=>['--session',scope.session,'--target',scope.target];
async function setup(t:Parameters<typeof createCliFixture>[0]) {
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const a=await f.json(app,['ghidra','open',exe,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',exe,'--session','new']) as Scope;
  const set=(who:Scope,at:string,text:string,extra:string[]=[])=>f.json(app,['ghidra','comments','set',...selectors(who),'--address',at,'--kind','eol','--text',text,...extra]);
  const get=async(who:Scope,at:string)=>(await f.json(app,['ghidra','comments','get',...selectors(who),'--address',at,'--kind','eol']) as {text:string|null}).text;
  return {f,app,a,b,set,get,backend:backend!};
}
test('A/B refresh receives disjoint changes, mixed conflict merges nothing, explicit nullable resolution publishes',async t=>{
  const {f,app,a,b,set,get,backend}=await setup(t);
  await set(a,'1000','A');await set(b,'1100','B');await f.json(app,['ghidra','merge',...selectors(a)]);
  assert.equal(await get(b,'1000'),null);
  const refresh=await f.json(app,['ghidra','refresh',...selectors(b)]) as {receivedChanges:number;preservedLocalChanges:number};
  assert.equal(refresh.receivedChanges,1);assert.equal(refresh.preservedLocalChanges,1);assert.equal(await get(b,'1000'),'A');assert.equal(await get(b,'1100'),'B');
  const repeated=await f.json(app,['ghidra','refresh',...selectors(b)]) as {receivedChanges:number};assert.equal(repeated.receivedChanges,0);
  await f.json(app,['ghidra','merge',...selectors(b)]);await f.json(app,['ghidra','refresh',...selectors(a)]);
  await set(a,'1000','A overlap');await set(b,'1000','B overlap');await set(b,'1100','B another');await f.json(app,['ghidra','merge',...selectors(a)]);
  const before=backend.publications,failed=await f.run(app,['ghidra','merge',...selectors(b),'--json']);assert.notEqual(failed.exitCode,0);assert.equal(backend.publications,before);
  const mixed=await f.json(app,['ghidra','refresh',...selectors(b)]) as {state:string};assert.equal(mixed.state,'conflict');assert.equal(await get(b,'1000'),'B overlap');
  const afterRefreshCount=backend.publications;
  assert.notEqual((await f.run(app,['ghidra','merge',...selectors(b),'--json'])).exitCode,0);
  assert.equal(backend.publications,afterRefreshCount,'Refresh must not turn an unresolved overlap into an unchanged-base overwrite');
  const stale=await f.run(app,['ghidra','comments','set',...selectors(b),'--address','1000','--kind','eol','--text','resolution','--resolve-conflict','--expect-shared','stale','--json']);
  assert.notEqual(stale.exitCode,0);assert.equal(await get(b,'1000'),'B overlap');
  await set(b,'1000','',['--resolve-conflict','--expect-shared','A overlap']);
  await f.json(app,['ghidra','merge',...selectors(b)]);assert.equal(await get(b,'1000'),null);assert.equal(await get(b,'1100'),'B another');
});
test('committed response loss freezes every publisher, then open reconciles without another check-in',async t=>{
  const {f,app,a,b,set,backend}=await setup(t);await set(a,'1000','saved A');backend.losePublication=true;backend.cannotVerify=true;
  const args=['ghidra','merge',...selectors(a),'--request-id','lost'];assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);
  const count=backend.publications;await set(b,'1100','private B');assert.notEqual((await f.run(app,['ghidra','merge',...selectors(b),'--json'])).exitCode,0);
  assert.equal(backend.publications,count);
  backend.cannotVerify=false;
  const opened=await f.json(app,['ghidra','open',...selectors(a)]) as {state:string;pendingChanges:number};assert.equal(opened.state,'ready');assert.equal(opened.pendingChanges,0);
  const retry=await f.json(app,args) as {state:string};assert.equal(retry.state,'merged');assert.equal(backend.publications,count);
});
test('lost setter response is reconciled from observed saved state, never by executing it again',async t=>{
  const {f,app,a,backend,get}=await setup(t);backend.loseSetter=true;
  const args=['ghidra','comments','set',...selectors(a),'--address','1000','--kind','eol','--text','retained','--request-id','setter'];
  assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);const edits=backend.edits;
  backend.loseSetter=false;await f.json(app,['ghidra','open',...selectors(a)]);
  assert.equal(await get(a,'1000'),'retained');assert.equal((await f.json(app,args) as {state:string}).state,'applied');assert.equal(backend.edits,edits);
});
test('one context orders a setter before merge and retains a setter queued after merge',async t=>{
  const {a,backend}=await setup(t),research=new Research(backend.workspace,async()=>backend);
  let release!:()=>void,started!:()=>void;
  const held=new Promise<void>(ok=>release=ok),entered=new Promise<void>(ok=>started=ok);
  const call=backend.call.bind(backend);let first=true;
  backend.call=async(scope,operation,parameters)=>{
    if(operation==='/set_comment'&&first){first=false;started();await held;}
    return call(scope,operation,parameters);
  };
  const before=research.edit(a,'1000','comment.eol','before merge');await entered;
  const merge=research.merge(a),after=research.edit(a,'1100','comment.eol','after merge');release();
  await before;
  assert.equal((await merge as {applied:number}).applied,1);await after;
  const saved=backend.workspace.context(a);assert.equal(saved.scalars.length,1);assert.equal(saved.scalars[0]!.local,'after merge');
  const shared=await backend.latest(a.target),fields=await backend.fields(shared.snapshot,[{address:'1000',field:'comment.eol'},{address:'1100',field:'comment.eol'}]);
  assert.equal(fields['1000@comment.eol']!.value,'before merge');assert.equal(fields['1100@comment.eol']!.value,null);
});
test('shared value changed again after explicit resolution prevents publication and preserves the decision',async t=>{
  const {f,app,a,b,set,get,backend}=await setup(t);
  await set(a,'1000','first shared');await set(b,'1000','private');await f.json(app,['ghidra','merge',...selectors(a)]);
  await f.json(app,['ghidra','refresh',...selectors(b)]);
  await set(b,'1000','decision',['--resolve-conflict','--expect-shared','first shared']);
  await set(a,'1000','newer shared');await f.json(app,['ghidra','merge',...selectors(a)]);
  const count=backend.publications;
  assert.notEqual((await f.run(app,['ghidra','merge',...selectors(b),'--json'])).exitCode,0);
  assert.equal(backend.publications,count);assert.equal(await get(b,'1000'),'decision');
});
