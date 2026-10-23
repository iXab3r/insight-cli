import {CliError} from '@eyeauras/cli-factory';
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
  const args=['ghidra','close',...select,'--request-id','lost-close'];assert.equal((await f.run(app,args)).exitCode,1);assert.equal((await f.json(app,args) as {state:string}).state,'closed');assert.equal(releases,1);
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

test('ENOSPC close without a caller ID retrieves its status identity and proves release without another open or close',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,releases=0,opens=0;
  const create=()=>f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const close=backend.close.bind(backend),open=backend.open.bind(backend);
    backend.open=async(...args)=>{opens++;return open(...args);};
    return Object.assign(backend,{close:async(selected:{session:string;target:string})=>{releases++;await close(selected);throw Object.assign(Error('Synthetic stop receipt disk full'),{code:'ENOSPC'});},
      closed:async(selected:{session:string;target:string})=>!backend.views.has(workspace.context(selected).id)});
  }}));
  let app=create();const exe=join(f.root,'fixture.exe');await writeFile(exe,'synthetic release after disk failure');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','retained private']);
  assert.equal((await f.run(app,['ghidra','close',...select])).exitCode,1);
  const status=await f.json(app,['sessions','status',who.session,'--target',who.target]) as {ghidra:{state:string;unresolvedRequests:{id:string;operation:string}[]}};
  assert.equal(status.ghidra.state,'needs_recovery');assert.equal(status.ghidra.unresolvedRequests.length,1);
  const request=status.ghidra.unresolvedRequests[0]!;assert.equal(request.operation,'ghidra.close');const opensBefore=opens;
  await app.dispose();app=create();
  const args=['ghidra','close',...select,'--request-id',request.id],result=await f.json(app,args) as {state:string;pendingChanges:number};
  assert.equal(result.state,'closed');assert.equal(result.pendingChanges,1);assert.deepEqual(await f.json(app,args),result);
  assert.equal(releases,1);assert.equal(opens,opensBefore);assert.equal(backend!.publications,0);
  assert.equal(backend!.workspace.context(who).state,'stopped');assert.equal(backend!.workspace.unresolved(who).length,0);
  assert.equal((await f.run(app,['ghidra','save',...select,'--request-id',request.id])).exitCode,1);
  await f.json(app,['ghidra','open',...select]);
  assert.equal((await f.json(app,['ghidra','comments','get',...select,'--address','1000','--kind','eol']) as {text:string}).text,'retained private');
});

test('ENOSPC before release retains unknown close and provides scoped recovery until the original worker ends',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,releases=0,ended=false;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);return Object.assign(backend,{close:async()=>{releases++;throw Object.assign(Error('Synthetic snapshot disk full'),{code:'ENOSPC'});},closed:async()=>ended});
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'synthetic live worker after disk failure');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  const args=['ghidra','close',...select,'--request-id','caller-close'];assert.equal((await f.run(app,args)).exitCode,1);
  const before=backend!.workspace.context(who),request=backend!.workspace.unresolved(who)[0]!;
  const other=join(f.root,'other.exe');await writeFile(other,'independent target');
  const otherWho=await f.json(app,['ghidra','open',other,'--session',who.session]) as {session:string;target:string};
  assert.equal((await f.json(app,['ghidra','comments','get','--session',otherWho.session,'--target',otherWho.target,'--address','1000','--kind','eol']) as {text:unknown}).text,null);
  const retry=await f.run(app,[...args,'--json']);assert.equal(retry.exitCode,1);const failure=JSON.parse(retry.stderr).error;assert.equal(failure.code,'coordinator.unknown');
  assert.ok(failure.next.some((argv:string[])=>argv.slice(0,2).join(' ')==='tools processes'&&argv.includes(who.session)&&argv.includes(who.target)));
  assert.equal(releases,1);assert.equal(backend!.workspace.unresolved(who)[0]!.id,request.id);assert.deepEqual(backend!.workspace.context(who),before);
  const continuation=await f.run(app,['ghidra','open',...select,'--json']);assert.equal(continuation.exitCode,1);
  const next=JSON.parse(continuation.stderr).error.next[0];assert.deepEqual(next.slice(0,2),['ghidra','close']);assert.ok(next.includes('caller-close'));
  assert.equal(backend!.workspace.unresolved(who)[0]!.id,request.id);
  ended=true;
  const result=await f.json(app,['ghidra','close',...select,'--request-id',request.id]) as {state:string};assert.equal(result.state,'closed');assert.equal(releases,1);
});


test('generated save ID retrieves its retained snapshot under automatic publication without another workflow',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,opens=0,saves=0,failed=false;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const complete=workspace.completeSavedRequest.bind(workspace),open=backend.open.bind(backend),saved=backend.saved.bind(backend);
    workspace.completeSavedRequest=(...args:Parameters<typeof complete>)=>{if(workspace.request(args[1]).operation==='ghidra.save'&&!failed){failed=true;throw Object.assign(Error('Synthetic save acknowledgment disk full'),{code:'ENOSPC'});}return complete(...args);};
    backend.open=async(...args)=>{opens++;return open(...args);};backend.saved=async selected=>{saves++;return saved(selected);};return backend;
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'synthetic automatic save recovery');
  const who=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','private']);
  await f.json(app,['ghidra','sync-policy','set',...select,'--publish','after-save','--refresh','manual']);
  assert.equal((await f.run(app,['ghidra','save',...select])).exitCode,1);
  const request=backend!.workspace.unresolved(who)[0]!,before={opens,saves};
  const shadow=backend!.workspace.reserveAdministration('ghidra.automatic',{session:who.session,target:who.target},request.id).request;
  backend!.workspace.administrationState(shadow.id,'unknown',{phase:'local'});
  const external=backend!.workspace.unresolvedSessionAdministration(who.session).map(row=>row.id);
  const result=await f.json(app,['ghidra','save',...select,'--request-id',request.id]) as {state:string;pendingChanges:number};
  assert.equal(result.state,'saved');assert.equal(result.pendingChanges,1);assert.deepEqual({opens,saves},before);assert.equal(backend!.publications,0);
  assert.equal(backend!.workspace.request(request.id).state,'applied');assert.deepEqual(backend!.workspace.unresolvedSessionAdministration(who.session).map(row=>row.id),external);
});

test('open continuation reports its recovery cause and retains the original unknown request',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,attempts=0,failOpen=true;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const open=backend.open.bind(backend);
    backend.open=async(scope,request)=>{attempts++;if(failOpen)throw new CliError('Native context ownership mismatch',{code:'coordinator.binding'});return open(scope,request);};return backend;
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'synthetic input, never executed');
  const first=await f.run(app,['ghidra','open',input,'--session','new','--json']);assert.equal(first.exitCode,1);
  const who=JSON.parse(first.stdout),select=['--session',who.session,'--target',who.target];
  const original=backend!.workspace.unresolved(who)[0]!;
  const again=await f.run(app,['ghidra','open',...select,'--json']);assert.equal(again.exitCode,1);
  assert.match(again.stderr,/Native context ownership mismatch/);assert.doesNotMatch(again.stderr,/unproved effect/);
  assert.deepEqual(backend!.workspace.unresolved(who).map(row=>row.id),[original.id]);assert.equal(attempts,2);
  const status=await f.json(app,['sessions','status',who.session,'--target',who.target]) as {ghidra:{state:string}};
  assert.equal(status.ghidra.state,'needs_recovery');
  failOpen=false;assert.equal((await f.json(app,['ghidra','open',...select]) as {state:string}).state,'ready');
  assert.equal(backend!.workspace.request(original.id).state,'applied');assert.equal(backend!.publications,0);
});
