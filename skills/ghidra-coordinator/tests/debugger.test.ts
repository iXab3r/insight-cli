import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {debuggerResult,debuggerExecutionSettled} from '../src/debugger-results.js';
import type {Scope} from '../src/workspace.js';
import type {Artifact} from '../src/artifacts.js';

test('debugger program metadata stays private and pending, while CPU steps add no program edit; lost responses retain metadata on close',async t=>{
  for(const lost of [false,true]){
    const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let backend:SessionBackend,connected=false,placed=false,sets=0,snap=0;
    const trace='trace_00000000-0000-4000-8000-000000000001';
    const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
      backend=new SessionBackend(workspace);const close=backend.close.bind(backend);
      return Object.assign(backend,{inspect:async(snapshot:Artifact)=>{const view=JSON.parse(await readFile(await workspace.artifacts.verify(snapshot),'utf8'));return {fingerprint:createHash('sha256').update(view.opaque).digest('hex'),count:view.opaque==='base'?0:1};},
        debuggerStart:async()=>{},closed:async()=>!connected,close:async(selected:Scope)=>{connected=false;await close(selected);},
        debuggerLaunch:async()=>{connected=true;return {status:'launched',offer_title:'fixture',trace_name:'fixture'};},
        debuggerSaved:async(selected:Scope)=>({connected,active:trace,traces:[{id:trace,name:'fixture',snapshot:workspace.context(selected).workingSnapshot!,snap:'0',modules:1,threads:1,connected}]}),
        debuggerCall:async(selected:Scope,operation:string)=>{
          if(operation==='status')return {debugger_active:true,trace_active:true,open_traces:1,target_connected:connected,module_count:1,snap,execution_state:'STOPPED'};
          if(operation==='step'){snap++;return {status:'stepped'};}
          if(operation==='list_breakpoints')return placed?[{address:'1000',name:'',state:'ENABLED',kinds:['SW_EXECUTE'],trace_location_count:1}]:[];
          if(operation==='set_breakpoint'){sets++;placed=true;backend.views.get(workspace.context(selected).id)!.view.opaque='breakpoint';if(lost)throw Error('Synthetic lost breakpoint response');return {status:'set',address:'1000'};}
          throw Error('Unexpected debugger fixture operation');
        }});
    }}));
    const input=join(f.root,'fixture.exe');await writeFile(input,'owned metadata debugger fixture');
    const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=['--session',a.session,'--target',a.target];
    assert.equal((await f.json(app,['ghidra','debugger','launch',...select]) as {pendingChanges:number}).pendingChanges,0);
    const args=['ghidra','debugger','set-breakpoint',...select,'--address','1000','--request-id','bp'];
    if(lost){assert.notEqual((await f.run(app,args)).exitCode,0);await f.json(app,['ghidra','close',...select]);}
    else{assert.equal((await f.json(app,args) as {pendingChanges:number}).pendingChanges,1);assert.equal((await f.json(app,['ghidra','debugger','step',...select]) as {pendingChanges:number}).pendingChanges,1);}
    assert.equal(backend!.workspace.context(a).complexChanges.length,1);assert.equal(backend!.workspace.context(b).complexChanges.length,0);
    const snapshot=backend!.workspace.context(a).workingSnapshot!;assert.equal(JSON.parse(await readFile(await backend!.workspace.artifacts.verify(snapshot),'utf8')).opaque,'breakpoint');
    await f.run(app,args);assert.equal(sets,1);
  }
});

test('debugger completion rejects stale stopped snapshots and terminated or disconnected targets',()=>{
 const before={snap:2},stopped={snap:2,target_connected:true,execution_state:'STOPPED'};
 assert.equal(debuggerExecutionSettled('step',before,stopped),false);
 assert.equal(debuggerExecutionSettled('step',before,{...stopped,snap:3}),true);
 assert.equal(debuggerExecutionSettled('step',before,{...stopped,snap:3,execution_state:'TERMINATED'}),false);
 assert.equal(debuggerExecutionSettled('step',before,{...stopped,snap:3,target_connected:false}),false);
 assert.equal(debuggerExecutionSettled('resume',before,stopped),false);
 assert.equal(debuggerExecutionSettled('resume',before,{...stopped,snap:3}),true);
 assert.equal(debuggerExecutionSettled('resume',before,{...stopped,execution_state:'RUNNING'}),true);
 assert.equal(debuggerExecutionSettled('interrupt',before,stopped),true);
});

test('debugger readback rejects wrong addresses, inconsistent memory and malformed CPU data',()=>{
  assert.throws(()=>debuggerResult('read_memory',{address:'1000',size:8},{address:'1000',size:8,hex:'00',dwords:[]}),/inconsistent/);
  assert.throws(()=>debuggerResult('static_to_dynamic',{address:'1000'},{static_address:'1100',dynamic_address:'2100'}),/another address/);
  assert.throws(()=>debuggerResult('registers',{}, {PC:9007199254740992}),/exact hexadecimal/);
  assert.throws(()=>debuggerResult('set_breakpoint',{address:'1000'},{status:'set',address:'1100'}),/another address/);
  assert.deepEqual(debuggerResult('registers',{}, {PC:'0xffffffffffffffff'}),{PC:'0xffffffffffffffff'});
  assert.equal((debuggerResult('list_breakpoints',{},[{address:'1000',name:'',state:'ENABLED',kinds:['SW_EXECUTE'],trace_location_count:1}]) as {name:string}[])[0]!.name,'');
});

test('a dead debugger retains its verified uncertain trace candidate without overwriting a newer observation or recreating execution',async t=>{
  for(const continuation of ['open','close','newer-observation']){
    const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend,ended=false,snap=0,steps=0,launches=0,closes=0;
    const trace='trace_00000000-0000-4000-8000-000000000001';
    const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
      backend=new SessionBackend(workspace);
      return Object.assign(backend,{debuggerStart:async()=>{},closed:async()=>ended,close:async()=>{closes++;},
        debuggerLaunch:async()=>{launches++;return {status:'launched',offer_title:'fixture',trace_name:'fixture'};},
        debuggerCall:async(_scope:Scope,operation:string)=>{if(operation==='step'){steps++;snap++;throw Error('Synthetic lost completed step');}
          return {debugger_active:true,trace_active:launches>0,open_traces:launches,...(launches?{target_connected:!ended,module_count:1,snap,execution_state:'STOPPED'}:{})};},
        debuggerSaved:async(selected:Scope)=>({traces:launches?[{id:trace,name:'fixture',snapshot:workspace.context(selected).workingSnapshot!,snap:String(snap),modules:1,threads:1,connected:!ended}]:[],...(launches?{active:trace}:{}),connected:launches>0&&!ended}),
      });
    }}));
    const input=join(f.root,'fixture.exe');await writeFile(input,'owned uncertain debugger fixture');const selected=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=['--session',selected.session,'--target',selected.target];
    await f.json(app,['ghidra','debugger','launch',...select]);const uncertain=['ghidra','debugger','step',...select,'--request-id','lost'];assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(backend!.workspace.context(selected).debugger!.traces[0]!.snap,'0');
    if(continuation==='newer-observation'){snap=2;await f.json(app,['ghidra','debugger','status',...select]);}
    ended=true;backend!.views.clear();await f.json(app,['ghidra',continuation==='close'?'close':'open',...select]);
    const saved=backend!.workspace.context(selected).debugger!;assert.equal(saved.traces[0]!.snap,continuation==='newer-observation'?'2':'1');assert.equal(saved.connected,false);assert.ok(saved.traces.every(row=>!row.connected));
    assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(steps,1);assert.equal(launches,1);assert.equal(closes,0);
  }
});

test('debugger request identity preserves isolated targets and never repeats an uncertain CPU step',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let backend:SessionBackend,launches=0,steps=0,lost=false;
  const states=new Map<string,{trace:string;connected:boolean;snap:number}>();
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const key=(scope:Scope)=>workspace.context(scope).id;
    const close=backend.close.bind(backend);
    return Object.assign(backend,{close:async(scope:Scope)=>{const state=states.get(key(scope));if(state)state.connected=false;await close(scope);},debuggerStart:async()=>{},debuggerSelect:async()=>{},closed:async(scope:Scope)=>!states.get(key(scope))?.connected,
      debuggerCall:async(scope:Scope,operation:string)=>{
        const state=states.get(key(scope));
        if(operation==='status')return {debugger_active:true,trace_active:Boolean(state),open_traces:state?1:0,...(state?{target_connected:state.connected,module_count:1,snap:state.snap,execution_state:'STOPPED'}:{})};
        if(operation==='step'){steps++;state!.snap++;if(lost)throw Error('Synthetic lost step response');return {status:'stepped'};}
        throw Error('Unexpected fixture debugger operation');
      },debuggerLaunch:async(scope:Scope)=>{launches++;states.set(key(scope),{trace:'trace_00000000-0000-4000-8000-000000000001',connected:true,snap:0});return {status:'launched',offer_title:'fixture',trace_name:'fixture'};},
      debuggerSaved:async(scope:Scope)=>{const state=states.get(key(scope));return {connected:state?.connected??false,...(state?{active:state.trace}:{}),traces:state?[{id:state.trace,name:'fixture',snapshot:workspace.context(scope).workingSnapshot!,snap:String(state.snap),modules:1,threads:1,connected:state.connected}]:[]};},
    });
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned synthetic debugger input');
  const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=(scope:Scope)=>['--session',scope.session,'--target',scope.target];
  const launch=['ghidra','debugger','launch',...select(a),'--request-id','launch'];const result=await f.json(app,launch);assert.deepEqual(await f.json(app,launch),result);assert.equal(launches,1);
  assert.equal((await f.json(app,['ghidra','debugger','status',...select(b)]) as {connectionState:string}).connectionState,'idle');
  const busy=['ghidra','debugger','launch',...select(a),'--request-id','busy'];const first=await f.run(app,[...busy,'--json']),retry=await f.run(app,[...busy,'--json']);assert.equal(first.exitCode,1);assert.deepEqual(JSON.parse(first.stdout),JSON.parse(retry.stdout));assert.equal(launches,1);
  lost=true;const step=['ghidra','debugger','step',...select(a),'--request-id','step'];assert.equal((await f.run(app,step)).exitCode,1);assert.equal((await f.run(app,step)).exitCode,1);assert.equal(steps,1);
  const observed=await f.json(app,['ghidra','debugger','status',...select(a)]) as {connectionState:string};assert.equal(observed.connectionState,'connected');assert.equal(steps,1);
  await f.json(app,['ghidra','close',...select(a)]);await f.json(app,['ghidra','open',...select(a)]);
  assert.equal((await f.run(app,step)).exitCode,1);assert.equal(steps,1);assert.equal(launches,1);
  assert.equal((await f.json(app,['ghidra','debugger','status',...select(a)]) as {connectionState:string}).connectionState,'disconnected');
});
