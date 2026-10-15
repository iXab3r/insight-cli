import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {debuggerResult} from '../src/debugger-results.js';
import type {Scope} from '../src/workspace.js';

test('debugger readback rejects wrong addresses, inconsistent memory and malformed CPU data',()=>{
  assert.throws(()=>debuggerResult('read_memory',{address:'1000',size:8},{address:'1000',size:8,hex:'00',dwords:[]}),/inconsistent/);
  assert.throws(()=>debuggerResult('static_to_dynamic',{address:'1000'},{static_address:'1100',dynamic_address:'2100'}),/another address/);
  assert.throws(()=>debuggerResult('registers',{}, {PC:9007199254740992}),/exact hexadecimal/);
  assert.throws(()=>debuggerResult('set_breakpoint',{address:'1000'},{status:'set',address:'1100'}),/another address/);
  assert.deepEqual(debuggerResult('registers',{}, {PC:'0xffffffffffffffff'}),{PC:'0xffffffffffffffff'});
  assert.equal((debuggerResult('list_breakpoints',{},[{address:'1000',name:'',state:'ENABLED',kinds:['SW_EXECUTE'],trace_location_count:1}]) as {name:string}[])[0]!.name,'');
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
