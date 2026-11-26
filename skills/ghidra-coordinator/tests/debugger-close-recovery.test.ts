import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {Research} from '../src/research.js';
import {Lifecycle} from '../src/lifecycle.js';
import {Debugger} from '../src/debugger.js';
import type {Scope} from '../src/workspace.js';
import {recoveryFixture} from './scoped-recovery-fixture.js';

async function debuggerFixture(t:test.TestContext,options:{edited?:boolean;metadataChanged?:boolean;legacy?:boolean}={}){
  const f=await recoveryFixture(t),traceId='trace_'+randomUUID(),tracePath=join(f.root,'trace.gzf');await writeFile(tracePath,'synthetic retained trace bytes');
  const trace={id:traceId,name:'owned trace',snapshot:await f.workspace.captureSnapshot(tracePath),snap:'0',thread:'7',modules:1,threads:1,connected:true};
  const previous=await f.localReceipt('a'.repeat(64),options.legacy?undefined:'1'.repeat(64));
  const currentFingerprint=(options.edited?'b':'a').repeat(64),currentMetadata=(options.metadataChanged?'2':'1').repeat(64);
  const c=f.workspace.context(f.scope);f.workspace.saveContext(f.scope,c.generation,{state:'ready',workingSnapshot:previous,debugger:{traces:[trace],active:traceId,connected:true}});
  const counters={save:0,checkpoint:0,inspectTrace:0,stop:0,open:0},fault={save:false,checkpoint:false,stop:false,metadata:false,traceIdentity:false},inspections:string[]=[];
  let stopped=false;
  const record={binding:{...f.processBinding(process.pid),mode:'gui'},http:{call:async(operation:string)=>{
    assert.equal(operation,'/save_program');counters.save++;if(fault.save)throw Error('Save not acknowledged');
    await writeFile(f.bytes,'saved static fingerprint '+currentFingerprint);return {success:true};}}};
  const backend=f.backend(),read=f.server.nativeRead.bind(f.server);
  f.server.nativeRead=async(binding,q)=>{
    if(q.operation==='inspect'){
      assert.equal(q.fingerprint,'a'.repeat(64),'Legacy fallback must inspect the immutable shared base');
      assert.equal((q.parameters as any).kind,'debugger_bookmarks');return {state:'verified',value:{fingerprint:'1'.repeat(64),count:0}};
    }return read(binding,q);
  };
  f.server.traceInspect=async()=>{counters.inspectTrace++;return {id:fault.traceIdentity?'trace_'+randomUUID():traceId,target:f.scope.target,context:f.scope.id,name:trace.name,modules:1,threads:1};};
  Object.assign(backend,{
    open:async()=>{counters.open++;return f.workspace.context(f.scope);},selected:async()=>record,closed:async()=>stopped,
    nativeView:async(_record:unknown,q:Record<string,unknown>)=>{
      if(q.expected!==undefined){inspections.push(String(q.expected));assert.equal(q.expected,currentFingerprint,'Exact native byte guard rejected a superseded receipt');}
      if(q.operation==='fingerprint')return {...f.saved,fingerprint:currentFingerprint};
      assert.equal(q.operation,'inspect');assert.equal((q.parameters as any).kind,'debugger_bookmarks');
      return fault.metadata?{count:0}:{fingerprint:currentMetadata,count:Number(options.metadataChanged===true)};
    },
    traceHelper:async(_s:Scope,p:Record<string,unknown>)=>{
      assert.equal(p.operation,'checkpoint');counters.checkpoint++;if(fault.checkpoint)throw Error('Trace checkpoint not acknowledged');
      await writeFile(join(String(p.output),traceId+'.gzf'),'new verified trace checkpoint');
      return {active:traceId,traces:[{id:traceId,snap:'9',thread:'7',connected:true}]};
    },
    stopRecord:async()=>{counters.stop++;if(fault.stop)throw Error('Owned stop not verified');stopped=true;},
  });
  const research=new Research(f.workspace,async()=>backend),lifecycle=new Lifecycle(f.workspace,research,async()=>backend);
  return {...f,backend,research,lifecycle,counters,fault,previous,trace,inspections,currentFingerprint,currentMetadata};
}

for(const legacy of [false,true])for(const edited of [false,true])for(const metadataChanged of [false,true])
test(`GUI close retains current static bytes and verified traces (edited ${edited}, metadata ${metadataChanged}, old receipt ${legacy})`,async t=>{
  const f=await debuggerFixture(t,{legacy,edited,metadataChanged}),before=f.workspace.context(f.scope);
  const result:any=await f.lifecycle.change(f.scope,'close','gui-close'),after=f.workspace.context(f.scope);
  assert.equal(result.state,'closed');assert.equal(f.counters.stop,1);assert.equal(f.counters.checkpoint,1);assert.equal(f.counters.inspectTrace,1);
  assert.deepEqual(after.nativeCheckout,before.nativeCheckout);assert.equal(after.state,'stopped');
  const receipt=JSON.parse(await readFile(await f.workspace.artifacts.verify(after.workingSnapshot!),'utf8'));
  assert.equal(receipt.fingerprint,f.currentFingerprint);assert.equal(receipt.debuggerMetadata,f.currentMetadata);
  assert.equal(after.complexChanges.length,before.complexChanges.length+Number(metadataChanged));
  assert.equal(after.debugger!.active,f.trace.id);assert.equal(after.debugger!.traces[0]!.id,f.trace.id);assert.equal(after.debugger!.traces[0]!.thread,'7');
  assert.equal(after.debugger!.traces[0]!.snap,'9');assert.equal(after.debugger!.connected,false);assert.equal(after.debugger!.traces[0]!.connected,false);
  assert.equal(await readFile(await f.workspace.artifacts.verify(after.debugger!.traces[0]!.snapshot),'utf8'),'new verified trace checkpoint');
  assert.equal(await readFile(await f.workspace.artifacts.verify(f.trace.snapshot),'utf8'),'synthetic retained trace bytes');
  assert.equal(await readFile(f.bytes,'utf8'),'saved static fingerprint '+f.currentFingerprint);assert.ok(f.inspections.every(fp=>fp===f.currentFingerprint));
  const savedCounters={...f.counters};assert.deepEqual(await f.lifecycle.change(f.scope,'close','gui-close'),result);assert.deepEqual(f.counters,savedCounters);
  await f.research.open(f.scope.target,f.scope.session,{autoAnalyze:false});assert.equal(f.counters.open,savedCounters.open+1);
  assert.equal(f.workspace.context(f.scope).workingSnapshot!.id,after.workingSnapshot!.id);assert.deepEqual(f.workspace.context(f.scope).debugger,after.debugger);
});

for(const failure of ['save','checkpoint','metadata','traceIdentity','stop'] as const)
test(`GUI close keeps ${failure} failure uncertain and never repeats close on retrieval`,async t=>{
  const f=await debuggerFixture(t,{edited:true,metadataChanged:true}),before=f.workspace.context(f.scope);f.fault[failure]=true;
  await assert.rejects(f.lifecycle.change(f.scope,'close','failed-close'));
  assert.equal(f.workspace.requestByCaller('failed-close')!.state,'unknown');
  const counts={...f.counters};await assert.rejects(f.lifecycle.change(f.scope,'close','failed-close'),/remains unresolved/);assert.deepEqual(f.counters,counts);
  if(failure==='stop'){
    assert.equal(f.counters.stop,1);assert.notEqual(f.workspace.context(f.scope).workingSnapshot!.id,before.workingSnapshot!.id);
    assert.equal(f.workspace.context(f.scope).debugger!.traces[0]!.id,f.trace.id);
    // Once independent lifetime proof becomes available, retrieval settles without another save/checkpoint/stop.
    Object.assign(f.backend,{closed:async()=>true});const result:any=await f.lifecycle.change(f.scope,'close','failed-close');assert.equal(result.state,'closed');
    assert.deepEqual(f.counters,counts);
  }else{
    assert.equal(f.counters.stop,0);assert.deepEqual(f.workspace.context(f.scope),before);
  }
  await f.workspace.artifacts.verify(f.previous);await f.workspace.artifacts.verify(f.trace.snapshot);
});

test('exact fingerprint checks still reject an older native receipt after GUI save',async t=>{
  const f=await debuggerFixture(t,{edited:true});await f.backend.saved(f.scope);
  await assert.rejects(f.backend.inspect(f.previous,{kind:'debugger_bookmarks'}),/superseded receipt/);
  assert.equal(f.counters.stop,0);
});

test('GUI to headless transition uses retained metadata witnesses and the same verified trace checkpoints',async t=>{
  const f=await debuggerFixture(t,{edited:true,metadataChanged:true});let reopened=0;
  Object.assign(f.backend,{privateCopy:async()=>{reopened++;}});await f.backend.mode(f.scope,'headless');
  assert.equal(reopened,1);assert.equal(f.counters.stop,1);assert.equal(f.counters.checkpoint,1);
  const after=f.workspace.context(f.scope);assert.equal(after.debugger!.traces[0]!.id,f.trace.id);assert.equal(after.debugger!.connected,false);
  assert.equal(after.complexChanges.length,2);assert.ok(f.inspections.every(fp=>fp===f.currentFingerprint));
});

for(const operation of ['traces','status'])for(const legacy of [false,true])for(const metadataChanged of [false,true])
test(`passive debugger ${operation} checkpoints GUI edits with immutable metadata (old receipt ${legacy}, metadata ${metadataChanged})`,async t=>{
  const f=await debuggerFixture(t,{edited:true,legacy,metadataChanged}),before=f.workspace.context(f.scope);let queries=0,starts=0;
  Object.assign(f.backend,{debuggerStart:async()=>{starts++;},debuggerCall:async(_s:Scope,op:string)=>{
    queries++;assert.equal(op,'status');return {debugger_active:true,trace_active:true,target_connected:true,open_traces:1,module_count:1,execution_state:'STOPPED'};
  }});
  const debuggerService=new Debugger(f.workspace,f.research,async()=>f.backend);
  const result:any=await debuggerService.read(f.scope,operation,{}),after=f.workspace.context(f.scope);
  assert.equal(result.connectionState,'connected');assert.equal(starts,1);assert.equal(queries,Number(operation==='status'));
  assert.equal(f.counters.save,1);assert.equal(f.counters.checkpoint,1);assert.equal(f.counters.stop,0);
  assert.equal(after.complexChanges.length,before.complexChanges.length+Number(metadataChanged));assert.deepEqual(after.nativeCheckout,before.nativeCheckout);
  const receipt=JSON.parse(await readFile(await f.workspace.artifacts.verify(after.workingSnapshot!),'utf8'));
  assert.equal(receipt.fingerprint,f.currentFingerprint);assert.equal(receipt.debuggerMetadata,f.currentMetadata);assert.equal(after.debugger!.active,f.trace.id);
  // A second passive checkpoint must not duplicate the already acknowledged metadata diagnostic.
  await debuggerService.read(f.scope,operation,{});assert.equal(f.workspace.context(f.scope).complexChanges.length,after.complexChanges.length);
  assert.ok(f.inspections.every(fp=>fp===f.currentFingerprint));
});

test('debugger execution compares retained metadata without weakening step observation or replay guards',async t=>{
  const f=await debuggerFixture(t,{edited:true,metadataChanged:true});let steps=0,statuses=0;
  Object.assign(f.backend,{debuggerStart:async()=>{},debuggerCall:async(_s:Scope,op:string)=>{
    if(op==='status'){statuses++;return {debugger_active:true,trace_active:true,target_connected:true,open_traces:1,module_count:1,execution_state:'STOPPED',snap:steps?'1':'0'};}
    assert.equal(op,'step');steps++;return {status:'stepped'};
  }});
  const service=new Debugger(f.workspace,f.research,async()=>f.backend),result:any=await service.change(f.scope,'step',{kind:'into'},'owned-step');
  assert.equal(result.state,'applied');assert.equal(steps,1);assert.equal(statuses,2);assert.equal(f.workspace.context(f.scope).complexChanges.length,2);
  assert.deepEqual(await service.change(f.scope,'step',{kind:'into'},'owned-step'),result);assert.equal(steps,1);
});

for(const problem of ['malformed witness','mismatched immutable base'])test(`GUI close preserves uncertainty for ${problem}`,async t=>{
  const f=await debuggerFixture(t,{edited:true,legacy:problem==='mismatched immutable base'}),before=f.workspace.context(f.scope);
  if(problem==='malformed witness'){
    const receipt=await f.localReceipt('a'.repeat(64),'malformed');f.workspace.saveContext(f.scope,before.generation,{workingSnapshot:receipt});
  }else{
    const base=await f.sharedReceipt(2,'a'.repeat(64));f.workspace.saveContext(f.scope,before.generation,{baseSnapshot:base});
  }
  const original=f.workspace.context(f.scope);await assert.rejects(f.lifecycle.change(f.scope,'close','invalid-metadata'),/metadata/);
  assert.equal(f.workspace.requestByCaller('invalid-metadata')!.state,'unknown');assert.equal(f.counters.stop,0);assert.deepEqual(f.workspace.context(f.scope),original);
});
