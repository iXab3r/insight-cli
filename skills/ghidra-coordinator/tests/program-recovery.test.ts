import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import type {ResearchBackend} from '../src/research.js';
import {Research} from '../src/research.js';
test('lost structural acknowledgment retains an immutable candidate and continuation verifies without replay',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
  let backend:SessionBackend&Pick<ResearchBackend,'inspect'>,canVerify=false;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);const call=backend.call.bind(backend);
    backend.call=async(scope,path,p)=>{
      if(path!=='/create_property_map')return call(scope,path,p);
      backend.views.get(workspace.context(scope).id)!.view.opaque='property:'+p!.name;backend.edits++;
      throw Error('Lost completed structural response');
    };
    backend.inspect=async(snapshot,p)=>{
      assert.equal(p.kind,'property');const view=JSON.parse(await readFile(await workspace.artifacts.verify(snapshot),'utf8'));
      return {exists:canVerify&&view.opaque==='property:'+p.name};
    };return backend;
  }}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const selected=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string};
  const selectors=['--session',selected.session,'--target',selected.target];
  const intent=['ghidra','program','create-property-map',...selectors,'--name','Notes','--type','string','--request-id','lost-map'];
  assert.notEqual((await f.run(app,[...intent,'--json'])).exitCode,0);
  const request=backend!.workspace.unresolved(selected)[0]!;
  const candidate=(request.result as {savedSnapshot?:unknown}).savedSnapshot;assert.ok(candidate);
  assert.notEqual((await f.run(app,[...intent,'--json'])).exitCode,0);assert.equal(backend!.edits,1);
  for(let attempt=0;attempt<3;attempt++) {
    assert.notEqual((await f.run(app,['ghidra','open',...selectors,'--json'])).exitCode,0);
    assert.equal(backend!.workspace.unresolved(selected).length,1,'A blocked continuation must not add mutually blocking open intents');
  }
  canVerify=true;
  await backend!.dispose();
  const continuation=await f.json(app,['ghidra','open',...selectors]) as {state:string};assert.equal(continuation.state,'ready');
  assert.equal((await f.json(app,intent) as {state:string}).state,'applied');assert.equal(backend!.edits,1);
  assert.deepEqual(backend!.workspace.context(selected).workingSnapshot,candidate);
});
test('GUI preparation saves the private view before a documentation mutation captures its generation',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const scope=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string};
  let gui=false;
  backend!.mode=async(selected,mode)=>{assert.equal(mode,'gui');const context=backend!.workspace.context(selected);
    backend!.workspace.saveContext(selected,context.generation,{workingSnapshot:await backend!.saved(selected)});gui=true;};
  backend!.call=async(_scope,operation)=>{assert.equal(operation,'/batch_apply_documentation');assert.equal(gui,true);return {errors:[]};};
  const research=new Research(backend!.workspace,async()=>backend!);
  const result=await research.mutate(scope,'/batch_apply_documentation',{goto:true},async(_backend,response)=>response,'gui-doc',async()=>({verified:true}));
  assert.equal((result as {state:string}).state,'applied');assert.equal(backend!.workspace.unresolved(scope).length,0);
});
