import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {uiResult} from '../src/ui-results.js';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
const selected={session:'session',target:'target'};
test('UI results reject foreign programs and partial navigation while stripping internal routing',()=>{
  const tools={count:1,tools:[{name:'CodeBrowser',instance:'internal worker',has_program_manager:true,current_program:'program',open_programs:['program']}]};
  const value=uiResult('tools',{},tools,selected,'/program','fixture.exe');assert.equal(JSON.stringify(value).includes('internal worker'),false);assert.deepEqual(value.tools,[{name:'CodeBrowser',hasProgramManager:true,current:selected,open:[selected]}]);
  assert.throws(()=>uiResult('tools',{}, {...tools,tools:[{...tools.tools[0],current_program:'peer'}]},selected,'/program','fixture.exe'),/undeclared program/);
  assert.throws(()=>uiResult('goto',{address:'1000'},{success:true,address:'1100'},selected,'/program','fixture.exe'),/requested address/);
  assert.throws(()=>uiResult('cursor',{}, {address:null},selected,'/program','fixture.exe'),/omitted its reason/);
  assert.throws(()=>uiResult('cursor',{}, {address:{address:'1000'}},selected,'/program','fixture.exe'),/undeclared program/);
  assert.throws(()=>uiResult('prompt_policy',{action:'enable'},{enabled:false,remaining_ms:0,reason:'fixture',actions:[]},selected,'/program','fixture.exe'),/requested state/);
});

test('UI mode preparation precedes durable intent and navigation retry never dispatches twice',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let moves=0,lose=false,at='1000';
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace);
    return Object.assign(backend,{mode:async(who:{session:string;target:string})=>{const before=workspace.context(who);workspace.saveContext(who,before.generation,{workingSnapshot:await backend.saved(who)});},
      ui:async(who:{session:string;target:string},op:string,p:Record<string,unknown>)=>{
        if(op==='goto'){moves++;at=String(p.address);if(lose)throw Error('Synthetic lost GUI response');return {address:'0x'+at};}
        if(op==='cursor')return {address:{address:'0x'+at,...who}};
        throw Error('Unexpected fixture UI operation');
      }});
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned synthetic input');const who=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string};
  const select=['--session',who.session,'--target',who.target],args=['ghidra','ui','goto',...select,'--address','1000','--request-id','goto'];
  const value=await f.json(app,args);assert.deepEqual(await f.json(app,args),value);assert.equal(moves,1);
  lose=true;const lost=['ghidra','ui','goto',...select,'--address','1100','--request-id','lost'];assert.equal((await f.run(app,lost)).exitCode,1);assert.equal((await f.run(app,lost)).exitCode,1);assert.equal(moves,2);
  await f.json(app,['ghidra','open',...select]);assert.equal((await f.json(app,lost) as {value:{address:string}}).value.address,'0x1100');assert.equal(moves,2,'Continuation observes the existing cursor without navigating again');
});

test('a lost GUI process ends an uncertain prompt action without losing private work or re-enabling policy',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let policies=0,disconnected=false,backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    backend=new SessionBackend(workspace);return Object.assign(backend,{closed:async()=>disconnected,
      ui:async()=>{policies++;throw Error('Synthetic lost prompt policy response');}});
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned synthetic input');const who=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string},select=['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','comments','set',...select,'--address','1000','--kind','eol','--text','retained private']);
  const args=['ghidra','ui','prompt-policy',...select,'--action','enable','--request-id','lost-policy'];assert.equal((await f.run(app,args)).exitCode,1);assert.equal(policies,1);
  disconnected=true;backend!.views.clear();await f.json(app,['ghidra','open',...select]);
  assert.equal((await f.run(app,args)).exitCode,1);assert.equal(policies,1);
  assert.equal((await f.json(app,['ghidra','comments','get',...select,'--address','1000','--kind','eol']) as {text:string}).text,'retained private');
});
