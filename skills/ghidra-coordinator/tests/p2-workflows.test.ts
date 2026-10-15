import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile,readFile} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {sdkInputs} from '../src/sdk.js';
import {debuggerWriteInputs} from '../src/debugger.js';
import {debuggerResult} from '../src/debugger-results.js';
import {nativeJvmDirectories} from '../src/native-inputs.js';
import type {Scope} from '../src/workspace.js';
import type {Artifact} from '../src/artifacts.js';

test('SDK preflight rejects truncated numeric layouts, silently ignored bit placement and unknown decompiler/diff options',()=>{
  for(const field of [{name:'x',type:'uint',bit_size:1.5},{name:'x',type:'uint',bit_offset:3},{name:'x',type:'uint',offset:1e20},{name:'x',type:'uint',typo:true}])
    assert.throws(()=>sdkInputs('type-structure',{path:'/Owned',packing:-1,fields:[field]}));
  assert.throws(()=>sdkInputs('decompiler-ir',{options:{respect_read_only:'false'}}),/Boolean/);
  assert.throws(()=>sdkInputs('changes',{categories:['bytes','bytes']}),/distinct/);
  assert.throws(()=>sdkInputs('context-set',{address:'1000',end_address:'20000',value:'0x1'}),/65536/);
  assert.doesNotThrow(()=>sdkInputs('type-structure',{path:'/Owned',packing:1,fields:[{name:'flags',type:'uint',bit_size:3}]}));
});

test('live target receipts require refreshed bytes/registers; malformed history/budgets cannot pass as complete',()=>{
  const p={address:'1000',expect_hex:'0102',bytes_hex:'0304'};
  assert.throws(()=>debuggerWriteInputs('write_memory',{...p,bytes_hex:'03'}),/length/);
  assert.throws(()=>debuggerResult('write_memory',p,{status:'written',address:'1000',size:2,bytes_hex:'0304',snap:'1',verified_from:'trace_cache'}),/refreshed/);
  assert.throws(()=>debuggerResult('write_memory',p,{status:'written',address:'1000',size:2,bytes_hex:'0305',snap:'1',verified_from:'live_target_refresh'}),/requested bytes/);
  assert.throws(()=>debuggerResult('write_register',{register:'rax',value:'0x3'},{status:'written',register:'RAX',value:'0x4',bits:64,snap:'1',verified_from:'live_target_refresh'}),/requested value/);
  assert.throws(()=>debuggerResult('objects',{limit:2,max_scan:1},{items:[],visited:2,complete:true}),/budget/);
  assert.throws(()=>debuggerResult('schedule',{}, {schedule:'0',validated:true,executed:true,base_snap:'0',ticks:'0',patches:'0',snap_only:true}),/validation/);
});

test('a lost native file reply recovers only matching completed bytes without another exporter call',async t=>{
  for(const corrupt of [false,true]){
    const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let calls=0,nativeOutput='';
    const content=Buffer.from('native-export-sentinel'),app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{
      sdkFile:async(operation:string,p:Record<string,unknown>)=>{calls++;nativeOutput=String(p.output);await writeFile(nativeOutput,content);
        const value={state:'exported',format:'Raw Bytes'};await writeFile(String(p.receipt),JSON.stringify({request:p.request_id,operation,value,
          files:[{name:basename(nativeOutput),sha256:createHash('sha256').update(content).digest('hex'),size:content.length}]}));throw Error('Lost after durable native completion');},
    })}));
    const input=join(f.root,'input.exe');await writeFile(input,'synthetic owned input');const selected=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,
      output=join(f.root,'exported'),args=['ghidra','formats','export','--session',selected.session,'--target',selected.target,'--exporter','Raw Bytes','--output-directory',output,'--request-id','owned-export'];
    assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(calls,1);
    if(corrupt){await writeFile(nativeOutput,'corrupted');assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(calls,1);await writeFile(nativeOutput,content);}
    const result=await f.json(app,args);assert.equal((result as {state:string}).state,'exported');assert.deepEqual(await readFile(join(output,'program.out')),content);
    assert.deepEqual(await f.json(app,args),result);assert.equal(calls,1);
  }
});

test('native Ghidra cache/settings/temp roots are explicitly confined in addition to Java home',()=>{
  const root=join('owned','runtime'),flags=nativeJvmDirectories(root);
  assert.ok(flags.includes('-Dapplication.cachedir='+join(root,'cache')));assert.ok(flags.includes('-Dapplication.settingsdir='+join(root,'settings')));assert.ok(flags.includes('-Dapplication.tempdir='+root));
});

test('a proven rejected live precondition permits a new intent, while a lost write reply is never repeated',async t=>{
  for(const lost of [false,true]){
    const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let attempts=0,writes=0,phase='reject',connected=false;
    const trace='trace_00000000-0000-4000-8000-000000000001';
    const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>Object.assign(new SessionBackend(workspace),{
      inspect:async(_snapshot:Artifact)=>({fingerprint:'d'.repeat(64),count:0}),debuggerStart:async()=>{},
      debuggerLaunch:async()=>{connected=true;return {status:'launched',offer_title:'fixture',trace_name:'fixture'};},
      debuggerSaved:async(selected:Scope)=>({connected,...(connected?{active:trace}:{}),traces:connected?[{id:trace,name:'fixture',snapshot:workspace.context(selected).workingSnapshot!,snap:'0',modules:1,threads:1,connected:true}]:[]}),
      debuggerCall:async(_selected:Scope,operation:string)=>{if(operation==='status')return {debugger_active:true,trace_active:connected,open_traces:connected?1:0,target_connected:connected,module_count:1,snap:0,execution_state:'STOPPED'};
        if(operation==='write_memory'){attempts++;if(phase==='reject')return {status:'rejected',target_effect_started:false,reason:'native_live_precondition_changed'};writes++;if(lost)throw Error('Lost native live write reply');return {status:'written',address:'1000',bytes_hex:'02',size:1,verified_from:'live_target_refresh',snap:'0'};}
        throw Error('Unexpected debugger operation');},
    })}));
    const input=join(f.root,'owned.exe');await writeFile(input,'synthetic stopped target');const selected=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,select=['--session',selected.session,'--target',selected.target];await f.json(app,['ghidra','debugger','launch',...select]);
    const args=['ghidra','debugger','write-memory',...select,'--address','1000','--expect-hex','01','--bytes-hex','02'];
    assert.notEqual((await f.run(app,[...args,'--request-id','rejected'])).exitCode,0);assert.equal(writes,0);
    assert.notEqual((await f.run(app,[...args,'--request-id','rejected'])).exitCode,0);assert.equal(attempts,1);
    phase='write';const outcome=await f.run(app,[...args,'--request-id','write']);assert.equal(outcome.exitCode===0,!lost);
    await f.run(app,[...args,'--request-id','write']);assert.equal(writes,1);assert.equal(attempts,2);
  }
});
