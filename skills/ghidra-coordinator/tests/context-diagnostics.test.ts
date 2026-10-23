import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile,readFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {recordLifecycle,navigationResult} from '../src/context-diagnostics.js';
import {traceCommand,timed} from '../src/internal-timing.js';
import type {Workspace} from '../src/workspace.js';

const diagnostic=()=>({functions:{sampled:1,oneByteBodies:1,bodyBytes:1,entriesWithInstructions:0,complete:true},instructions:{sampled:0,complete:true},references:{sampled:0,complete:true},definedData:{sampled:1,strings:0,complete:true},scan:{visited:2,maximum:10000,sampleLimitPerCategory:128,complete:true,reason:'exhausted'},assessment:'sparse-metadata',recommendations:['Use bounded decode'],read_only:{modification_unchanged:true}});
test('navigation shares CLI/RPC read-only scope, validates budgets and separates initial policy from observations',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let calls=0,saves=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{const backend=new SessionBackend(workspace);backend.saved=async()=>{saves++;throw Error('No diagnostic save');};backend.call=async(_scope,operation,p)=>{assert.equal(operation,'/navigation_diagnostic');assert.deepEqual(p,{max_scan:10000});calls++;return diagnostic();};return backend;}}));
 const input=join(f.root,'secret-selector.exe');await writeFile(input,'owned navigation');const selected=await f.json(app,['ghidra','open',input,'--session','new','--no-analysis']) as {session:string;target:string};
 await f.profileStore.setPermissions('default',['ReadOnly']);const args=['ghidra','analysis','navigation','--session',selected.session,'--target',selected.target];
 const value=await f.json(app,args) as any;assert.equal(value.value.initialAnalysis,'none');assert.equal(value.value.priorAnalysis,'unknown');assert.equal(value.value.assessment,'sparse-metadata');
 const [rpc]=await f.rpc(app,[args]) as any[];assert.deepEqual(rpc.result,value);assert.equal(saves,0);
 for(const budget of ['0','200001'])assert.notEqual((await f.run(app,[...args,'--max-scan',budget,'--json'])).exitCode,0);assert.equal(calls,2);
 const malformed=diagnostic();malformed.functions.sampled=10001;assert.throws(()=>navigationResult(malformed,10000),/Malformed navigation/);
});
test('lifecycle is non-starting, retains bounded events and never exposes private process receipts',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let workspace!:Workspace,opens=0;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{workspace=w;const backend=new SessionBackend(w),open=backend.open.bind(backend);backend.open=async(...args)=>{opens++;return open(...args);};return backend;}}));
 const input=join(f.root,'owned.exe');await writeFile(input,'owned lifecycle');const selected=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string},context=workspace.context(selected),before=opens;
 for(let n=0;n<130;n++)await recordLifecycle(workspace,context.id,{at:new Date().toISOString(),event:'stop',reason:'owner_dispose',pid:100+n});
 const root=join(workspace.directory,'ghidra-native','context',context.id),processRoot=join(root,'owned');await mkdir(processRoot,{recursive:true});
 const binding={context:context.id,target:selected.target,session:selected.session,root:processRoot,pid:9,tokenSecret:'private-secret'};
 for(const path of [join(root,'current.json'),join(processRoot,'process.json')])await writeFile(path,JSON.stringify(binding));
 await writeFile(join(processRoot,'stopped.json'),JSON.stringify({pid:9,tokenSecret:'private-secret'}));
 const args=['ghidra','diagnostics','lifecycle','--session',selected.session,'--target',selected.target];await f.profileStore.setPermissions('default',['ReadOnly']);
 const value=await f.json(app,args) as any;assert.equal(value.lifecycle.events.length,128);assert.equal(value.lifecycle.latest.reason,'unknown');assert.equal(value.lifecycle.ownerShutdownCause,'unknown');assert.doesNotMatch(JSON.stringify(value),/private-secret|\/owned/);
 const [rpc]=await f.rpc(app,[args]) as any[];assert.deepEqual(rpc.result,value);assert.equal(opens,before);
 await writeFile(join(root,'current.json'),JSON.stringify({...binding,target:'other'}));assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);assert.equal(opens,before);
});
test('internal spans correlate nested phases and failures without recording arguments, paths or exception text',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'});const root=join(f.root,'owned');
 await traceCommand(root,'ghidra functions inspect',async()=>{await timed('native.http','/get_functions',async()=>{});await assert.rejects(timed('adapter.normalize','functions.inspect',async()=>{throw Error('SECRET_PAYLOAD');}));});
 const text=await readFile(join(root,'diagnostics/timings.jsonl'),'utf8'),rows=text.trim().split('\n').map(line=>JSON.parse(line));assert.equal(rows.length,3);assert.equal(new Set(rows.map(row=>row.trace)).size,1);
 const parent=rows.find(row=>row.phase==='facade.command');assert.ok(rows.filter(row=>row.phase!=='facade.command').every(row=>row.parent===parent.span));assert.ok(rows.every(row=>row.durationMs>=0));assert.equal(rows.find(row=>row.phase==='adapter.normalize').outcome,'failure');assert.doesNotMatch(text,/SECRET_PAYLOAD/);
});
