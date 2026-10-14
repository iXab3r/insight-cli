import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';

test('static query leaves use typed domain flags, explicit scope, shared API definitions and ReadOnly permissions',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
  const calls:{operation:string;parameters:Record<string,unknown>}[]=[],backendResult={data_types:[],count:0};
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace),call=backend.call.bind(backend);
    backend.call=async(scope,operation,parameters={})=>{
      if(['/get_comment','/set_comment','/get_functions','/rename_function'].includes(operation))return call(scope,operation,parameters);
      calls.push({operation,parameters});
      if(operation==='/emulate_function')return {success:true,steps_executed:1,stop_reason:'return',registers:{RAX:'1'}};
      if(operation==='/get_assembly_context')return {'1000':{},'1100':{}};
      return backendResult;
    };return backend;
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned query fixture');
  const opened=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string};
  const selected=['--session',opened.session,'--target',opened.target];
  const query=['ghidra','types','find-data-types',...selected,'--pattern','Record','--categories','false','--limit','12'];
  const result=await f.json(app,query) as {session:string;target:string;value:unknown};
  assert.equal(result.session,opened.session);assert.equal(result.target,opened.target);assert.deepEqual(result.value,backendResult);
  assert.deepEqual(calls.at(-1),{operation:'/find_data_types',parameters:{pattern:'Record',categories:false,offset:0,limit:12}});
  const rpc=await f.rpc(app,[query]);assert.deepEqual((rpc[0] as {result:unknown}).result,result);
  await f.profileStore.setPermissions('default',['ReadOnly']);
  assert.deepEqual(await f.json(app,query),result,'Queries remain available with only ReadOnly authority');
  assert.notEqual((await f.run(app,['ghidra','comments','set',...selected,'--address','1000','--kind','eol','--text','denied','--json'])).exitCode,0);
  const before=calls.length;
  for(const extra of [['--limit','1001'],['--categories','yes'],['--program','other']]) {
    assert.notEqual((await f.run(app,['ghidra','types','find-data-types',...selected,...extra,'--json'])).exitCode,0);
  }
  assert.equal(calls.length,before);
  await f.json(app,['ghidra','emulation','emulate-function',...selected,'--function','first','--registers','{"RAX":"1"}','--memory','[]']);
  assert.deepEqual(calls.at(-1)!.parameters.registers,{RAX:'1'});assert.deepEqual(calls.at(-1)!.parameters.memory,[]);
  await f.json(app,['ghidra','xrefs','get-assembly-context',...selected,'--xref-sources','"1000,1100"']);
  assert.equal(calls.at(-1)!.parameters.xref_sources,'1000,1100','JSON strings must be decoded exactly once');
  const schema=JSON.parse(await readFile(new URL('../../references/queries.json',import.meta.url),'utf8')) as {tools:{command:string;path:string}[]};
  assert.equal(schema.tools.length,72);assert.equal(new Set(schema.tools.map(t=>t.command)).size,72);
  const help=await f.run(app,['ghidra','types','find-data-types','--help']);assert.equal(help.exitCode,0);assert.match(help.stdout,/--pattern/);assert.doesNotMatch(help.stdout,/--program\b/);
  backendResult.count=-1;
  const failed=await f.run(app,[...query,'--json']);assert.notEqual(failed.exitCode,0);
  const machine=JSON.parse(failed.stdout);assert.equal(machine.session,opened.session);assert.equal(machine.target,opened.target);
});
