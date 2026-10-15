import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {archiveOrigin,archivePost,archivePayload} from '../src/archive-contract.js';
import type {Scope} from '../src/workspace.js';

test('archive transport validates explicit origins and complete bounded responses',async()=>{
  for(const url of ['http://remote.example','https://user:secret@example.test','https://example.test/?token=secret','file:///tmp/archive'])assert.throws(()=>archiveOrigin(url));
  assert.equal(archiveOrigin('https://example.test/api/'),'https://example.test/api');
  await assert.rejects(archivePost(async()=>Response.json({created:true}) as never,'https://example.test',{}),/count/);
  await assert.rejects(archivePost(async()=>Response.json({created:'yes',conflicts_enqueued:0}) as never,'https://example.test',{}),/created flag/);
  await assert.rejects(archivePost(async()=>new Response('x'.repeat(65537)) as never,'https://example.test',{}),/64 KiB/);
  assert.throws(()=>archivePayload({binary_name:'other'},'fixture.exe','v1','run'),/another input/);
});

test('archive retries retain exact external outcomes while private research stays independent',async t=>{
  let calls=0,lost=false,pages=0;const bodies:Record<string,unknown>[]=[];
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',values:{archiveUrl:'https://archive.example.test'},permissions:['ReadOnly','Update','Destructive'],secrets:{archiveToken:'synthetic-archive-secret'}}]});
  const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(url,options)=>{
    assert.equal(String(url),'https://archive.example.test/v1/doc_archive/upsert');assert.equal((options!.headers as Record<string,string>).Authorization,'Bearer synthetic-archive-secret');assert.equal(options!.redirect,'error');
    calls++;bodies.push(JSON.parse(String(options!.body)));if(lost)throw Error('Synthetic response loss');return Response.json({created:calls===1,conflicts_enqueued:2});
  }},backend:workspace=>Object.assign(new SessionBackend(workspace),{archivePayloads:async(_selected:Scope,p:Record<string,unknown>)=>{
    pages++;const payload=(at:string)=>({binary_name:p.binary_name,version:p.version,source_run_id:p.run_id,source_tool:'ghidra_mcp_ingest',address:at,name:'named',prototype:'int named(void)',no_return:false,is_thunk:false});
    return p.function?{payloads:[payload(String(p.function))],visited:1,skipped:0,more:false}:{payloads:[payload('0x1000'),payload('0x1100')],visited:3,skipped:1,more:false};
  }})}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned synthetic archive input');
  const a=await f.json(app,['ghidra','open',input,'--session','new']) as Scope,b=await f.json(app,['ghidra','open',input,'--session','new']) as Scope;
  const select=(who:Scope)=>['--session',who.session,'--target',who.target];
  const bulk=['ghidra','archive','ingest-program',...select(a),'--version-label','v1','--request-id','bulk'];
  const result=await f.json(app,bulk) as Record<string,unknown>;assert.equal(result.created,1);assert.equal(result.updated,1);assert.equal(result.conflicts_enqueued,4);assert.equal(result.total_functions,3);assert.equal(result.skipped_default_named,1);
  assert.deepEqual(await f.json(app,bulk),result);assert.equal(calls,2);assert.equal(pages,1);
  const preview=await f.json(app,['ghidra','archive','ingest-function',...select(a),'--address','1000','--dry-run']) as Record<string,unknown>;assert.equal(preview.state,'preview');assert.equal(calls,2);
  lost=true;const uncertain=['ghidra','archive','ingest-function',...select(a),'--address','1000','--request-id','lost'];
  assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.notEqual((await f.run(app,uncertain)).exitCode,0);assert.equal(calls,3);
  assert.notEqual((await f.run(app,['ghidra','archive','ingest-function',...select(b),'--address','1000','--request-id','bulk'])).exitCode,0);assert.equal(calls,3);
  await f.json(app,['ghidra','comments','set',...select(a),'--address','1000','--kind','eol','--text','retained private work']);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address','1000','--kind','eol']) as {text:null}).text,null);
  assert.ok(bodies.every(body=>body.binary_name==='fixture.exe'&&body.version==='v1'||body.version==='unknown'));
});
