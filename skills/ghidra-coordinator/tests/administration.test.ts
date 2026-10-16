import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import type {ResearchBackend} from '../src/research.js';
test('profile administration retries are durable, unknown effects do not replay, and IDs cannot cross research/administration',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let calls=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace) as SessionBackend&Pick<ResearchBackend,'administration'>;
    backend.administration=async(operation,p)=>{calls++;if(p.repository==='lost')throw Error('Lost administration response');return {state:'created',repository:p.repository,operation};};return backend;
  }}));
  const create=['ghidra','server','repositories','create','--repository','owned','--request-id','create'];
  const result=await f.json(app,create);assert.deepEqual(await f.json(app,create),result);assert.equal(calls,1);
  const different=await f.run(app,['ghidra','server','repositories','create','--repository','other','--request-id','create','--json']);assert.notEqual(different.exitCode,0);assert.equal(calls,1);
  const lost=['ghidra','server','repositories','create','--repository','lost','--request-id','lost'];assert.notEqual((await f.run(app,[...lost,'--json'])).exitCode,0);
  assert.notEqual((await f.run(app,[...lost,'--json'])).exitCode,0);assert.equal(calls,2);
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  assert.notEqual((await f.run(app,['ghidra','open',exe,'--session','new','--request-id','create','--json'])).exitCode,0);
  const opened=await f.json(app,['ghidra','open',exe,'--session','new','--request-id','research']);assert.ok(opened);
  assert.notEqual((await f.run(app,['ghidra','server','repositories','create','--repository','owned','--request-id','research','--json'])).exitCode,0);assert.equal(calls,2);
});
test('administration permission and path checks reject before dispatch',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let started=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:()=>{started++;throw Error('Unexpected backend');}}));
  assert.notEqual((await f.run(app,['ghidra','server','admin','terminate-all-checkouts','--repository','owned','--json'])).exitCode,0);
  assert.notEqual((await f.run(app,['ghidra','server','repositories','files','--repository','owned','--path','/../other','--json'])).exitCode,0);
  assert.equal(started,0);
});
