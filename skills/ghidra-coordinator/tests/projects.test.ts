import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile,readFile,mkdir,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';

test('owned project selection rejects traversal, preserves unknown creation and separates another project',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]});let calls=0;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const backend=new SessionBackend(workspace);
    return Object.assign(backend,{project:async(operation:string,p:Record<string,unknown>)=>{
      calls++;const root=String(p.root),owner=JSON.parse(await readFile(join(root,'owner.json'),'utf8'));assert.equal(owner.project,p.project);
      if(operation==='create'){await writeFile(join(root,'project.gpr'),'owned');if(p.project==='lost')throw Error('Synthetic lost creation acknowledgment');return {project:p.project,state:'ready'};}
      if(operation==='info')return {project:p.project,state:'ready'};
      throw Error('Unexpected fixture operation');
    }});
  }}));
  const invoke=(argv:string[])=>f.json(app,['ghidra','projects',...argv]);
  const initial=await f.run(app,['ghidra','projects','create','--project','../foreign']);assert.equal(initial.exitCode,1);assert.equal(calls,0);
  const lost=['create','--project','lost','--request-id','lost'];assert.equal((await f.run(app,['ghidra','projects',...lost])).exitCode,1);assert.equal(calls,1);
  assert.equal((await f.run(app,['ghidra','projects',...lost])).exitCode,1);assert.equal(calls,1,'A lost create must not dispatch again');
  assert.equal((await f.run(app,['ghidra','projects','close','--project','lost'])).exitCode,1);assert.equal(calls,1,'An unresolved project blocks later effects');
  const args=['create','--project','other','--request-id','other'];const value=await invoke(args);assert.deepEqual(await invoke(args),value);assert.equal(calls,2);
  assert.equal((await invoke(['list']) as {count:number}).count,2);
  const status=await invoke(['info','--project','lost']) as {state:string;unresolvedRequests:{requestId:string}[]};
  assert.equal(status.state,'ready','Read-only inspection remains available');assert.equal(status.unresolvedRequests[0]?.requestId,'lost');
});

test('project container symlink refuses foreign storage before native dispatch',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let calls=0;
  const workspace=join(f.appArguments.AppDataDirectory,'workspace');await mkdir(workspace,{recursive:true});const foreign=join(f.root,'foreign');await mkdir(foreign);await symlink(foreign,join(workspace,'ghidra-projects'));
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:store=>Object.assign(new SessionBackend(store),{project:async()=>{calls++;return {};}})}));
  const result=await f.run(app,['ghidra','projects','create','--project','test']);assert.equal(result.exitCode,1);assert.equal(calls,0);
  assert.match(JSON.stringify(result),/Project container moved/);
});

test('lost export acknowledgment verifies retained output and never replaces an existing output',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let failed=false,backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>{
    const complete=workspace.completeSavedRequest.bind(workspace);workspace.completeSavedRequest=(...args:Parameters<typeof complete>)=>{
      if(workspace.request(args[1]).operation==='ghidra.program.export'&&!failed){failed=true;throw Error('Synthetic lost export acknowledgment');}return complete(...args);};
    backend=new SessionBackend(workspace);return backend;
  }}));
  const input=join(f.root,'fixture.exe');await writeFile(input,'owned synthetic input');const who=await f.json(app,['ghidra','open',input,'--session','new']) as {session:string;target:string};
  const select=['--session',who.session,'--target',who.target],output=join(f.root,'private.gzf'),args=['ghidra','program','export',...select,'--output',output,'--request-id','lost'];
  assert.equal((await f.run(app,args)).exitCode,1);const contents=await readFile(output,'utf8');
  await f.json(app,['ghidra','open',...select]);assert.equal((await f.json(app,args) as {state:string}).state,'exported');assert.equal(await readFile(output,'utf8'),contents);
  assert.equal((await f.run(app,['ghidra','program','export',...select,'--output',output])).exitCode,1);assert.equal(await readFile(output,'utf8'),contents);assert.equal(backend!.publications,0);
});
