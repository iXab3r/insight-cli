import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,stat} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {packageVersion} from '../src/package-version.js';

test('toolbox discovery and all skills need no profile, native state or transport',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'});
 const forbidden=new Proxy({}, {get(){return ()=>{throw Error('Profile, secret or native state must not be accessed');};}});
 const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,profileStore:forbidden as never,secretStore:forbidden as never,fetch:async()=>{throw Error('No network');}},backend:()=>{throw Error('No native tool');}}));
 const list=await f.json(app,['tools','list','--profile','missing']) as {version:string;items:{id:string;kind:string;skill:string}[]};
 assert.equal(list.version,packageVersion);assert.deepEqual(list.items.map(x=>x.id),['ghidra','ilspy','sevenzip','llvm','dotnet-dump','dotnet-stack','dotnet-trace','die','artifacts']);
 for(const tool of list.items){
  const shown=await f.json(app,['tools','show',tool.id]) as {skill:{name:string;path:string};runtime:{readiness?:string;required:boolean}};
  assert.equal(shown.skill.name,tool.skill);assert.equal(shown.runtime.required,tool.kind==='analytical');
  if(tool.kind==='analytical')assert.equal(shown.runtime.readiness,'notChecked');
  assert.ok((await readFile(shown.skill.path,'utf8')).includes(packageVersion));
  const selected=await f.json(app,['skill',tool.skill]) as {path:string};assert.equal(selected.path,shown.skill.path);
 }
 const responses=await f.rpc(app,[['tools','list'],['skill','insight-re']]) as {result:unknown}[];
 assert.equal(responses.length,2);
 for(const argv of [['--help'],['tools','--help'],['skill','--help'],['tools','list'],['tools','show','ilspy'],['tools','processes','--help']])assert.equal(await app.classify(argv),'local');
 assert.equal(await app.classify(['tools','processes']),'owner');
 const missing=await f.run(app,['tools','show','absent']);assert.notEqual(missing.exitCode,0);assert.match(missing.stderr,/insight-cli tools list/);
 await assert.rejects(stat(f.appArguments.AppDataDirectory));
});

test('each packaged skill uses references contained inside its own directory',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),app=f.createApplication(runtime=>createInsightCli({runtime}));
 const main=await f.json(app,['skill']) as {skills:string[]};
 for(const name of main.skills){
  const skill=await f.json(app,['skill',name]) as {path:string};
  const text=await readFile(skill.path,'utf8');
  for(const link of text.matchAll(/\]\(([^)]+)\)/g)){
   if(/^[a-z][a-z0-9+.-]*:|^#/.test(link[1]!))continue;
   assert.ok(!link[1]!.includes('../'),name+': reference crosses skill boundary');
   await stat(join(dirname(skill.path),link[1]!));
  }
 }
});
