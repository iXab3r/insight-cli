import test from 'node:test';
import assert from 'node:assert/strict';
import { createCliFixture } from '@eyeauras/cli-factory/testing';
import { createInsightCli } from '../src/prototype-cli.js';
import { stat, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Store } from '../src/store.js';
const server='ghidra://127.0.0.1:14100';
const identity={profile:'default',server,repository:'synthetic',programPath:'/fixture.exe',binarySha256:'a'.repeat(64),language:'x86:LE:64:default',compilerSpec:'windows',imageBase:'140000000'};
test('help and local skill discovery work without configured profile or runtime directory',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-ghidra'});const app=f.createApplication(runtime=>createInsightCli({runtime}));
 const help=await f.run(app,['--help']);assert.equal(help.exitCode,0);assert.match(help.stdout,/findings/);
 const skill=await f.json(app,['skill']) as {path:string;version:string};assert.equal(skill.version,'0.1.0');assert.match(await readFile(skill.path,'utf8'),/insight-cli 0.2.0/);
 await assert.rejects(stat(f.appArguments.AppDataDirectory));
});
test('Update denied before files/state, JSON and RPC share command declaration and profile isolation',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-ghidra',profiles:[{name:'default',values:{server}},{name:'other',values:{server}}]});const app=f.createApplication(runtime=>createInsightCli({runtime}));
 const denied=await f.run(app,['targets','register','--file','does-not-exist.json','--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'ghidra/coordinator.sqlite')));
 await app.execute(['permissions','grant','Update']);const path=join(f.root,'identity.json');await writeFile(path,JSON.stringify(identity));const target=await f.json(app,['targets','register','--file',path]) as {id:string};
 const responses=await f.rpc(app,[['targets','show',target.id],['targets','list','--profile','other']]) as {result:unknown}[];
 assert.equal((responses[0]?.result as {id:string}).id,target.id);assert.deepEqual(responses[1]?.result,[]);
 const otherDenied=await f.run(app,['targets','register','--file',path,'--profile','other','--json']);assert.notEqual(otherDenied.exitCode,0);assert.match(otherDenied.stderr,/permission/i);
});
test('registered worker binding and durable idempotency remain after worker cleanup',async t=>{
 let store:Store;const f=await createCliFixture({after:action=>t.after(async()=>{store?.close();await (action as ()=>Promise<void>)();})},{applicationId:'insight-ghidra',profiles:[{name:'default',values:{server},permissions:['ReadOnly','Update']}]});const app=f.createApplication(runtime=>createInsightCli({runtime}));
 store=new Store(join(f.appArguments.AppDataDirectory,'ghidra'),'default',server);const target=store.register(identity);
 store.putWorker('reader',target.id,{pid:process.pid,endpoint:'http://127.0.0.1:19000',projectDirectory:'/synthetic/project',identity,version:1,role:'reader'});
 const proposal={requestId:'r-1',findingId:'f-1',workerId:'reader',targetId:target.id,identity,baselineVersion:1,address:'140001000',kind:'eol',before:null,after:'Synthetic finding',evidence:'Synthetic code evidence'};
 const path=join(f.root,'proposal.json');await writeFile(path,JSON.stringify(proposal));const accepted=await f.json(app,['findings','submit','--file',path]);store.removeWorker('reader');assert.deepEqual(await f.json(app,['findings','submit','--file',path]),accepted);
 const removed=await f.run(app,['profile','delete','default','--json']);assert.notEqual(removed.exitCode,0);
 assert.equal(store.findings().length,1);
});
test('native credentials are scoped through Factory secrets and profile JSON contains no password',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-ghidra',profiles:[{name:'default',values:{server,readerUser:'reader',publisherUser:'publisher'}},{name:'other',values:{server}}]});const app=f.createApplication(runtime=>createInsightCli({runtime}));
 const {Readable}=await import('node:stream');const login=await f.run(app,['auth','login','--role','reader','--password-stdin','--json'],{input:Readable.from(['synthetic-disposable-password\n'])});assert.equal(login.exitCode,0,login.stderr);
 const status=await f.json(app,['auth','status']) as {identity:{readerStored:boolean}};assert.equal(status.identity.readerStored,true);
 const other=await f.json(app,['auth','status','--profile','other']) as {identity:{readerStored:boolean}};assert.equal(other.identity.readerStored,false);
 const profile=await f.json(app,['profile','show']);assert.ok(!JSON.stringify(profile).includes('synthetic-disposable-password'));
});
test('profile deletion protects an unopened durable queue after owner restart',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-ghidra',profiles:[{name:'default',values:{server}},{name:'pending',values:{server}}]});
 const profileArgs=f.appArguments.WithProfile('pending');
 const store=new Store(join(profileArgs.AppDataDirectory,'ghidra'),'pending',server),identity2={...identity,profile:'pending'},target=store.register(identity2);
 store.putWorker('reader',target.id,{pid:process.pid,endpoint:'http://127.0.0.1:19000',projectDirectory:'/synthetic',identity:identity2,version:1,role:'reader'});store.submit({requestId:'r',findingId:'f',targetId:target.id,identity:identity2,workerId:'reader',baselineVersion:1,address:'140001000',kind:'eol',before:null,after:'Synthetic',evidence:'Synthetic'});store.close();
 const app=f.createApplication(runtime=>createInsightCli({runtime}));const deletion=await f.run(app,['profile','delete','pending','--json']);assert.notEqual(deletion.exitCode,0);assert.match(deletion.stderr,/preserved/);assert.ok(await stat(join(profileArgs.AppDataDirectory,'ghidra/coordinator.sqlite')));
});
