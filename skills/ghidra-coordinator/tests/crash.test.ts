import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{spawn}from'node:child_process';
import {fileURLToPath} from 'node:url';
import{Store}from'../src/store.js';import{Coordinator,type Publisher}from'../src/coordinator.js';import{key}from'../src/model.js';
for(const phase of ['accepted','local_application','staged','checking_in','publication_unknown','verification'])test('SIGKILL/restart at '+phase,async t=>{
 const dir=await mkdtemp(join(tmpdir(),'insight-kill-'));let store:Store;t.after(async()=>{store?.close();await rm(dir,{recursive:true,force:true});});
 const child=spawn(process.execPath,[fileURLToPath(new URL('./crash-child.js',import.meta.url)),dir,phase],{stdio:'ignore'});const exit=await new Promise<{code:number|null;signal:string|null}>((ok,bad)=>{child.once('error',bad);child.once('exit',(code,signal)=>ok({code,signal}));});if(process.platform==='win32')assert.equal(exit.code,1);else assert.equal(exit.signal,'SIGKILL');
 store=new Store(dir,'default','ghidra://127.0.0.1:14100');assert.equal(store.findings().length,1);const batch=store.batches()[0]!;
 const remote=JSON.parse(await readFile(join(dir,'synthetic-remote.json'),'utf8'));
 let commits=0;const unsupported=async()=>{throw Error('No recovery write may execute');};
 const publisher:Publisher={open:unsupported,checkout:unsupported,read:unsupported,apply:unsupported,save:unsupported,checkIn:async()=>{commits++;return 3;},published:async(t,f)=>({identity:t,version:remote.version,values:Object.fromEntries(f.map(x=>[key(x),remote.values[key(x)]??null]))}),history:async(_t,id)=>remote.markers.includes(id)?[2]:[],released:async()=>true,release:unsupported,complete:async()=>{},abandon:async()=>{}};
 const c=new Coordinator(store,publisher);
 if(['publication_unknown','verification'].includes(phase)){assert.equal((await c.recover(batch.id)).state,'published_verified');assert.equal(remote.version,2);}
 else if(phase==='checking_in'){await assert.rejects(c.recover(batch.id),/insufficient/);await assert.rejects(c.integrate(batch.targetId),/recovery/);assert.equal(remote.version,1);}
 else{await assert.rejects(c.recover(batch.id),/retained/);assert.equal((await c.recover(batch.id,true)).state,'conflict_pending');}
 assert.equal(commits,0);
});
test('another process cannot recover a live prior owner',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'insight-live-')),store=new Store(dir,'default','ghidra://127.0.0.1:14100');t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});
 const identity={profile:'default',server:'ghidra://127.0.0.1:14100',repository:'alpha',programPath:'/fixture.exe',binarySha256:'a'.repeat(64),language:'x86:LE:64:default',compilerSpec:'windows',imageBase:'140000000'};const target=store.register(identity);store.putWorker('reader',target.id,{pid:process.pid,endpoint:'http://127.0.0.1:19000',projectDirectory:'/synthetic',identity,version:1,role:'reader'});store.submit({requestId:'r',findingId:'f',targetId:target.id,identity,workerId:'reader',baselineVersion:1,address:'140001000',kind:'eol',before:null,after:'Synthetic',evidence:'Synthetic'});store.begin(target.id);
 const child=spawn(process.execPath,[fileURLToPath(new URL('./recovery-child.js',import.meta.url)),dir],{stdio:['ignore','pipe','ignore']});let result='';child.stdout.on('data',chunk=>result+=chunk);const code=await new Promise(ok=>child.once('exit',ok));assert.equal(code,1);assert.equal(JSON.parse(result).code,'coordinator.busy');assert.equal(store.batches()[0]!.state,'applying');
});
