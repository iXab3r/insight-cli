import test,{type TestContext} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createRequire} from 'node:module';
import {connectInsight,InsightCommandError,InsightTransportError} from '../src/persistent-client.js';

test('new persistent subpath preserves root and legacy deep-path resolution for import and require',()=>{
 const require=createRequire(import.meta.url);
 for(const [name,file]of [['@eyeauras/insight-cli','index.js'],['@eyeauras/insight-cli/persistent','persistent-client.js'],['@eyeauras/insight-cli/dist/src/persistent-client.js','persistent-client.js']]){
  assert.ok(require.resolve(name!).endsWith(join('dist','src',file!)));assert.ok(import.meta.resolve(name!).endsWith('/dist/src/'+file));
 }
});

async function fixture(t:TestContext,body:string){
  const root=await mkdtemp(join(tmpdir(),'insight-rpc-test-'));t.after(()=>rm(root,{recursive:true,force:true}));const bin=join(root,'child.mjs');
  await writeFile(bin,`import{createInterface}from'node:readline';import{appendFileSync}from'node:fs';const log=${JSON.stringify(join(root,'received'))};const lines=createInterface({input:process.stdin});for await(const line of lines){const r=JSON.parse(line);appendFileSync(log,JSON.stringify(r)+String.fromCharCode(10));${body}}`);
  return {root,cli:await connectInsight({executable:process.execPath,arguments:[bin],cwd:root})};
}
test('one child, sequential IDs, argv preserved, unicode framing and close drains admitted commands',async t=>{
 const {root,cli}=await fixture(t,`const out=JSON.stringify({jsonrpc:'2.0',id:r.id,result:{argv:r.params.argv,pid:process.pid,text:'Ω😀'}})+String.fromCharCode(10);const b=Buffer.from(out);for(let i=0;i<b.length;i+=3)process.stdout.write(b.subarray(i,i+3));`);
 const a=cli.execute<any>(['first','space Ω','--json']),b=cli.execute<any>(['second','$(literal)']);const closed=cli.close();
 const [x,y]=await Promise.all([a,b]);await closed;assert.equal(x.pid,y.pid);assert.equal(x.text,'Ω😀');assert.deepEqual(x.argv,['first','space Ω','--json']);
 assert.deepEqual(y.argv,['second','$(literal)']);assert.deepEqual((await readFile(join(root,'received'),'utf8')).trim().split('\n').map(x=>JSON.parse(x).id),[1,2]);
 await assert.rejects(cli.execute(['after-close']),(e:unknown)=>e instanceof InsightTransportError&&!e.dispatched);await cli.close();
});
test('typed command errors retain data and do not break the next request',async t=>{
 const {cli}=await fixture(t,`process.stdout.write(JSON.stringify(r.id===1?{jsonrpc:'2.0',id:r.id,error:{code:-32000,message:'compile failed',data:{result:{state:'rejected',contextState:'ready'}}}}:{jsonrpc:'2.0',id:r.id,result:{ok:true}})+String.fromCharCode(10));`);
 await assert.rejects(cli.execute(['compile']),(e:unknown)=>e instanceof InsightCommandError&&(e.rpc.data as any).result.contextState==='ready');
 assert.deepEqual(await cli.execute(['read']),{ok:true});await cli.close();
});
test('lost mutation reply is dispatched once, queued work remains undispatched and no reconnect occurs',async t=>{
 const {root,cli}=await fixture(t,`process.exit(1);`);
 const results=await Promise.allSettled([cli.execute(['mutate','--request-id','owned']),cli.execute(['queued'])]);
 for(const r of results)assert.equal(r.status,'rejected');assert.equal((results[0] as PromiseRejectedResult).reason.dispatched,true);assert.equal((results[1] as PromiseRejectedResult).reason.dispatched,false);
 assert.equal((await readFile(join(root,'received'),'utf8')).trim().split('\n').length,1);await assert.rejects(cli.close());
});
test('malformed, null error, wrong ID and oversized replies fail the stream without replay',async t=>{
 for(const body of [`process.stdout.write('not-json'+String.fromCharCode(10));`,`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:r.id,error:null})+String.fromCharCode(10));`,`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:r.id+1,result:1})+String.fromCharCode(10));`,`process.stdout.write('x'.repeat(4*1024**2+1));`]){
  const {cli}=await fixture(t,body);await assert.rejects(cli.execute(['read']),(e:unknown)=>e instanceof InsightTransportError&&e.dispatched);await assert.rejects(cli.close());
 }
});
test('spawn failure and invalid argv do not dispatch',async t=>{
 await assert.rejects(connectInsight({executable:join(tmpdir(),'nonexistent-insight-'+process.pid)}),(e:unknown)=>e instanceof InsightTransportError&&!e.dispatched);
 const {cli}=await fixture(t,`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:r.id,result:1})+String.fromCharCode(10));`);await assert.rejects(cli.execute(['\0']),TypeError);await cli.close();
});

test('startup rejection retains sanitized reason and exit while queued work stays undispatched',async t=>{
 const {root,cli}=await fixture(t,`await new Promise(resolve=>process.stderr.write('synthetic-private-marker:'+ 'x'.repeat(16384)+'\\n',resolve));await new Promise(resolve=>process.stderr.write('Host build/protocol mismatch ',resolve));await new Promise(resolve=>process.stderr.write('or closing. Run ipc-server status/stop before retrying.'+'x'.repeat(16384)+'\\n',resolve));process.exit(1);`);
 const results=await Promise.allSettled([cli.execute(['changing','--request-id','owned']),cli.execute(['queued'])]);
 assert.equal(results[0]!.status,'rejected');assert.equal(results[1]!.status,'rejected');
 const first=(results[0] as PromiseRejectedResult).reason,queued=(results[1] as PromiseRejectedResult).reason;
 assert.ok(first instanceof InsightTransportError);assert.equal(first.dispatched,true);
 assert.ok(queued instanceof InsightTransportError);assert.equal(queued.dispatched,false);
 for(const error of [first,queued]){
  assert.deepEqual(error.termination,{exitCode:1,signal:null,reason:'host_incompatible'});
  assert.ok(Object.isFrozen(error.termination));assert.match(error.message,/host build\/protocol|host build/);assert.match(error.message,/exit 1/);
  assert.doesNotMatch(error.message,/synthetic-private-marker|xxxxx|status\/stop/);
 }
 await assert.rejects(cli.close(),(e:unknown)=>e instanceof InsightTransportError&&e.termination?.reason==='host_incompatible');
 await assert.rejects(cli.execute(['later']),(e:unknown)=>e instanceof InsightTransportError&&!e.dispatched&&e.termination?.exitCode===1&&/host build/.test(e.message));
 assert.equal((await readFile(join(root,'received'),'utf8')).trim().split('\n').length,1);
});

test('an exited frontend exposes exit details before any execute without exposing arbitrary stderr',async t=>{
 for(const kind of ['private','invalid_launch','ipc_disconnect']){
  const root=await mkdtemp(join(tmpdir(),'insight-rpc-startup-'));t.after(()=>rm(root,{recursive:true,force:true}));const bin=join(root,'child.mjs');
  const diagnostic=kind==='invalid_launch'?'The --json-rpc transport must be started without a CLI command.':kind==='ipc_disconnect'?'IPC invocation failed; command outcome may be unknown. No replay was attempted.':'synthetic-private-marker:never-export-this';
  const exitCode=kind==='private'?7:kind==='invalid_launch'?2:1;
  await writeFile(bin,`await new Promise(resolve=>process.stderr.write(${JSON.stringify(diagnostic)},resolve));process.exit(${exitCode});`);
  const cli=await connectInsight({executable:process.execPath,arguments:[bin]});
  await assert.rejects(cli.close(),(e:unknown)=>e instanceof InsightTransportError&&!e.dispatched&&e.termination?.exitCode===exitCode);
  await assert.rejects(cli.execute(['not-sent']),(e:unknown)=>{
   assert.ok(e instanceof InsightTransportError);assert.equal(e.dispatched,false);assert.equal(e.termination?.signal,null);
   assert.equal(e.termination?.reason,kind==='invalid_launch'?'invalid_rpc_launch':kind==='ipc_disconnect'?'ipc_disconnected':undefined);assert.doesNotMatch(e.message,/synthetic-private-marker|never-export-this/);
   assert.match(e.message,kind==='invalid_launch'?/without CLI command or profile flags/:kind==='ipc_disconnect'?/outcome may be unknown/:/exit 7/);return true;
  });
 }
});
