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
  assert.ok(require.resolve(name!).endsWith('/dist/src/'+file));assert.ok(import.meta.resolve(name!).endsWith('/dist/src/'+file));
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
