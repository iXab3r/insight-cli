import test from'node:test';import assert from'node:assert/strict';import{HttpBridge,decodeMcp}from'../src/transport.js';
test('MCP success envelope with error, missing or malformed content is rejected',()=>{
 for(const result of [{isError:true,content:[{type:'text',text:'{}'}]},{isError:false,content:[{type:'text',text:'{"error":"synthetic failure"}'}]},{isError:false,content:[]},{isError:false,content:[{type:'text',text:'{"success":false}'}]}])assert.throws(()=>decodeMcp(result));
 assert.deepEqual(decodeMcp({isError:false,content:[{type:'text',text:'{"status":"success"}'}]}),{status:'success'});
 assert.deepEqual(decodeMcp({isError:false,content:[{type:'text',text:'["first","second"]'}]}),['first','second']);
});
test('HTTP queries accept bounded array results and retain useful backend domain failures',async()=>{
 const fetch=async(input:string|URL|Request)=>String(input).endsWith('/mcp/schema')?
   Response.json({tools:[{path:'/list',method:'GET',params:[]},{path:'/inspect',method:'GET',params:[]}]}):
   String(input).endsWith('/list')?Response.json(['first','second']):Response.json({error:'No P-code operations at the selected address'});
 const bridge=new HttpBridge('http://127.0.0.1:19001',fetch as typeof globalThis.fetch);
 assert.deepEqual(await bridge.call('/list'),['first','second']);
 await assert.rejects(bridge.call('/inspect'),/No P-code operations/);
});
test('HTTP status alone is insufficient, schema controls body/query selectors',async()=>{
 const requests:{url:string;init?:RequestInit}[]=[];
 const fetch=async(input:string|URL|Request,init?:RequestInit)=>{const url=String(input);requests.push({url,init});if(url.endsWith('/mcp/schema'))return new Response(JSON.stringify({tools:[{path:'/set_comment',method:'POST',params:[{name:'program',source:'query'},{name:'address',source:'body'},{name:'comment',source:'body'}]}]}));return new Response('{"success":false}');};
 const bridge=new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch);
 await assert.rejects(bridge.call('/set_comment',{program:'/fixture.exe',address:'140001000',comment:'Synthetic'}),/operation failed/);
 assert.ok(requests[1]!.url.includes('program=%2Ffixture.exe'));assert.deepEqual(JSON.parse(String(requests[1]!.init?.body)),{address:'140001000',comment:'Synthetic'});
 await assert.rejects(bridge.call('/set_comment',{unknown:'selector'}),/parameter/);
});
test('worker URLs require an exact loopback port',()=>{for(const endpoint of ['http://example.test:19000','http://127.0.0.1','https://127.0.0.1:19000','http://user:password@127.0.0.1:19000'])assert.throws(()=>new HttpBridge(endpoint));});
test('initial import allows analysis to exceed discovery budget without retrying the operation',async t=>{
 const budgets:number[]=[],paths:string[]=[];
 t.mock.method(AbortSignal,'timeout',(ms:number)=>{budgets.push(ms);return new AbortController().signal;});
 const fetch=async(input:string|URL|Request)=>{const path=new URL(String(input)).pathname;paths.push(path);return Response.json(path==='/mcp/schema'?{tools:[{path:'/import_file',method:'POST',params:[]}]}:{success:true});};
 await new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch).call('/import_file');
 assert.deepEqual(budgets,[30000,600000]);assert.deepEqual(paths,['/mcp/schema','/import_file']);
});
test('timeout and caller cancellation retain useful operation details without exposing credentials',async t=>{
 t.mock.method(AbortSignal,'timeout',()=>AbortSignal.abort(new DOMException('Timed out','TimeoutError')));
 const fetch=async(_input:string|URL|Request,init?:RequestInit)=>{init!.signal!.throwIfAborted();return Response.json({});};
 const timeout=new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch,undefined,'private-test-token');
 await assert.rejects(timeout.instance(),(error:unknown)=>{const e=error as {code:string;message:string;result:unknown};assert.equal(e.code,'coordinator.timeout');assert.match(e.message,/mcp\/instance_info.*30 seconds/);assert.doesNotMatch(e.message,/private-test-token|19000/);return true;});
 const cancelled=new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch,AbortSignal.abort());
 await assert.rejects(cancelled.instance(),(error:unknown)=>(error as {code:string}).code==='coordinator.cancelled');
});
test('response stream failure is a bounded transport error rather than a raw stack',async()=>{
 const fetch=async()=>new Response(new ReadableStream({start(controller){controller.error(new Error('private native error'));}}));
 await assert.rejects(new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch).instance(),/Ghidra request \/mcp\/instance_info did not complete/);
});
test('authenticated descriptor reuse rebinds cancellation and never crosses token identity',async()=>{
 let schemas=0;const signals:AbortSignal[]=[],tokens:string[]=[];
 const fetch=async(input:string|URL|Request,init?:RequestInit)=>{init!.signal!.throwIfAborted();signals.push(init!.signal!);tokens.push(String((init!.headers as Record<string,string>).Authorization));if(String(input).endsWith('/mcp/schema')){schemas++;return Response.json({tools:[{path:'/read',method:'GET',params:[]}]});}return Response.json({ok:true});};
 const first=new AbortController(),bridge=new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch,first.signal,'owned-token');
 await bridge.call('/read');first.abort();const second=new AbortController();
 const next=bridge.forRequest(fetch as typeof globalThis.fetch,second.signal,'owned-token',120000);assert.deepEqual(await next.call('/read'),{ok:true});assert.equal(schemas,1);assert.equal(signals.at(-1)!.aborted,false);
 const changed=next.forRequest(fetch as typeof globalThis.fetch,second.signal,'other-owned-token',120000);await changed.call('/read');assert.equal(schemas,2);assert.equal(tokens.at(-1),'Bearer other-owned-token');
 second.abort();await assert.rejects(next.call('/read'),/cancelled/);
});
