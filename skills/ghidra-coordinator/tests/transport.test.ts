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
