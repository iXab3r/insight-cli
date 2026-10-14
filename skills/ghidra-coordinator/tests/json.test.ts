import test from 'node:test';
import assert from 'node:assert/strict';
import {parseDomainJson} from '../src/json.js';
import {decodeMcp,HttpBridge} from '../src/transport.js';
test('64-bit domain integers survive CLI/MCP/HTTP JSON without rounding or changing safe numbers/text',async()=>{
  const source='{"wide":9223372036854775807,"negative":-9223372036854775808,"safe":19,"ratio":0.5,"text":"9223372036854775807"}';
  const expected={wide:'9223372036854775807',negative:'-9223372036854775808',safe:19,ratio:0.5,text:'9223372036854775807'};
  assert.deepEqual(parseDomainJson(source),expected);
  assert.deepEqual(decodeMcp({content:[{type:'text',text:source}]}),expected);
  const fetch=async(input:string|URL|Request)=>String(input).endsWith('/mcp/schema')?
    Response.json({tools:[{path:'/enum',method:'GET',params:[]}]}):new Response(source);
  assert.deepEqual(await new HttpBridge('http://127.0.0.1:19009',fetch as typeof globalThis.fetch).call('/enum'),expected);
});
