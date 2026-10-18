import test from 'node:test';
import assert from 'node:assert/strict';
import {ghidraBudget} from '../src/budgets.js';
import {HttpBridge} from '../src/transport.js';
test('native budgets are bounded profile execution policy with practical defaults',()=>{
 assert.equal(ghidraBudget({},'import'),3600000);assert.equal(ghidraBudget({},'save'),120000);
 assert.equal(ghidraBudget({initialImportSeconds:'86400'},'import'),86400000);
 assert.equal(ghidraBudget({saveSeconds:3600},'save'),3600000);
 for(const value of [0,-1,1.5,NaN,Infinity,'1e3',' 60',null,86401])assert.throws(()=>ghidraBudget({initialImportSeconds:value},'import'));
 for(const value of [0,3601,'abc'])assert.throws(()=>ghidraBudget({saveSeconds:value},'save'));
});
test('save and snapshot export share the configured budget; discovery stays short',async t=>{
 const budgets:number[]=[],paths:string[]=[];
 t.mock.method(AbortSignal,'timeout',(ms:number)=>{budgets.push(ms);return new AbortController().signal;});
 const fetch=async(input:string|URL|Request)=>{const path=new URL(String(input)).pathname;paths.push(path);return Response.json(path==='/mcp/schema'?{tools:['/save_program','/export_program'].map(path=>({path,method:'GET',params:[]}))}:{success:true});};
 const bridge=new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch,undefined,undefined,undefined,45000);
 await bridge.call('/save_program');await bridge.call('/export_program');
 assert.deepEqual(budgets,[30000,45000,45000]);assert.deepEqual(paths,['/mcp/schema','/save_program','/export_program']);
});
test('save deadline retains its phase and setting and sends no retry',async t=>{
 let requests=0;
 t.mock.method(AbortSignal,'timeout',(ms:number)=>ms===30000?new AbortController().signal:AbortSignal.abort());
 const fetch=async(input:string|URL|Request,init?:RequestInit)=>{requests++;init!.signal!.throwIfAborted();return Response.json({tools:[{path:'/save_program',method:'GET',params:[]}]});};
 await assert.rejects(new HttpBridge('http://127.0.0.1:19000',fetch as typeof globalThis.fetch).call('/save_program'),(error:unknown)=>{
  const e=error as {code:string;result:unknown};assert.equal(e.code,'coordinator.timeout');assert.deepEqual(e.result,{operation:'/save_program',timeoutMilliseconds:120000,phase:'save',budgetSetting:'saveSeconds',outcome:'unknown'});return true;
 });assert.equal(requests,2);
});
