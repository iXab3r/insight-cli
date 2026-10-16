import test from 'node:test';
import assert from 'node:assert/strict';
import {queryResult} from '../src/query-results.js';
import {qualifyQuery,queryDescription} from '../src/query-policy.js';
import {blockContent,verifyMemoryCreation} from '../src/memory-inputs.js';
import {verifyMutation} from '../src/mutation-effects.js';
import {nativeQuery} from '../src/native-queries.js';
import type {HttpBridge} from '../src/transport.js';
import type {ResearchBackend} from '../src/research.js';
import type {Artifact} from '../src/artifacts.js';
import {readFile} from 'node:fs/promises';

test('the AES signature matches the independent finite-field definition for every byte',async()=>{
  const source=await readFile(new URL('../../references/native/InsightResearchQueries.java',import.meta.url),'utf8');
  const encoded=/signatures.put\("AES-SBOX",hex\("([^"]+)"/.exec(source)![1]!.replaceAll(' ','');
  assert.equal(encoded.length,512);
  const multiply=(a:number,b:number)=>{let value=0;for(let i=0;i<8;i++){if(b&1)value^=a;a=(a<<1)^(a&0x80?0x11b:0);b>>=1;}return value;};
  const expected=Array.from({length:256},(_,input)=>{let inverse=input?1:0;if(input)for(let n=0;n<254;n++)inverse=multiply(inverse,input);
    let value=inverse;for(let shift=1;shift<5;shift++)value^=((inverse<<shift)|(inverse>>(8-shift)))&255;return value^0x63;});
  assert.deepEqual([...Buffer.from(encoded,'hex')],expected);
});

test('nested unavailable results cannot masquerade as completed analysis, even with a valid outer envelope',()=>{
  for(const path of ['/find_dead_code','/detect_crypto_constants','/get_functions']) {
    assert.throws(()=>queryResult(path,{},[{status:'Not yet implemented'}]),/unavailable analysis/);
    assert.throws(()=>qualifyQuery(path,{functions:[{details:{status:'unsupported'}}]}),/unavailable analysis/);
  }
  assert.throws(()=>queryResult('/find_dead_code',{},[]),/object/);
  assert.doesNotThrow(()=>queryResult('/find_dead_code',{}, {findings:[],complete:false,unresolved_flow:true,algorithm:'static-cfg',scan:{visited:1,maximum:100,complete:true,reason:'exhausted'},truncated:false}));
  assert.match(queryDescription('/find_dead_code','unused'),/static CFG/);
});

test('heuristic confidence is explicitly uncalibrated and output limits are not mislabeled backend-work limits',()=>{
  const result=qualifyQuery('/suggest_field_names',{suggestions:[{offset:0,confidence:'medium'}]}) as Record<string,unknown>;
  assert.equal((result.semantics as Record<string,unknown>).kind,'suggestion');
  assert.deepEqual(result.suggestions,[{offset:0,confidence:null,confidence_kind:'uncalibrated'}]);
  assert.equal((result.scanPolicy as Record<string,unknown>).workBound,'not-guaranteed');
  const native=qualifyQuery('/list_globals',{globals:[],scan:{complete:false},truncated:true}) as Record<string,unknown>;
  assert.equal(native.scanPolicy,undefined);assert.equal(native.truncated,true);
});

test('native script success alone is insufficient; structured result and placeholder defenses survive adapter boundaries',async()=>{
  const fake=(console_output:string)=>({call:async()=>({success:true,console_output})}) as unknown as HttpBridge;
  await assert.rejects(nativeQuery(fake('compiled successfully'),'/program','/get_entry_points',{}),/unique result/);
  await assert.rejects(nativeQuery(fake('INSIGHT_QUERY:{"value":1}\nINSIGHT_QUERY:{"value":2}'),'/program','/get_entry_points',{}),/unique result/);
  await assert.rejects(nativeQuery(fake('INSIGHT_QUERY:{"error":{"code":"unsupported","message":"unsupported language"}}'),'/program','/emulate_function',{}),/unsupported language/);
  assert.deepEqual(await nativeQuery(fake('prefix\nINSIGHT_QUERY:{"value":{"matches":[],"complete":false}}\nsuffix'),'/program','/detect_crypto_constants',{}),{matches:[],complete:false});
});

test('block creation rejects conflicting/truncated content before dispatch and hashes padding independently',()=>{
  for(const p of [{bytes_hex:'a'},{bytes_base64:'YQ'},{bytes_hex:'01',bytes_base64:'AQ=='},{bytes_hex:'0102',size:1},
    {initialized:false,bytes_hex:'01',size:1},{initialized:false,fill_byte:1,size:1},{size:16777217}])assert.throws(()=>blockContent(p));
  assert.equal(blockContent({bytes_hex:'616263'}).sha256,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(blockContent({initialized:false,size:64}).sha256,null);
});

test('memory and prototype acknowledgments require the immutable DB effect, including content and convention',async()=>{
  const parameters={name:'Record',address:'0x1000',size:4,bytes_hex:'01020304',overlay:false},expected=blockContent(parameters);
  let value:Record<string,unknown>={exists:true,name:'Record',start:'1000',size:4,initialized:true,overlay:false,read:true,write:true,execute:false,volatile:false,comment:'',sha256:'wrong'};
  const backend={inspect:async()=>value} as unknown as ResearchBackend,snapshot={} as Artifact;
  await assert.rejects(verifyMemoryCreation(backend,snapshot,parameters),/content digest/);
  value.sha256=expected.sha256;await verifyMemoryCreation(backend,snapshot,parameters);
  value={exists:true,returnType:'int',parameters:[],expectedPrototype:{returnType:'int',parameters:[]},callingConvention:'__cdecl'};
  await assert.rejects(verifyMutation(backend,snapshot,'/set_function_prototype',{function_address:'1000',prototype:'int f(void)',calling_convention:'__fastcall'},{}),/convention/);
  (value.expectedPrototype as Record<string,unknown>).inlineCallingConvention='__thiscall';
  await assert.rejects(verifyMutation(backend,snapshot,'/set_function_prototype',{function_address:'1000',prototype:'int __thiscall f(void)'},{}),/convention/);
  value.callingConvention='__thiscall';
  await verifyMutation(backend,snapshot,'/set_function_prototype',{function_address:'1000',prototype:'int __thiscall f(void)'},{});
});
