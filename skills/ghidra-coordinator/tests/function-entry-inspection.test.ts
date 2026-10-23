import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {inspectFunctions} from '../src/function-inspection.js';
import {entryRequest,locatedEntries} from '../src/function-entries.js';
import type {ResearchBackend} from '../src/research.js';

const scope={session:'s_fixture',target:'t_fixture'},view={identity:'fixture-view'},observation={modification:'42'};
const opts={limit:3,offset:0,total:5,resolveAddress:'containing-or-preceding',maxEntryDistance:4096};
const row=(entryPoint:string,kind='preceding-entry-candidate',distanceBytes=8)=>({status:'resolved',entryPoint,kind,recordedBodyContainsAddress:kind!=='preceding-entry-candidate',...(kind==='recorded-containing'?{}:{distanceBytes})});
const response=(items:Record<string,unknown>)=>({protocol:'insight-function-entries-v1',modification:'42',items});

test('explicit bounded address policy validates literal selectors and options before native dispatch',()=>{
  assert.equal(entryRequest({functions:'named'},{}),undefined);
  assert.deepEqual(entryRequest({functions:'0x1008,00001008'},opts),{addresses:['1008'],maximum:4096});
  for(const [p,o] of [
    [{functions:'1008'},{maxEntryDistance:1}], [{functions:'1008'},{...opts,resolveAddress:'nearest'}],
    [{functions:'1008'},{resolveAddress:opts.resolveAddress}], [{functions:'1008'},{...opts,maxEntryDistance:0}],
    [{functions:'1008'},{...opts,maxEntryDistance:65537}], [{functions:'1008'},{...opts,maxEntryDistance:1.5}],
    [{functions:'named'},opts], [{functions:'ram:1008'},opts], [{functions:'10000000000000000'},opts],
    [{function:'1008',functions:'1009'},opts], [{functions:'1008,1008'},opts],
    [{functions:Array.from({length:21},(_,i)=>(0x1000+i).toString(16)).join(',')},opts]
  ] as const)assert.throws(()=>entryRequest(p,o),{code:'coordinator.invalid'});
});

test('native facts reject selector/view mismatches and fabricated candidate containment or distances',()=>{
  const request={addresses:['1008'],maximum:16};
  assert.equal(locatedEntries(response({'1008':row('1000')}),request,'42').get('1008')!.entry,'1000');
  for(const value of [
    {...response({'1008':row('1000')}),modification:'43'}, response({'1009':row('1000')}),
    response({'1008':{...row('1000'),distanceBytes:7}}),response({'1008':{...row('1000'),recordedBodyContainsAddress:true}}),
    response({'1008':row('1010',undefined,-8)}),response({'1008':row('ff0',undefined,24)}),
    response({'1008':row('1000','exact-entry',0)}),response({'1008':{...row('1000','recorded-containing'),distanceBytes:8}}),
    response({'1008':{status:'not_found',reason:'no_function_exists'}})
  ])assert.throws(()=>locatedEntries(value,request,'42'));
  // A noncontiguous recorded body can contain an address preceding the function entry.
  const earlier=locatedEntries(response({'1008':row('1010','recorded-containing')}),request,'42').get('1008')!;
  assert.equal(earlier.resolution!.distanceBytes,undefined);
});

test('fused reads deduplicate selected entries but charge every original row and retain provenance without requested metadata',async()=>{
  const calls:{op:string;p:Record<string,unknown>}[]=[];let observations=0;
  const backend={call:async(_s:unknown,op:string,p:Record<string,unknown>)=>{
    calls.push({op,p});if(op==='/insight/function-entries/v1')return response({'1008':row('1000'),'1009':row('1000',undefined,9),'3000':{status:'not_found',reason:'entry_distance_exceeded'}});
    assert.equal(op,'/get_functions');assert.equal(p.functions,'1000');assert.equal(p.fields,'decompiled_code,entry_point');
    return {functions:{'1000':{name:'fixture',entry_point:'00001000',decompiled_code:'a😀бc'}}};
  }} as unknown as ResearchBackend;
  const result=await inspectFunctions(backend,scope,{functions:'0x1008,00001009,3000',fields:'decompiled_code'},opts,view,observation,async()=>{observations++;return observation;});
  const value=result.value as any;assert.equal(calls.length,2);assert.equal(observations,1);
  assert.deepEqual(calls[0]!.p,{addresses:'1008,1009,3000',max_entry_distance:4096});
  assert.equal(value.functions['0x1008'].decompiled_code,'a😀б');assert.equal(value.functions['00001009'].decompiled_code,'a😀');
  assert.equal(value.textBudget.returnedCharacters,5);assert.equal(value.functions['0x1008'].entry_point,'1000');
  assert.equal(value.functions['0x1008'].resolution.requestedAddress,'0x1008');assert.equal(value.functions['00001009'].resolution.distanceBytes,9);
  assert.equal(value.functions['0x1008'].text.textSha256,value.functions['00001009'].text.textSha256);
  assert.equal(value.functions['3000'].status,'not_found');assert.equal(value.functions['3000'].reason,'entry_distance_exceeded');
});

test('policy misses avoid empty native bulk reads; native per-item failures keep selected entry and resolution',async()=>{
  let reads=0,mode='miss';const backend={call:async(_s:unknown,op:string)=>{
    if(op==='/insight/function-entries/v1')return response({'1008':mode==='miss'?{status:'not_found',reason:'no_preceding_entry'}:row('1000')});
    reads++;return {functions:{'1000':{error:'Decompiler failed'}}};
  }} as unknown as ResearchBackend;
  const invoke=()=>inspectFunctions(backend,scope,{functions:'1008',fields:'decompiled_code'},opts,view,observation,async()=>observation);
  let result=await invoke();assert.equal((result.value as any).functions['1008'].reason,'no_preceding_entry');assert.equal(reads,0);
  mode='failure';result=await invoke();const failed=(result.value as any).functions['1008'];assert.equal(reads,1);assert.equal(failed.status,'failed');
  assert.equal(failed.reason,'native_function_failure');assert.equal(failed.selector,'1008');assert.equal(failed.entry_point,'1000');assert.equal(failed.resolution.kind,'preceding-entry-candidate');
});

test('changed/lost observations and mismatched backend identity fail before owner saves; aliases preserve manifests and continuation',async()=>{
  const root=await mkdtemp(join(tmpdir(),'entry-inspection-'));let mismatch=false;
  const backend={call:async(_s:unknown,op:string)=>op==='/insight/function-entries/v1'?response({'1008':row('1000'),'1009':row('1000',undefined,9)}):{functions:{'1000':{name:'fixture',entry_point:mismatch?'2000':'1000',decompiled_code:'abcdef'}}}} as unknown as ResearchBackend;
  const parameters={functions:'1008,1009',fields:'decompiled_code'},saved={...opts,saveDirectory:join(root,'saved')};
  await assert.rejects(inspectFunctions(backend,scope,parameters,saved,view,observation,async()=>({modification:'43'})),(e:any)=>e.result.reason==='changed_view');
  await assert.rejects(stat(saved.saveDirectory),{code:'ENOENT'});
  await assert.rejects(inspectFunctions(backend,scope,parameters,saved,view,observation,async()=>{throw Error('lost observation');}),/lost observation/);
  mismatch=true;await assert.rejects(inspectFunctions(backend,scope,parameters,saved,view,observation,async()=>observation),(e:any)=>e.result.reason==='selector_mismatch');
  await assert.rejects(stat(saved.saveDirectory),{code:'ENOENT'});mismatch=false;
  const result=await inspectFunctions(backend,scope,parameters,saved,view,observation,async()=>observation),manifest=JSON.parse(await readFile(join(saved.saveDirectory,'manifest.json'),'utf8'));
  assert.deepEqual(manifest.value,JSON.parse(JSON.stringify(result.value)));const values=(result.value as any).functions;
  assert.equal(await readFile(values['1008'].savedText.file,'utf8'),'abcdef');assert.notEqual(values['1008'].savedText.file,values['1009'].savedText.file);
  const page=await inspectFunctions(backend,scope,parameters,{...opts,offset:3,expectView:view.identity},view,observation,async()=>observation);
  assert.equal((page.value as any).functions['1008'].decompiled_code,'def');
});
