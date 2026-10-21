import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {entryRequest} from '../src/function-entries.js';
import {locatedBoundaries} from '../src/function-boundaries.js';
import {inspectFunctions} from '../src/function-inspection.js';
import type {ResearchBackend} from '../src/research.js';
const request={addresses:['1008'],unwindMaximum:4194304},scope={session:'s_test',target:'t_test'},view={identity:'test'},observation={modification:'42'};
const opts={limit:8,offset:0,total:10,resolveAddress:'containing-or-pe-runtime'};
const boundary={source:'pe-exception-directory',begin:'1000',endExclusive:'1020',tableRecordAddress:'3000',semanticMembership:'not-established',instructionBoundary:'not-checked',unwindInfo:'not-parsed'};
const lookup={state:'validated',complete:true,reason:'validated',headersSource:'current-mapped-memory',recordCount:2,recordsValidated:2,bytesRead:256,maximumBytes:4194304,deadlineMilliseconds:5000};
const row={status:'resolved',entryPoint:'1000',kind:'pe-runtime-range',recordedBodyContainsAddress:false,database:null,boundary};
const packet=(r:unknown=row,s:unknown=lookup)=>({protocol:'insight-function-boundaries-v1',modification:'42',boundaryLookup:s,items:{'1008':r}});
test('PE mode budgets and literal selectors validate independently before dispatch',()=>{
 assert.deepEqual(entryRequest({functions:'0x1008,00001008'},opts),request);
 for(const options of [{...opts,maxEntryDistance:5},{maxUnwindBytes:1},{resolveAddress:'containing-or-preceding',maxEntryDistance:5,maxUnwindBytes:5},...[0,16777217,1.5,NaN].map(maxUnwindBytes=>({...opts,maxUnwindBytes}))])assert.throws(()=>entryRequest({functions:'1008'},options));
 assert.throws(()=>entryRequest({functions:'named'},opts));
});
test('native runtime evidence has strict full validation, half-open ranges and independent DB facts',()=>{
 assert.equal(locatedBoundaries(packet(),request,'42').entries.get('1008')!.entry,'1000');
 const database={entryPoint:'1000',kind:'recorded-containing',recordedBodyContainsAddress:true};
 assert.equal(locatedBoundaries(packet({...row,database,recordedBodyContainsAddress:true}),request,'42').entries.get('1008')!.entry,'1000');
 const high={...row,entryPoint:'fffffffffffffff0',boundary:{...boundary,begin:'fffffffffffffff0',endExclusive:'10000000000000000'}};
 assert.equal(locatedBoundaries({...packet(high),items:{'ffffffffffffffff':high}},{...request,addresses:['ffffffffffffffff']},'42').entries.get('ffffffffffffffff')!.entry,'fffffffffffffff0');
 for(const p of [packet({...row,boundary:{...boundary,endExclusive:'1008'}}),packet({...row,boundary:{...boundary,begin:'1009'}}),packet({...row,boundary:{...boundary,instructionBoundary:'verified'}}),packet({...row,database:{...database,entryPoint:'900'}}),packet({...row,entryPoint:'1001'}),packet(row,{...lookup,complete:false}),packet(row,{...lookup,recordsValidated:1}),packet(row,{...lookup,bytesRead:4194305}),{...packet(),modification:'43'},{...packet(),items:{'1009':row}},packet({...row,boundary:undefined})])assert.throws(()=>locatedBoundaries(p,request,'42'));
 for(const state of ['unavailable','incomplete','malformed']){
  const s={...lookup,state,complete:false,reason:state==='unavailable'?'headers_not_mapped':state==='incomplete'?'byte_limit':'invalid_runtime_range',recordsValidated:0};
  const unresolved={status:'unresolved',reason:'boundary_lookup_'+state,database,boundary:null};
  const r=locatedBoundaries(packet(unresolved,s),request,'42').entries.get('1008')!;assert.equal(r.status,'partial');assert.equal(r.entry,undefined);assert.deepEqual(r.resolution!.database,database);
  assert.throws(()=>locatedBoundaries(packet({...unresolved,boundary},s),request,'42'));
 }
 const conflict={status:'unresolved',reason:'boundary_conflict',database:{...database,entryPoint:'900'},boundary};
 assert.equal(locatedBoundaries(packet(conflict),request,'42').entries.get('1008')!.reason,'boundary_conflict');
 assert.throws(()=>locatedBoundaries(packet({...conflict,reason:'runtime_entry_not_defined'}),request,'42'));
});
test('batch aliases deduplicate native inspect and preserve unresolved evidence; single error includes lookup',async()=>{
 const calls:string[]=[];const unresolved={status:'unresolved',reason:'runtime_entry_not_defined',database:null,boundary};
 let missing=false;
 const backend={call:async(_s:unknown,op:string)=>{calls.push(op);return op==='/insight/function-boundaries/v1'?packet(missing?unresolved:row):{functions:{'1000':{name:'fixture',entry_point:'1000',decompiled_code:'abcdefghijk'}}};}} as unknown as ResearchBackend;
 const result=await inspectFunctions(backend,scope,{functions:'1008,0x1008',fields:'decompiled_code'},opts,view,observation,async()=>observation);
 const v=result.value as any;assert.equal(calls.length,2);assert.equal(v.functions['1008'].decompiled_code,'abcdefgh');assert.equal(v.functions['0x1008'].decompiled_code,'ab');assert.equal(v.boundaryLookup.complete,true);assert.deepEqual(v.functions['1008'].resolution.boundary,boundary);
 missing=true;calls.length=0;const r=await inspectFunctions(backend,scope,{functions:'1008'},opts,view,observation,async()=>observation);assert.equal((r.value as any).functions['1008'].status,'partial');assert.deepEqual(calls,['/insight/function-boundaries/v1']);
 await assert.rejects(inspectFunctions(backend,scope,{function:'1008'},opts,view,observation,async()=>observation),(e:any)=>e.result.reason==='runtime_entry_not_defined'&&e.result.boundaryLookup.complete===true&&e.result.resolution.boundary.begin==='1000');
});
test('after guard runs for failed lookup and bulk dispatch, rejects before save and never replays',async()=>{
 const root=await mkdtemp(join(tmpdir(),'pe-guard-'));
 for(const stage of ['lookup','inspect'])for(const changed of [false,true]){
  let observed=0,count=0;
  const backend={call:async(_s:unknown,op:string)=>{count++;if(stage==='inspect'&&op==='/insight/function-boundaries/v1')return packet();throw Error('lost native response');}} as unknown as ResearchBackend;
  const saveDirectory=join(root,stage+changed);
  await assert.rejects(inspectFunctions(backend,scope,{functions:'1008'}, {...opts,saveDirectory},view,observation,async()=>{observed++;return changed?{modification:'43'}:observation;}),(e:any)=>changed?e.result.reason==='changed_view':e.message==='lost native response');
  assert.equal(count,stage==='lookup'?1:2);assert.equal(observed,1);await assert.rejects(stat(saveDirectory),{code:'ENOENT'});
 }
});
