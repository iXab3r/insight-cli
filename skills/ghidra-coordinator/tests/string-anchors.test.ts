import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {anchorAlgorithm,anchorRequest,anchorResult,inspectAnchors} from '../src/string-anchors.js';
import type {Scope} from '../src/workspace.js';
import type {ResearchBackend} from '../src/research.js';
const who:Scope={session:'s_owned',target:'t_owned'};
const options={text:'Widget',encodings:'ascii',scanFrom:'1000',scanThrough:'1fff'};
const request=()=>anchorRequest(options,who);
function result(complete=false){return {algorithm:anchorAlgorithm,encodings:['ascii'],modification:'1',matches:[{encoding:'ascii',matchAddress:'1012',matchByteLength:6,matchOffsetBytes:2,literalCandidate:{start:'1010',terminatorAddress:'101a',byteLength:10,textFrom:'1010',text:'a/Widget.x',textBytes:Buffer.from('a/Widget.x').toString('hex'),textByteLength:10,leftBoundary:'nul',rightBoundary:'nul',boundariesComplete:true,decoding:'valid',complete:true,reason:'complete'}}],scan:{from:{address:'1000',encoding:'ascii'},through:'1fff',next:complete?null:{address:'1013',encoding:'ascii'},complete,reason:complete?'exhausted':'result_limit',bytesRead:4096,testedPairs:19,candidates:1,elapsedMs:.1}};}
test('literal validation, explicit encodings, numeric range/cap and bounded page controls',()=>{
 const normalized=anchorRequest({...options,encodings:'utf16le, ascii',scanFrom:'0x001000'},who);
 assert.deepEqual(normalized.query.encodings,['ascii','utf16le']);assert.equal(normalized.query.start,'1000');
 for(const change of [{text:''},{text:'\0'},{text:'x'.repeat(257)},{text:'\ud800'},{text:'\udc00'},{text:'Ω'},{encodings:'utf8'},{encodings:'ascii,ascii'},{encodings:''},{scanThrough:'fff'},{scanFrom:'ram:1000'},{maxStringBytes:17},{maxStringBytes:14},{maxBytes:32767},{maxCandidates:0},{timeoutSeconds:31},{limit:1001}])assert.throws(()=>anchorRequest({...options,...change},who));
 assert.equal(anchorRequest({...options,text:'😀',encodings:'utf16le'},who).query.text,'😀');
});
test('stateless cursor binds scope/view/query, retains budgets, permits only page-control overrides',async()=>{
 const observation={modification:'1',incarnation:'owned'},view='a'.repeat(64);let calls=0;
 const backend={call:async()=>{calls++;return result();}} as unknown as ResearchBackend;
 const first=await inspectAnchors(backend,who,request(),view,observation,async()=>observation),cursor=first.value.cursor!;
 const next=anchorRequest({cursor,limit:'17'},who);assert.equal(next.from.address,'1013');assert.equal(next.budgets.limit,17);assert.equal(next.budgets.max_bytes,4194304);assert.deepEqual(next.query,request().query);
 for(const key of ['text','encodings','scanFrom','scanThrough','maxStringBytes'])assert.throws(()=>anchorRequest({cursor,[key]:'x'},who));
 for(const value of ['x',cursor+'=','sa1.e30','sa1.__8'])assert.throws(()=>anchorRequest({cursor:value},who));
 assert.throws(()=>anchorRequest({cursor},{...who,target:'other'}));
 await assert.rejects(inspectAnchors(backend,who,next,'b'.repeat(64),observation,async()=>observation),/view changed/);assert.equal(calls,1);
 await assert.rejects(inspectAnchors(backend,who,request(),view,observation,async()=>({...observation,incarnation:'changed'})),/view changed/);assert.equal(calls,2);
 backend.call=async()=>{throw Error('Native refused changed program');};
 await assert.rejects(inspectAnchors(backend,who,request(),view,observation,async()=>({...observation,modification:'2'})),/view changed/);
 await assert.rejects(inspectAnchors(backend,who,request(),view,observation,async()=>observation),/Native refused/);
 await assert.rejects(inspectAnchors(backend,who,request(),view,observation,async()=>{throw Error('After-observation unavailable');}),/After-observation unavailable/);
 const token=JSON.parse(Buffer.from(cursor.slice(4),'base64url').toString());token.budgets={};assert.throws(()=>anchorRequest({cursor:'sa1.'+Buffer.from(JSON.stringify(token)).toString('base64url')},who));
});
test('protocol rejects invented matches, boundaries, offsets, decoding, coverage, counters and mutation',()=>{
 const r=request();assert.equal(anchorResult(result(),r,'1').algorithm,anchorAlgorithm);
 const changes=[(v:any)=>v.matches[0].matchAddress='1013',(v:any)=>v.matches[0].matchOffsetBytes=3,(v:any)=>v.matches[0].matchByteLength=7,(v:any)=>v.matches[0].literalCandidate.start='100f',(v:any)=>v.matches[0].literalCandidate.text='different',(v:any)=>v.matches[0].literalCandidate.textBytes='00'+v.matches[0].literalCandidate.textBytes.slice(2),(v:any)=>v.matches.push(v.matches[0]),(v:any)=>v.scan.next.address='1000',(v:any)=>v.scan.complete=true,(v:any)=>v.scan.bytesRead=0,(v:any)=>v.scan.candidates=0,(v:any)=>v.scan.from.address='1001',(v:any)=>v.modification='2'];
 for(const change of changes){const v=result();change(v);assert.throws(()=>anchorResult(v,r,'1'));}
 const partial=result();Object.assign(partial.matches[0]!.literalCandidate,{start:null,byteLength:null,leftBoundary:'range_edge',boundariesComplete:false,complete:false,reason:'missing_boundary'});partial.matches[0]!.matchOffsetBytes=null as any;assert.equal(anchorResult(partial,r,'1').matches instanceof Array,true);
 const bad=result();Object.assign(bad.matches[0]!.literalCandidate,{text:null,textBytes:Buffer.from([255,...Buffer.from('/Widget.x')]).toString('hex'),decoding:'invalid',complete:false,reason:'invalid_encoding'});assert.equal(anchorResult(bad,r,'1').matches instanceof Array,true);
});
test('CLI/RPC share read-only precompiled endpoint and fast ordered observations without snapshots',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let calls=0,observations=0,saves=0,incarnation='one',workspace:any;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{workspace=w;const b=new SessionBackend(w) as SessionBackend&{inspectObservation:()=>Promise<unknown>};b.inspectObservation=async()=>{observations++;return {incarnation,modification:'1'};};b.call=async(_s,op,p)=>{assert.equal(op,'/insight/string-anchors/v1');assert.equal(p!.max_bytes,4194304);calls++;return result();};b.saved=async()=>{saves++;throw Error('No read save');};return b;}}));
 const input=join(f.root,'owned.exe');await writeFile(input,'owned string anchors');const selected=await f.json(app,['ghidra','open',input,'--session','new','--no-analysis']) as Scope;
 const initial=JSON.stringify(workspace.context(selected));await f.profileStore.setPermissions('default',['ReadOnly']);
 const args=['ghidra','strings','anchors','--session',selected.session,'--target',selected.target,'--text','Widget','--encodings','ascii','--scan-from','1000','--scan-through','1fff'];
 const value=await f.json(app,args) as any;const [rpc]=await f.rpc(app,[args]) as any[];assert.deepEqual(rpc.result,value);assert.equal(calls,2);assert.equal(observations,4);assert.equal(saves,0);assert.equal(JSON.stringify(workspace.context(selected)),initial);
 incarnation='two';assert.notEqual((await f.run(app,['ghidra','strings','anchors','--session',selected.session,'--target',selected.target,'--cursor',value.value.cursor,'--json'])).exitCode,0);assert.equal(calls,2);
});
