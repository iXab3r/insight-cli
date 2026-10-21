import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {referenceAlgorithm,referenceForms,referenceRequest,referenceResult,referenceEncoding,inspectCodeReferences} from '../src/code-references.js';
import type {Scope} from '../src/workspace.js';
import type {ResearchBackend} from '../src/research.js';
const who:Scope={session:'s_owned',target:'t_owned'};
const request=()=>referenceRequest({to:'2000',forms:'call-rel32',scanFrom:'1000',scanThrough:'1fff'},who);
function result(complete=false){return {algorithm:referenceAlgorithm,language:'x86:LE:64:default',forms:['call-rel32'],matches:[{from:'1000',to:'2000',form:'call-rel32',bytes:'e8fb0f0000',length:5,operand_index:0,operand_bits:64,target_role:'direct-call-target',validation:'decoded',boundary:'unconfirmed',instruction:'CALL 0x2000'}],scan:{from:'1000',through:'1fff',next_start:complete?null:'1001',complete,reason:complete?'exhausted':'result_limit',bytes_read:15,tested_starts:1,visited_candidates:1,elapsed_ms:0.1},read_only:{modification_unchanged:true}};}
test('small encoding contract handles displacement, widths and prefix order without including immediate MOV/SIMD/FS/GS/address override',()=>{
 const cases:[string,string,number,number,number][]=[['e8fb0f0000','call-rel32',5,64,4091],['488d05f90f0000','lea-rip',7,64,4089],['668b05f90f0000','mov-rip',7,16,4089],['488905f90f0000','mov-rip',7,64,4089],['8a05faffffff','mov-rip',6,8,-6],['48668d05f80f0000','lea-rip',8,16,4088],['66488d05f80f0000','lea-rip',8,64,4088],['ff15fa0f0000','call-rip-slot',6,64,4090]];
 for(const [bytes,form,length,bits,delta]of cases){const e=referenceEncoding(Buffer.from(bytes,'hex'))!;assert.equal(e.form,form);assert.equal(e.length,length);assert.equal(e.bits,bits);assert.equal(e.delta,delta);}
 for(const bytes of ['c705f60f000078563412','678b05fa0f0000','648b05fa0f0000','658b05fa0f0000','f38b05fa0f0000','0f1005fa0f0000','e800','48'.repeat(15)+'e800000000'])assert.equal(referenceEncoding(Buffer.from(bytes,'hex')),undefined,bytes);
 assert.equal(referenceEncoding(Buffer.from('b8e800000000','hex')),undefined);assert.equal(referenceEncoding(Buffer.from('e800000000','hex'))!.form,'call-rel32');
});
test('stateless continuation normalizes query, inherits controls, rejects selectors/malformed/scope and changed views',async()=>{
 const r=request(),observation={modification:'1',incarnation:'owned-process'};let calls=0;
 const backend={call:async()=>{calls++;return result();},observation:async()=>observation} as unknown as ResearchBackend;
 const first=await inspectCodeReferences(backend,who,r,'a'.repeat(64),observation),cursor=first.value.cursor!;
 const page=referenceRequest({cursor,limit:'17'},who);assert.equal(page.from,'1001');assert.equal(page.budgets.limit,17);assert.equal(page.budgets.max_bytes,r.budgets.max_bytes);assert.deepEqual(page.query,r.query);
 for(const key of ['to','forms','scanFrom','scanThrough'])assert.throws(()=>referenceRequest({cursor,[key]:'1000'},who));
 for(const token of ['x',cursor+'=', 'cr1.e30','cr1.__8'])assert.throws(()=>referenceRequest({cursor:token},who));
 assert.throws(()=>referenceRequest({cursor},{...who,target:'other'}));
 await assert.rejects(inspectCodeReferences(backend,who,page,'b'.repeat(64),observation),/view changed/);assert.equal(calls,1);
 backend.observation=async()=>({...observation,incarnation:'replacement'});
 await assert.rejects(inspectCodeReferences(backend,who,r,'a'.repeat(64),observation),/view changed/);
 const decoded=JSON.parse(Buffer.from(cursor.slice(4),'base64url').toString());decoded.budgets={};assert.throws(()=>referenceRequest({cursor:'cr1.'+Buffer.from(JSON.stringify(decoded)).toString('base64url')},who));
 const all=referenceRequest({to:'0x002000,1000',scanFrom:'0',scanThrough:'ffffffffffffffff'},who);assert.deepEqual(all.query.targets,['1000','2000']);assert.deepEqual(all.query.forms,referenceForms);
 for(const options of [{to:'1,01'},{forms:'mov-rip,mov-rip'},{forms:'jmp-rel32'},{maxBytes:'14'},{maxCandidates:'1000001'},{scanThrough:'fff'},{to:'ram:2000'},{to:Array(65).fill('1').join(',')}])assert.throws(()=>referenceRequest({to:'2000',scanFrom:'1000',scanThrough:'1fff',...options},who));
});
test('facade rejects inconsistent target, bytes, coverage, instruction extent, candidate counts and native mutation',()=>{
 const r=request();assert.equal(referenceResult(result(),r).algorithm,referenceAlgorithm);
 for(const mutate of [(v:any)=>v.matches[0].to='2001',(v:any)=>v.matches[0].bytes='e8fa0f0000',(v:any)=>v.matches[0].operand_bits=32,(v:any)=>v.matches[0].boundary='known',(v:any)=>v.matches.push(v.matches[0]),(v:any)=>v.scan.next_start='1000',(v:any)=>v.scan.complete=true,(v:any)=>v.scan.bytes_read=0,(v:any)=>v.scan.visited_candidates=0,(v:any)=>v.scan.from='1001',(v:any)=>v.read_only.modification_unchanged=false]){const v=result();mutate(v);assert.throws(()=>referenceResult(v,r));}
 assert.throws(()=>referenceResult(result(),{...r,query:{...r.query,end:'1003'}}));
});
test('relative targets wrap at 64 bits without JavaScript precision loss',()=>{
 const r=referenceRequest({to:'ffffffffffffffff',forms:'call-rel32',scanFrom:'0',scanThrough:'4'},who),v=result(true);
 Object.assign(v.matches[0]!,{from:'0',to:'ffffffffffffffff',bytes:'e8faffffff'});
 Object.assign(v.scan,{from:'0',through:'4',bytes_read:5,tested_starts:5});
 assert.equal(referenceResult(v,r).matches instanceof Array,true);
});
test('CLI and RPC share read-only route with no snapshots/journal writes and reject changed incarnation before scanning',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let calls=0,saves=0,incarnation='one',workspace:any;
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:w=>{workspace=w;const b=new SessionBackend(w) as SessionBackend&{observation:()=>Promise<unknown>};b.observation=async()=>({incarnation,modification:'1'});b.call=async(_s,op,p)=>{assert.equal(op,'/code_references');assert.equal(p!.max_bytes,4194304);calls++;return result();};b.saved=async()=>{saves++;throw Error('No read save');};return b;}}));
 const input=join(f.root,'owned.exe');await writeFile(input,'owned code references');const selected=await f.json(app,['ghidra','open',input,'--session','new','--no-analysis']) as Scope;
 const initial=JSON.stringify(workspace.context(selected));await f.profileStore.setPermissions('default',['ReadOnly']);
 const args=['ghidra','analysis','code-references','--session',selected.session,'--target',selected.target,'--to','2000','--forms','call-rel32','--scan-from','1000','--scan-through','1fff'];
 const value=await f.json(app,args) as any;const [rpc]=await f.rpc(app,[args]) as any[];assert.deepEqual(rpc.result,value);assert.equal(calls,2);assert.equal(saves,0);assert.equal(JSON.stringify(workspace.context(selected)),initial);
 incarnation='two';assert.notEqual((await f.run(app,['ghidra','analysis','code-references','--session',selected.session,'--target',selected.target,'--cursor',value.value.cursor,'--json'])).exitCode,0);assert.equal(calls,2);
});
