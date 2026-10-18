import test from 'node:test';
import assert from 'node:assert/strict';
import {distribution,summarize} from '../performance/compare.mjs';
test('performance summary retains failures/censoring and removes only declared warmups',()=>{
 const d=distribution([10,1,2,3,4]);assert.deepEqual({n:d.n,p50:d.p50,p95:d.p95,mad:d.mad},{n:5,p50:3,p95:10,mad:1});
 const base={label:'before',fixture:'tiny',analysis:false,route:'cli',stage:'read.metadata'};
 const out=summarize([{...base,ok:true,ms:2},{...base,ok:true,ms:4},{...base,ok:false,ms:99,censored:true},{...base,ok:true,ms:0,warmup:true}]);
 const r=out['before/tiny/no-analysis/cli/read.metadata'];assert.equal(r.n,2);assert.equal(r.failures,1);assert.equal(r.censored,1);assert.equal(r.p50,2);
});
import {gate} from '../performance/gate.mjs';
import {pairedOverhead} from '../performance/paired-overhead.mjs';
test('paired route differences preserve negative deltas and reject missing or duplicate rounds',()=>{const base={evidencePhase:'baseline',label:'baseline',fixture:'tiny',analysis:false,stage:'read.metadata',ok:true,sample:0,startNs:'0'},records=[{...base,route:'cli',ms:10},{...base,route:'rpc',ms:20}];assert.equal(pairedOverhead(records,1).groups['baseline/tiny/no-analysis/read.metadata'].cliMinusRpcMs.p50,-10);assert.equal(pairedOverhead(records,1).passed,true);assert.equal(pairedOverhead(records.slice(0,1),1).passed,false);assert.equal(pairedOverhead([...records,records[0]],1).passed,false);});
test('performance gate rejects missing/failed samples and tolerates only declared variability',()=>{
 const b={'before/tiny/no-analysis/cli/read.metadata':{n:30,p50:100,p95:120,mad:2,failures:0,censored:0}},a={'after/tiny/no-analysis/cli/read.metadata':{n:30,p50:110,p95:130,mad:2,failures:0,censored:0}};
 assert.equal(gate(b,a).passed,true);a['after/tiny/no-analysis/cli/read.metadata'].p50=130;assert.equal(gate(b,a).passed,false);assert.equal(gate(b,{}).passed,false);assert.equal(gate({},{}).passed,false);a['after/tiny/no-analysis/cli/read.metadata'].n=3;assert.equal(gate(b,a).passed,false);
});
import {union,traceCoverage,settledTraceReport} from '../performance/trace-report.mjs';
test('timing coverage subtracts interval union, including nested/parallel overlap',()=>{assert.equal(union([[0n,10n],[2n,4n],[8n,12n],[20n,25n]]),17);});
test('native diagnostic trace coverage rejects missing stages and unresolved context trees',()=>{const empty=traceCoverage({stages:{},danglingParents:0,bindingScopesWithMultipleRequests:1});assert.equal(empty.passed,false);const stages=Object.fromEntries(empty.required.map(s=>[s,{count:1}]));assert.equal(traceCoverage({stages,danglingParents:0,bindingScopesWithMultipleRequests:1}).passed,true);assert.equal(traceCoverage({stages,danglingParents:1,bindingScopesWithMultipleRequests:1}).passed,false);assert.equal(traceCoverage({stages,danglingParents:0,bindingScopesWithMultipleRequests:0}).passed,false);});
import {mkdtemp,mkdir,writeFile,appendFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PublicCli,Recorder} from '../performance/public.mjs';
import {scriptEffects} from '../performance/script-effects.mjs';
import {requestTraces} from '../performance/request-traces.mjs';
test('trace finalization waits passively for late lifetime roots and retains unresolved parents',async t=>{const root=await mkdtemp(join(tmpdir(),'perf-trace-settle-'));t.after(()=>rm(root,{recursive:true,force:true}));const file=join(root,'owned.jsonl'),base={schema:1,pid:1,request:'owned',startNs:'0',durationNs:'10',ok:true};await writeFile(file,JSON.stringify({...base,id:2,parent:1,stage:'gate.wait'})+'\n');let pending;const timer=setTimeout(()=>{pending=appendFile(file,JSON.stringify({...base,id:1,stage:'command.total'})+'\n');},20);t.after(()=>clearTimeout(timer));const settled=await settledTraceReport(root,{timeoutMs:2000,intervalMs:10});await pending;assert.equal(settled.danglingParents,0);assert.equal(settled.records,2);await writeFile(file,JSON.stringify({...base,id:2,parent:1,stage:'gate.wait'})+'\n');const missing=await settledTraceReport(root,{timeoutMs:20,intervalMs:10});assert.equal(missing.danglingParents,1);assert.equal(missing.records,1);});
test('private transcript reduction binds script effects while retaining only public state counts',async t=>{
 const root=await mkdtemp(join(tmpdir(),'perf-effects-'));t.after(()=>rm(root,{recursive:true,force:true}));
 for(const label of ['baseline','candidate'])for(const fixture of ['tiny','large'])for(const analysis of [false,true]){const directory=join(root,label,fixture+'-'+(analysis?'analysis':'no-analysis')+'-0');await mkdir(directory,{recursive:true});await writeFile(join(directory,'requests.jsonl'),[{n:1,stage:'state.before-read-script',ok:true},{n:2,stage:'state.after-read-script',ok:true}].map(JSON.stringify).join('\n'));for(let n=1;n<=2;n++)await writeFile(join(directory,n+'.stdout'),JSON.stringify({session:'private-session',ghidra:{state:'ready',baseRevision:'R3',sharedRevision:'R3',unresolvedRequests:[],pendingChanges:n-1}}));}
 const result=await scriptEffects(root,1);assert.equal(result.passed,true);assert.equal(result.observations.length,8);assert.ok(!JSON.stringify(result).includes('private-session'));await writeFile(join(root,'candidate/tiny-no-analysis-0/2.stdout'),JSON.stringify({ghidra:{state:'ready',baseRevision:'R3',sharedRevision:'R3',unresolvedRequests:[],pendingChanges:0}}));assert.equal((await scriptEffects(root,1)).passed,false);
});
test('serial trace windows retain repeated work and reject ambiguous request overlap',async t=>{
 const root=await mkdtemp(join(tmpdir(),'perf-windows-'));t.after(()=>rm(root,{recursive:true,force:true}));await mkdir(join(root,'trace'));await mkdir(join(root,'candidate-trace'));const request={fixture:'tiny',analysis:false,stage:'persistence.read-script',route:'cli',startNs:'0',ms:.001};await writeFile(join(root,'candidate-trace/requests.jsonl'),JSON.stringify(request)+'\n');await writeFile(join(root,'trace/owned.jsonl'),[{stage:'backend.http.save_program',startNs:'100',durationNs:'50'},{stage:'backend.http.save_program',startNs:'200',durationNs:'60'},{stage:'backend.http.save_program',startNs:'2000',durationNs:'30'}].map(JSON.stringify).join('\n'));const result=await requestTraces(root);assert.equal(result.windows[0].stages['backend.http.save_program'].count,2);assert.equal(result.windows[0].stages['backend.http.save_program'].inclusiveSpanMs.p95,.00006);await writeFile(join(root,'candidate-trace/requests.jsonl'),[request,{...request,startNs:'500'}].map(JSON.stringify).join('\n'));await assert.rejects(requestTraces(root),/isolated serial/);
});
test('public benchmark adapter retains expected missing-function replies as checked evidence',async t=>{
 const root=await mkdtemp(join(tmpdir(),'perf-adapter-'));t.after(()=>rm(root,{recursive:true,force:true}));const bin=join(root,'owned.mjs');
 await writeFile(bin,`import{createInterface}from'node:readline';const input=createInterface({input:process.stdin});input.on('line',line=>{const r=JSON.parse(line);process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:r.id,error:{code:-32000,message:'Owned absent function',data:{code:'coordinator.partial',result:{reason:'function_not_found'}}}})+'\\n');});`);
 const recorder=new Recorder(root,{label:'synthetic'}),cli=new PublicCli(bin,'owned',recorder);cli.scope={session:'s_owned',target:'t_owned'};const rpc=await cli.rpc();
 try{const value=await rpc.call(['functions','decompile','--address','0'],{stage:'read.missing',expectedFailure:true,validate:v=>assert.equal(v.reason,'function_not_found')});assert.equal(value.reason,'function_not_found');assert.equal(recorder.rows[0].ok,true);assert.match(recorder.rows[0].resultHash,/^[a-f0-9]{64}$/);}
 finally{await rpc.close();}
});
import {resultHash} from '../performance/equivalence.mjs';
import {verifyResults} from '../performance/verify-results.mjs';
import {coverage} from '../performance/coverage.mjs';
import {nativeProofs} from '../performance/finalize.mjs';
test('native proof reduction fails incomplete checks and strips private call transcripts',()=>{const missing=nativeProofs({});assert.equal(missing.passed,false);const valid={checks:Object.fromEntries(Object.keys(missing.proofs['candidate-bounded-proof'].checks).map(k=>[k,true])),cleanup:[],calls:['private-transcript']},reports={'candidate-bounded-proof':valid,'candidate-trace-bounded-proof':valid};assert.equal(nativeProofs(reports).passed,true);assert.ok(!JSON.stringify(nativeProofs(reports)).includes('private-transcript'));valid.checks.inputUnchanged=false;assert.equal(nativeProofs(reports).passed,false);});
test('coverage rejects an entirely omitted case, duplicate repetitions and incorrect fixture bytes',()=>{
 const inventory=coverage([],{warm:2,cold:1});assert.equal(inventory.passed,false);assert.ok(inventory.failures.some(r=>r.fixture==='large'&&r.stage==='read.undefined'));
 const input=inventory.groups.flatMap(g=>Array.from({length:g.expected},(_,i)=>({evidencePhase:g.phase,label:g.label,fixture:g.fixture,analysis:g.analysis,route:g.route,stage:g.stage,...g.kind==='warm'?{sample:i,coldTrial:0}:{coldTrial:i},ok:true,ms:1,resultHash:'a'.repeat(64)})));
 for(const r of input.filter(r=>/^(read|first)\.(memory|large-output)$/.test(r.stage))){const length=r.stage.endsWith('.memory')?16:r.fixture==='large'?65536:256,data=Array(length).fill(0);data.splice(0,4,1,2,3,4);r.resultHash=resultHash(r.stage,{length,data,hex:Buffer.from(data).toString('hex')});}
 assert.equal(coverage(input,{warm:2,cold:1}).passed,true);
 const dropped=input.filter(r=>!(r.evidencePhase==='candidate'&&r.fixture==='large'&&r.stage==='read.undefined'));assert.equal(coverage(dropped,{warm:2,cold:1}).passed,false);
 assert.equal(coverage([...input,input[0]],{warm:2,cold:1}).passed,false);
 const memory=input.find(r=>r.stage==='read.memory');memory.resultHash='b'.repeat(64);assert.ok(coverage(input,{warm:2,cold:1}).failures.some(r=>r.reason[0].startsWith('Memory bytes differ')));
});
test('equivalence excludes routing metadata but binds complete useful output',()=>{
 const first={session:'s_one',target:'t_one',code:'return 17;',signature:'int owned_add(int x)',comments:{plate:null,eol:null,pre:null,post:null,repeatable:null}};
 const second={...first,session:'s_two',target:'t_two'};assert.equal(resultHash('read.decompile',first),resultHash('read.decompile',second));assert.notEqual(resultHash('read.decompile',first),resultHash('read.decompile',{...second,code:'return 0;'}));
 assert.equal(verifyResults([]).passed,false);const base={fixture:'tiny',analysis:false,stage:'read.decompile',ok:true,resultHash:resultHash('read.decompile',first)};assert.equal(verifyResults([{...base,label:'before',route:'cli'},{...base,label:'after',route:'rpc'}]).passed,true);assert.equal(verifyResults([{...base,label:'before',route:'cli'},{...base,label:'after',route:'rpc',resultHash:'different'}]).passed,false);
 const coldMismatch=[{...base,label:'before',route:'cli'},{...base,label:'before',route:'cli',stage:'first.decompile',resultHash:'different'}];assert.equal(verifyResults(coldMismatch).passed,true);assert.equal(verifyResults(coldMismatch,{includeFirst:true}).passed,false);
});
