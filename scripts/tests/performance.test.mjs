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
test('performance gate rejects missing/failed samples and tolerates only declared variability',()=>{
 const b={'before/tiny/no-analysis/cli/read.metadata':{n:30,p50:100,p95:120,mad:2,failures:0,censored:0}},a={'after/tiny/no-analysis/cli/read.metadata':{n:30,p50:110,p95:130,mad:2,failures:0,censored:0}};
 assert.equal(gate(b,a).passed,true);a['after/tiny/no-analysis/cli/read.metadata'].p50=130;assert.equal(gate(b,a).passed,false);assert.equal(gate(b,{}).passed,false);assert.equal(gate({},{}).passed,false);a['after/tiny/no-analysis/cli/read.metadata'].n=3;assert.equal(gate(b,a).passed,false);
});
import {union} from '../performance/trace-report.mjs';
test('timing coverage subtracts interval union, including nested/parallel overlap',()=>{assert.equal(union([[0n,10n],[2n,4n],[8n,12n],[20n,25n]]),17);});
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PublicCli,Recorder} from '../performance/public.mjs';
test('public benchmark adapter retains expected missing-function replies as checked evidence',async t=>{
 const root=await mkdtemp(join(tmpdir(),'perf-adapter-'));t.after(()=>rm(root,{recursive:true,force:true}));const bin=join(root,'owned.mjs');
 await writeFile(bin,`import{createInterface}from'node:readline';const input=createInterface({input:process.stdin});input.on('line',line=>{const r=JSON.parse(line);process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:r.id,error:{code:-32000,message:'Owned absent function',data:{code:'coordinator.partial',result:{reason:'function_not_found'}}}})+'\\n');});`);
 const recorder=new Recorder(root,{label:'synthetic'}),cli=new PublicCli(bin,'owned',recorder);cli.scope={session:'s_owned',target:'t_owned'};const rpc=await cli.rpc();
 try{const value=await rpc.call(['functions','decompile','--address','0'],{stage:'read.missing',expectedFailure:true,validate:v=>assert.equal(v.reason,'function_not_found')});assert.equal(value.reason,'function_not_found');assert.equal(recorder.rows[0].ok,true);assert.match(recorder.rows[0].resultHash,/^[a-f0-9]{64}$/);}
 finally{await rpc.close();}
});
import {resultHash} from '../performance/equivalence.mjs';
import {verifyResults} from '../performance/verify-results.mjs';
test('equivalence excludes routing metadata but binds complete useful output',()=>{
 const first={session:'s_one',target:'t_one',code:'return 17;',signature:'int owned_add(int x)',comments:{plate:null,eol:null,pre:null,post:null,repeatable:null}};
 const second={...first,session:'s_two',target:'t_two'};assert.equal(resultHash('read.decompile',first),resultHash('read.decompile',second));assert.notEqual(resultHash('read.decompile',first),resultHash('read.decompile',{...second,code:'return 0;'}));
 assert.equal(verifyResults([]).passed,false);const base={fixture:'tiny',analysis:false,stage:'read.decompile',ok:true,resultHash:resultHash('read.decompile',first)};assert.equal(verifyResults([{...base,label:'before',route:'cli'},{...base,label:'after',route:'rpc'}]).passed,true);assert.equal(verifyResults([{...base,label:'before',route:'cli'},{...base,label:'after',route:'rpc',resultHash:'different'}]).passed,false);
});
