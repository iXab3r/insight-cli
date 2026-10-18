import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile,spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fixtures} from './fixtures.mjs';
import {finalize} from './finalize.mjs';
import {scriptEffects} from './script-effects.mjs';
import {requestTraces} from './request-traces.mjs';
import {report} from './report.mjs';
import {identity} from './identity.mjs';
const exec=promisify(execFile),{values:o}=parseArgs({options:{root:{type:'string'},baseline:{type:'string'},candidate:{type:'string'},java:{type:'string'},ghidra:{type:'string'},python:{type:'string'},bridge:{type:'string'},'stock-jar':{type:'string'},'parity-jar':{type:'string'},smoke:{type:'boolean'},'ack-disposable':{type:'boolean'}}});
assert.equal(o['ack-disposable'],true);for(const k of ['root','baseline','candidate','java','ghidra','python','bridge','stock-jar','parity-jar'])assert.ok(o[k],k);
assert.equal(process.platform,'darwin','Native public AppData observation currently targets macOS');assert.ok(!process.env.CI||process.env.INSIGHT_NATIVE_PERFORMANCE==='owned');
const root=resolve(o.root);await mkdir(root,{recursive:false});
await writeFile(join(root,'identity.json'),JSON.stringify(await identity(o),null,2)+'\n');
const initial=JSON.parse((await exec(process.execPath,[resolve(o.baseline),'ipc-server','status','--json'])).stdout);assert.equal(initial.running,false,'An existing public IPC owner is active. Wait for its ordinary idle exit; this runner never stops a shared owner.');
const f=await fixtures(join(root,'fixtures')),manifest=join(root,'fixtures/manifest.json'),warm=o.smoke?'3':'30',cold=o.smoke?'1':'5',warmups=o.smoke?'1':'3';
const common=['--java',resolve(o.java),'--ghidra',resolve(o.ghidra),'--warm',warm,'--cold',cold,'--warmups',warmups,'--analysis','both','--ack-disposable'];
const phases=[];
async function run(label,args,env={}){const started=process.hrtime.bigint();let code;try{await new Promise((ok,bad)=>{const child=spawn(process.execPath,['scripts/performance/run.mjs',...common,'--root',join(root,label),...args],{cwd:process.cwd(),env:{...process.env,...env},stdio:'inherit'});child.once('error',bad);child.once('exit',c=>{code=c;c===0?ok():bad(Error('Native phase failed: '+label));});});}finally{phases.push({label,ms:Number(process.hrtime.bigint()-started)/1e6,code});await writeFile(join(root,'phases.json'),JSON.stringify(phases,null,2)+'\n');}}
await run('baseline',['--cli',resolve(o.baseline),'--label','baseline','--fixtures',manifest]);
await run('baseline-cold-rpc',['--phase','cold-rpc','--cli',resolve(o.baseline),'--label','baseline','--manifest',join(root,'baseline/manifest.json')]);
await run('baseline-persistence',['--phase','persistence','--cli',resolve(o.baseline),'--label','baseline','--manifest',join(root,'baseline/manifest.json')]);
await run('baseline-concurrency',['--phase','concurrency','--cli',resolve(o.baseline),'--label','baseline','--manifest',join(root,'baseline/manifest.json')]);
const stockArgs=['--route','stock','--python',resolve(o.python),'--bridge',resolve(o.bridge),'--fixture-root',root,'--manifest',join(root,'baseline/manifest.json')];
await run('stock-parity',[...stockArgs,'--jar',resolve(o['parity-jar']),'--label','stock-parity']);
await run('candidate',['--cli',resolve(o.candidate),'--label','candidate','--fixtures',manifest]);
await run('candidate-cold-rpc',['--phase','cold-rpc','--cli',resolve(o.candidate),'--label','candidate','--manifest',join(root,'candidate/manifest.json')]);
await run('candidate-persistence',['--phase','persistence','--cli',resolve(o.candidate),'--label','candidate','--manifest',join(root,'candidate/manifest.json')]);
await run('candidate-concurrency',['--phase','concurrency','--cli',resolve(o.candidate),'--label','candidate','--manifest',join(root,'candidate/manifest.json')]);
async function proof(label,env={}){const started=process.hrtime.bigint();let code;
 try{await new Promise((ok,bad)=>{const child=spawn(process.execPath,['scripts/proof-bounded-functions.mjs','--cli',resolve(o.candidate),'--java',resolve(o.java),'--ghidra-home',resolve(o.ghidra),'--root',join(root,label),'--ack-disposable'],{cwd:process.cwd(),env:{...process.env,...env},stdio:'inherit'});child.once('error',bad);child.once('exit',value=>{code=value;value===0?ok():bad(Error('Final installed native bounded-function proof failed: '+label));});});}
 finally{phases.push({label,ms:Number(process.hrtime.bigint()-started)/1e6,code});await writeFile(join(root,'phases.json'),JSON.stringify(phases,null,2)+'\n');}}
await proof('candidate-bounded-proof');
// A separate bridge-version factor; this also allows the ordinary owner to exit idle before opt-in tracing.
await run('stock-version-factor',[...stockArgs,'--jar',resolve(o['stock-jar']),'--label','stock-version-factor']);
const trace=join(root,'trace');await mkdir(trace,{mode:0o700});
await run('candidate-trace',['--cli',resolve(o.candidate),'--label','candidate-trace','--fixtures',manifest,'--warm','3','--cold','1','--warmups','1'],{CLI_FACTORY_TRACE_DIRECTORY:trace});
await run('candidate-trace-concurrency',['--phase','concurrency','--cli',resolve(o.candidate),'--label','candidate-trace','--manifest',join(root,'candidate-trace/manifest.json'),'--warm','3','--cold','1','--warmups','1'],{CLI_FACTORY_TRACE_DIRECTORY:trace});
await proof('candidate-trace-bounded-proof',{CLI_FACTORY_TRACE_DIRECTORY:trace});
const effects=await scriptEffects(root,Number(cold));await requestTraces(root);
const result=await finalize(root,Number(warm),Number(cold));await report(root);assert.equal(result.passed&&effects.passed,true,'Native coverage, useful-output, script-effect or regression check failed; retain every raw sample.');
