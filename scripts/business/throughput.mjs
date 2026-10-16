import assert from 'node:assert/strict';
import {join} from 'node:path';
import {mkdir,readFile} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {setTimeout as delay} from 'node:timers/promises';
import {PublicCli,exec,json,save} from './public-cli.mjs';
import {bindings} from './cases.mjs';
const algorithms=['hash_fnv','hash_djb','hash_sdbm'];
const sha=value=>createHash('sha256').update(typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value)).digest('hex');
export function hash(name,text){let h=name==='hash_fnv'?2166136261:name==='hash_djb'?5381:0;for(const ch of text){const c=ch.charCodeAt(0);h=name==='hash_fnv'?Math.imul(h^c,16777619)>>>0:name==='hash_djb'?(Math.imul(h,33)+c)>>>0:(c+Math.imul(h,65599))>>>0;}return '0x'+h.toString(16);}
export function candidates(seed,part,batch,protocol){return Array.from({length:protocol.candidatesPerBatch},(_,i)=>`${seed}/${part}/${batch}/${i}/`.padEnd(protocol.candidateLength,String.fromCharCode(97+(i+batch)%26)));}
async function batch(cli,scope,name,words,protocol){const wanted=hash(name,words[7%words.length]);const response=await cli.scoped(scope,'emulation emulate-hash-batch',[
 '--hash-function-address',cli.m.inputs[0].exports[name],'--string-register','RCX','--result-register','EAX','--target-hash',wanted,
 '--candidates',JSON.stringify(words),'--timeout-seconds',String(protocol.timeoutSecondsPerBatch),'--max-steps',String(protocol.maxStepsPerCandidate)]);
 const v=response.value;assert.equal(v.complete,true);assert.equal(v.truncated,false);assert.equal(v.tested,words.length);assert.ok(v.outcomes.every(o=>o.completed&&o.stop_reason==='return'));
 const expected=words.filter(w=>hash(name,w)===wanted);assert.deepEqual(v.matches.map(x=>x.candidate),expected);assert.ok(v.matches.every(x=>x.hash===wanted));
 return {targetHash:wanted,matches:expected.map(sha),matchIndexes:expected.map(word=>words.indexOf(word)),tested:v.tested,steps:v.steps_executed};
}
function cpuSeconds(raw){return raw.trim().split(':').reduce((n,p)=>n*60+Number(p),0);}
async function cpu(pids){const result=await exec('ps',['-p',pids.join(','),'-o','pid=,time=']);const out={};for(const line of result.stdout.trim().split('\n')){const [pid,time]=line.trim().split(/\s+/);out[pid]=cpuSeconds(time);}assert.equal(Object.keys(out).length,pids.length);return out;}
export async function trial(m,directory,protocol,{workers=1,cold=false,seed='task',counts=protocol.batchesPerPart,profile=m.profile}={}){
 await mkdir(directory,{recursive:true,mode:0o700});const cli=new PublicCli(m,directory,profile);let origin,scopes=[],failed,stopped=false;const clock=performance.now(),phases={},parts=[],workEvents=[],cpuSamples=[];
 if(cold)await cli.setup();const preparationStarted=performance.now();
 try{
  const beginning=cold?performance.now():undefined;origin=await cli.open();scopes.push(origin);
  if(!cold){for(const name of algorithms)await cli.scoped(origin,'comments set',['--address',m.inputs[0].exports[name],'--kind','plate','--clear']);await cli.scoped(origin,'merge');await cli.close(origin);scopes=[];origin=await cli.open();scopes.push(origin);}
  for(let i=1;i<workers;i++)scopes.push(await cli.open());
  const native=await bindings(cli,origin.target);assert.equal(native.length,workers);assert.equal(new Set(native.map(b=>b.pid)).size,workers);
  // No measured candidate is used during warmup. Cold timing includes its actual setup work.
  if(!cold)for(const scope of scopes)for(const name of algorithms)await batch(cli,scope,name,['warmup-only'],protocol);
  phases.setupSeconds=(performance.now()-preparationStarted)/1000;const started=beginning??performance.now(),researchStarted=performance.now();
  const active=new Set();let samplingError;const before=await cpu(native.map(b=>b.pid));
  const sample=(async()=>{try{while(!stopped){if(active.size===3)cpuSamples.push({at:performance.now(),cpu:await cpu(native.map(b=>b.pid))});await delay(250);}}catch(e){samplingError=e;}})();
  const investigate=async(part,scope)=>{const name=algorithms[part],start=performance.now();active.add(part);const results=[];
   try{for(let i=0;i<counts[part];i++)results.push(await batch(cli,scope,name,candidates(seed,part,i,protocol),protocol));
    const finding={algorithm:name,address:m.inputs[0].exports[name],batches:results.length,tested:results.reduce((n,r)=>n+r.tested,0),resultDigest:sha(results),
     dictionary:{format:'business-hash-dictionary-v1',seed,part,candidatesPerBatch:protocol.candidatesPerBatch,candidateLength:protocol.candidateLength},
     resolutions:results.map((r,batch)=>({batch,targetHash:r.targetHash,candidateIds:r.matchIndexes.map(index=>`${seed}/${part}/${batch}/${index}`)}))};
    assert.ok(JSON.stringify(finding).length<=16000,'Resolved finding exceeds the public comment bound');
    await cli.comment(scope,m.inputs[0].exports[name],JSON.stringify(finding));parts[part]=finding;
   }finally{active.delete(part);workEvents.push({part,started:start,ended:performance.now()});}
  };
  try{if(workers===1)for(let i=0;i<3;i++)await investigate(i,origin);else {const finished=await Promise.allSettled(scopes.map((scope,i)=>investigate(i,scope)));const errors=finished.filter(r=>r.status==='rejected').map(r=>r.reason);if(errors.length)throw new AggregateError(errors,'Concurrent research failed');}}
  finally{stopped=true;await sample;}if(samplingError)throw samplingError;
  phases.researchSeconds=(performance.now()-researchStarted)/1000;const completion=performance.now();
  if(workers===3){assert.ok(cpuSamples.length>=2,'No common three-worker observation window');const first=cpuSamples[0].cpu,last=cpuSamples.at(-1).cpu;assert.ok(native.every(b=>last[b.pid]>first[b.pid]),'All three native processes must do CPU work during overlapping task execution');}
  // The lead consumes each producer's actual public-CLI finding, then publishes the
  // combined result once. Worker contexts and their saved private work remain intact.
  const collecting=performance.now();
  for(let part=0;part<parts.length;part++){
   const producer=workers===1?origin:scopes[part],finding=JSON.parse(await cli.readComment(producer,parts[part].address));
   assert.deepEqual(finding,parts[part]);
   if(producer.session!==origin.session)await cli.comment(origin,parts[part].address,JSON.stringify(finding));
  }
  phases.collectionSeconds=(performance.now()-collecting)/1000;const publishing=performance.now();
  assert.equal((await cli.scoped(origin,'merge')).state,'merged');phases.publicationSeconds=(performance.now()-publishing)/1000;
  const verifying=performance.now();
  const reader=await cli.fresh(origin.target);for(const part of parts)assert.deepEqual(JSON.parse(await cli.readComment(reader,part.address)),part);
  phases.verificationSeconds=(performance.now()-verifying)/1000;
  const elapsedSeconds=(performance.now()-started)/1000;phases.completionSeconds=(performance.now()-completion)/1000;
  const after=await cpu(native.map(b=>b.pid));const result={workers,cold,seed,counts,elapsedSeconds,phases,resultDigest:sha(parts),parts,
   native:{distinctWorkers:native.length,processIds:native.map(b=>b.pid),cpuBefore:before,cpuAfter:after,commonActiveSamples:cpuSamples.length,
    ...(cpuSamples.length?{commonActiveWindow:{first:cpuSamples[0],last:cpuSamples.at(-1)}}:{}),
    overlapSeconds:workers===3?(Math.min(...workEvents.map(x=>x.ended))-Math.max(...workEvents.map(x=>x.started)))/1000:0},workEvents};
  await save(join(directory,'trial.json'),result);return result;
 }catch(e){failed=e;await save(join(directory,'failure.json'),{state:'failed',message:e.message,elapsedSeconds:(performance.now()-clock)/1000});throw e;}
 finally{stopped=true;try{await cli.cleanup();if(cold)await cli.call(['ghidra','server','disconnect']);}catch(e){throw failed?new AggregateError([failed,e],'Trial and cleanup failed'):e;}}
}
export async function runThroughput(id,m,directory){
 const protocolPath=join(m.root,'tests/acceptance/fixtures/benchmark-protocol.json'),protocolBytes=await readFile(protocolPath),protocol=JSON.parse(protocolBytes);await save(join(directory,'frozen-protocol.json'),{sha256:sha(protocolBytes),protocol});
 const trials=[],checks={};let comparison;
 if(id==='BS-21'||id==='BS-22'){trials.push(await trial(m,join(directory,'trial'),protocol,{workers:id==='BS-21'?1:3,seed:'single-complete-task'}));checks.expectedFindingsPublished=true;if(id==='BS-22')checks.threeNativeWorkersActive=true;}
 else if(id==='BS-23'){
  for(let pair=0;pair<protocol.pairedRepetitions;pair++){
   const order=protocol.modeOrder.slice(pair*2,pair*2+2);assert.deepEqual([...order].sort(),[1,3]);const pairTrials=[];
   for(const workers of order){console.log('Prepared acceptance pair',pair+1,'workers',workers);pairTrials.push(await trial(m,join(directory,`pair-${pair+1}-${workers}`),protocol,{workers,seed:'paired-task-'+pair}));await save(join(directory,'progress.json'),{trials:[...trials,...pairTrials]});}
   const serial=pairTrials.find(t=>t.workers===1),parallel=pairTrials.find(t=>t.workers===3);assert.equal(serial.resultDigest,parallel.resultDigest);trials.push(...pairTrials);
   await save(join(directory,'comparison-progress.json'),{completedPairs:pair+1,serialSeconds:serial.elapsedSeconds,parallelSeconds:parallel.elapsedSeconds,speedup:serial.elapsedSeconds/parallel.elapsedSeconds});
   assert.ok(parallel.elapsedSeconds<serial.elapsedSeconds,'Prepared-base pair '+(pair+1)+' failed; retain all measurements');
  }
  const pairs=Array.from({length:protocol.pairedRepetitions},(_,i)=>{const s=trials.find(t=>t.seed==='paired-task-'+i&&t.workers===1),p=trials.find(t=>t.seed==='paired-task-'+i&&t.workers===3);return {serialSeconds:s.elapsedSeconds,parallelSeconds:p.elapsedSeconds,speedup:s.elapsedSeconds/p.elapsedSeconds,efficiency:s.elapsedSeconds/(3*p.elapsedSeconds)};});
  comparison={pairs,oneSidedSignProbability:1/2**pairs.length};await save(join(directory,'comparison.json'),comparison);assert.ok(pairs.every(p=>p.speedup>1),'Prepared-base acceleration gate failed; retain all paired measurements');checks.sixPairedImprovements=true;checks.equivalentResults=true;
 }else if(id==='BS-24'){
  for(const workers of [1,3])trials.push(await trial(m,join(directory,'cold-'+workers),protocol,{workers,cold:true,seed:'cold-task',profile:m.profile+'-cold-'+workers}));assert.equal(trials[0].resultDigest,trials[1].resultDigest);checks.coldResultsEquivalent=true;checks.coldTimesReportedWithoutSpeedupGate=true;
 }else if(id==='BS-25'){
  for(const workers of [1,3])trials.push(await trial(m,join(directory,'uneven-'+workers),protocol,{workers,seed:'uneven-task',counts:protocol.unevenBatchesPerPart}));assert.equal(trials[0].resultDigest,trials[1].resultDigest);checks.unevenResultsEquivalent=true;checks.actualScalingReported=true;
 }else throw Error('Unknown throughput scenario');
 if(id==='BS-24'||id==='BS-25')comparison={serialSeconds:trials[0].elapsedSeconds,parallelSeconds:trials[1].elapsedSeconds,speedup:trials[0].elapsedSeconds/trials[1].elapsedSeconds,efficiency:trials[0].elapsedSeconds/(3*trials[1].elapsedSeconds),speedupRequired:false};
 const result={schema:1,id,state:'passed',checks,artifactSha256:m.artifactSha256,inputSha256:m.inputs.map(i=>i.sha256),protocolSha256:sha(protocolBytes),trials,...(comparison?{comparison}:{}),publicCliOnly:true,cleanupComplete:true};await save(join(directory,'result.json'),result);return result;
}
