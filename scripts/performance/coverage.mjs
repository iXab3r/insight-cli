import assert from 'node:assert/strict';
import {resultHash} from './equivalence.mjs';
// This inventory is deliberately independent of the collector's observed cases.
const reads=['metadata','decompile','hash-decompile','bulk','memory','large-output','paging','strings','xrefs','missing','undefined'];
const persistence=['new-context','peer-context','edit','durable-replay','read-script','merge','refresh','refresh-readback','peer-close','close','reopen','reopen-readback','final-close'];
const stockPersistence=['read-script','edit','save','close','reopen','readback'];
const concurrency=['long-operation','queued-configuration','independent-read','diagnostic','first-read','second-read'];
export function coverage(records,{warm=30,cold=5}={}){
 for(const n of [warm,cold])assert.ok(Number.isSafeInteger(n)&&n>0);
 const failures=[],groups=[];
 function check(phase,label,fixture,analysis,route,stage,kind,count){
  const matching=records.filter(r=>r.evidencePhase===phase&&r.label===label&&r.fixture===fixture&&r.analysis===analysis&&r.route===route&&r.stage===stage&&!r.warmup&&(kind==='cold'?r.sample===undefined:r.sample!==undefined&&(r.coldTrial===undefined||r.coldTrial===0)));
  const indexes=matching.map(r=>kind==='cold'?r.coldTrial:r.sample),reason=[];
  if(matching.length!==count||new Set(indexes).size!==count||indexes.some(n=>!Number.isSafeInteger(n)||n<0||n>=count))reason.push('missing, duplicate or unexpected repetition');
  if(matching.some(r=>!r.ok||r.censored||!Number.isFinite(r.ms)))reason.push('failed or censored request');
  if(/^(read|first)\./.test(stage)&&matching.some(r=>!/^[a-f0-9]{64}$/.test(r.resultHash??'')))reason.push('missing useful-output digest');
  const group={phase,label,fixture,analysis,route,stage,kind,expected:count,observed:matching.length};groups.push(group);
  if(reason.length)failures.push({...group,reason});
 }
 for(const fixture of ['tiny','large'])for(const analysis of [false,true]){
  for(const label of ['baseline','candidate']){
   for(const route of ['cli','rpc'])for(const name of reads){check(label,label,fixture,analysis,route,'read.'+name,'warm',warm);check(label,label,fixture,analysis,route,'first.'+name,'cold',cold);}
   for(const stage of ['cold.open','warm.new-input'])check(label,label,fixture,analysis,'cli',stage,'cold',cold);
   check(label,label,fixture,analysis,'rpc','cold.rpc-process','cold',cold);
   for(const stage of ['cold.rpc-process-and-open','cold.open'])check(label+'-cold-rpc',label,fixture,analysis,'rpc',stage,'cold',cold);
   for(const name of persistence)check(label+'-persistence',label,fixture,analysis,'cli','persistence.'+name,'warm',warm);
  }
  for(const phase of ['stock-parity','stock-version-factor']){
   for(const name of reads.filter(n=>n!=='undefined')){check(phase,phase,fixture,analysis,'stock','read.'+name,'warm',warm);check(phase,phase,fixture,analysis,'stock','first.'+name,'cold',cold);}
   for(const stage of ['cold.server','cold.import'])check(phase,phase,fixture,analysis,'stock',stage,'cold',cold);
   for(const name of stockPersistence)check(phase,phase,fixture,analysis,'stock','persistence.'+name,'warm',warm);
  }
 }
 for(const label of ['baseline','candidate'])for(const name of concurrency)check(label+'-concurrency',label,'tiny',false,'cli','concurrency.'+name,'warm',warm);
 let checkedMemoryOutputs=0;
 for(const r of records.filter(r=>/^(read|first)\.(memory|large-output)$/.test(r.stage)&&!r.warmup&&!r.label.includes('trace'))){const length=r.stage.endsWith('.memory')?16:r.fixture==='large'?65536:256,data=Array(length).fill(0);data.splice(0,4,1,2,3,4);const expected=resultHash(r.stage,{length,data,hex:Buffer.from(data).toString('hex')});checkedMemoryOutputs++;if(r.resultHash!==expected)failures.push({phase:r.evidencePhase,fixture:r.fixture,analysis:r.analysis,route:r.route,stage:r.stage,sample:r.sample,reason:['Memory bytes differ from the independently constructed fixture data array']});}
 return {schema:1,passed:failures.length===0,warm,cold,expectedGroups:groups.length,groups,checkedMemoryOutputs,failures,notApplicable:[{route:'stock',stage:'read.undefined',reason:'The stock public MCP tool catalog has no matching read-only bounded decode operation.'}]};
}
