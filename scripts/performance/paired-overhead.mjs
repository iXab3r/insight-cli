import {writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {distribution} from './compare.mjs';
import {phasedRows} from './finalize.mjs';
export function pairedOverhead(records,minimum=30){
 assert.ok(Number.isSafeInteger(minimum)&&minimum>0);
 const groups=new Map(),failures=[];
 for(const r of records.filter(r=>['baseline','candidate'].includes(r.evidencePhase)&&r.label===r.evidencePhase&&r.stage.startsWith('read.')&&Number.isSafeInteger(r.sample)&&r.sample>=0&&!r.warmup)){
  const key=[r.label,r.fixture,r.analysis?'analysis':'no-analysis',r.stage].join('/'),group=groups.get(key)??new Map(),pair=group.get(r.sample)??{};if(pair[r.route])failures.push({case:key,sample:r.sample,reason:'duplicate route'});pair[r.route]=r;group.set(r.sample,pair);groups.set(key,group);
 }
 const output={};for(const [key,values]of groups){const pairs=[];for(const [sample,p]of values){if(!p.cli?.ok||!p.rpc?.ok||p.cli.censored||p.rpc.censored){failures.push({case:key,sample,reason:'missing, failed or censored pair'});continue;}pairs.push({sample,cliStartNs:p.cli.startNs,rpcStartNs:p.rpc.startNs,cliMs:p.cli.ms,rpcMs:p.rpc.ms,deltaMs:p.cli.ms-p.rpc.ms});}if(pairs.length<minimum)failures.push({case:key,reason:'insufficient pairs',observed:pairs.length,minimum});output[key]={n:pairs.length,...pairs.length?{cliMinusRpcMs:distribution(pairs.map(p=>p.deltaMs))}:{},pairs};}
 if(!groups.size)failures.push({reason:'empty evidence'});return {schema:1,passed:failures.length===0,minimum,interpretation:'CLI minus persistent RPC for adjacent alternating requests of the same case/round and matching prepared private state. Negative values are retained. This is a descriptive route difference under load. Whole package versions and stock phases are serial and are not time-paired.',groups:output,failures};
}
export async function writePairedOverhead(root,minimum=30){const result=pairedOverhead(await phasedRows(root),minimum);await writeFile(join(root,'paired-overhead.json'),JSON.stringify(result,null,2)+'\n');return result;}
if(process.argv[1]===new URL(import.meta.url).pathname){const r=await writePairedOverhead(process.argv[2],Number(process.argv[3]??30));console.log(JSON.stringify({passed:r.passed,groups:Object.keys(r.groups).length}));if(!r.passed)process.exitCode=1;}
