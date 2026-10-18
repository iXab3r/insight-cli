import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {summarize,rows} from './compare.mjs';
// Host-calibrated distribution check; route phases are serial, not time-paired.
export function gate(before,after,{minimum=30,relative=.15,noiseMultiplier=3}={}){
 const failures=[];
 if(!Object.keys(before).length||!Object.keys(after).length)failures.push({reason:'empty evidence'});
 for(const [key,b] of Object.entries(before)){
  const suffix=key.substring(key.indexOf('/')),found=Object.entries(after).find(([name])=>name.endsWith(suffix));
  if(!found){failures.push({case:suffix,reason:'missing case'});continue;}const a=found[1];
  if(b.n<minimum||a.n<minimum||b.failures||a.failures||b.censored||a.censored){failures.push({case:suffix,reason:'insufficient or failed evidence'});continue;}
  const allowance=Math.max(b.p50*relative,noiseMultiplier*Math.max(a.mad,b.mad));
  if(a.p50>b.p50+allowance)failures.push({case:suffix,reason:'median regression',before:b.p50,after:a.p50,allowance});
  const tailAllowance=Math.max(b.p95*.30,noiseMultiplier*Math.max(a.mad,b.mad));
  if(a.p95>b.p95+tailAllowance)failures.push({case:suffix,reason:'tail regression',before:b.p95,after:a.p95,allowance:tailAllowance});
 }
 return {passed:failures.length===0,minimum,relative,noiseMultiplier,failures};
}
if(process.argv[1]===new URL(import.meta.url).pathname){const b=summarize((await rows(process.argv[2])).filter(x=>x.stage.startsWith('read.'))),a=summarize((await rows(process.argv[3])).filter(x=>x.stage.startsWith('read.'))),result=gate(b,a);console.log(JSON.stringify(result,null,2));assert.equal(result.passed,true);}
