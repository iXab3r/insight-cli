import assert from 'node:assert/strict';
import {parseArgs} from 'node:util';
import {resolve,dirname} from 'node:path';
import {pathToFileURL} from 'node:url';
import {performance} from 'node:perf_hooks';
import {mkdir,writeFile} from 'node:fs/promises';
import {distribution} from './compare.mjs';
const {values:o}=parseArgs({options:{baseline:{type:'string'},candidate:{type:'string'},entry:{type:'string'},output:{type:'string'},samples:{type:'string',default:'3'}}});
for(const k of ['baseline','candidate','entry','output'])assert.ok(o[k],k);
const n=Number(o.samples);assert.ok(Number.isSafeInteger(n)&&n>=3);
const before=(await import(pathToFileURL(resolve(o.baseline)))).readPackageBuildManifest,after=(await import(pathToFileURL(resolve(o.candidate)))).readPackageBuildManifest,rows=[];
for(let i=-1;i<n;i++)for(const [label,fn]of i%2?[['after',after],['before',before]]:[['before',before],['after',after]]){const start=performance.now(),digest=await fn(resolve(o.entry));rows.push({label,sample:i,warmup:i<0,ms:performance.now()-start,digest});}
assert.equal(new Set(rows.map(r=>r.digest)).size,1,'Both algorithms must verify identical deployed bytes');
const summary=Object.fromEntries(['before','after'].map(label=>[label,distribution(rows.filter(r=>r.label===label&&!r.warmup).map(r=>r.ms))]));
// PR smoke catches order-of-magnitude mistakes; native acceptance uses calibrated distributions.
const passed=summary.after.p50<=Math.max(summary.before.p50*2,summary.before.p50+50);
await mkdir(dirname(resolve(o.output)),{recursive:true});await writeFile(o.output,JSON.stringify({schema:1,passed,minimum:n,tolerance:'max(2x baseline median, baseline median + 50ms)',summary,rows},null,2)+'\n');assert.equal(passed,true,'Artifact verification smoke regressed');
