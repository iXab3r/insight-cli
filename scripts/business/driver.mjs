import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {json,save} from './public-cli.mjs';
import {runCase} from './cases.mjs';
const options={};for(let i=2;i<process.argv.length;i+=2)options[process.argv[i].slice(2)]=process.argv[i+1];
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.ok(!process.env.CI);assert.match(options.case,/^BS-(?:0[1-9]|1\d|2[0-5])$/);
const manifest=await json(options.manifest),sha=b=>createHash('sha256').update(b).digest('hex');
assert.equal(sha(await readFile(manifest.artifact)),manifest.artifactSha256);
for(const input of manifest.inputs)assert.equal(sha(await readFile(input.path)),input.sha256);
await mkdir(options.output,{recursive:true,mode:0o700});
await save(options.output+'/case.json',{id:options.case,state:'running'});
const report=Number(options.case.slice(3))<21?await runCase(options.case,manifest,options.output):
 await (await import('./throughput.mjs')).runThroughput(options.case,manifest,options.output);
console.log(JSON.stringify({id:report.id,state:report.state,checks:report.checks}));
