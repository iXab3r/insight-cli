import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {distribution} from './compare.mjs';
const exec=promisify(execFile),{values:o}=parseArgs({options:{module:{type:'string'},root:{type:'string'},samples:{type:'string',default:'30'}}});assert.ok(o.module&&o.root);
await mkdir(o.root,{recursive:false});const sink=resolve(o.root,'trace');await mkdir(sink,{mode:0o700});
const code=`import{timingRequest,timingSpan}from ${JSON.stringify(pathToFileURL(resolve(o.module)).href)};const start=process.hrtime.bigint();let count=0;for(let i=0;i<100;i++)await timingRequest(()=>timingSpan('component.noop',()=>{count++;}));console.log(JSON.stringify({count,ms:Number(process.hrtime.bigint()-start)/1e6}));`;
const rows=[];for(let sample=-3;sample<Number(o.samples);sample++)for(const label of sample%2?['on','off']:['off','on']){const env={...process.env};delete env.CLI_FACTORY_TRACE_DIRECTORY;if(label==='on')env.CLI_FACTORY_TRACE_DIRECTORY=sink;const value=JSON.parse((await exec(process.execPath,['--input-type=module','-e',code],{env})).stdout);assert.equal(value.count,100);rows.push({label,sample,warmup:sample<0,spans:200,...value});}
const summary=Object.fromEntries(['off','on'].map(label=>[label,distribution(rows.filter(r=>r.label===label&&!r.warmup).map(r=>r.ms))]));
await writeFile(join(o.root,'cost.json'),JSON.stringify({schema:1,unit:'ms per 100 requests / 200 spans, excludes process startup',summary,rows},null,2)+'\n');console.log(JSON.stringify(summary));
