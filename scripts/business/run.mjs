import assert from 'node:assert/strict';
import {mkdtemp,readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {prepare} from './prepare.mjs';
import {PublicCli,exec,json,save} from './public-cli.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url)),directory=await mkdtemp('/private/tmp/insight-business-');console.log('Business acceptance diagnostics:',directory);
const sha=b=>createHash('sha256').update(b).digest('hex');
async function inputs(){const hashes={};async function walk(path){for(const entry of await readdir(join(root,path),{withFileTypes:true})){if(['obj','bin','node_modules'].includes(entry.name)||entry.name.endsWith('.feature.cs'))continue;const name=join(path,entry.name);if(entry.isDirectory())await walk(name);else if(entry.isFile())hashes[name]=sha(await readFile(join(root,name)));}}
 for(const path of ['scripts','skills/ghidra-coordinator/src','skills/ghidra-coordinator/dist','skills/ghidra-coordinator/tests','skills/ghidra-coordinator/references','skills/ghidra-coordinator/runtime','tests/acceptance','tests/automation'])await walk(path);
 for(const path of ['automation.json','global.json','package.json','package-lock.json','.gitmodules'])hashes[path]=sha(await readFile(join(root,path)));return hashes;
}
let m,failed,log='',exitCode=1;const extra=process.argv.slice(2);
try{
 m=await prepare(root,directory);const sourceHashes=await inputs(),baseRevision=(await exec('git',['rev-parse','HEAD'],{cwd:root})).stdout.trim();
 const child=spawn(process.execPath,[join(root,'scripts/run-automation.mjs'),'test','--suite','acceptance','--tag','business','--property','RestoreLockedMode=true','--timeout-seconds','86400',...extra],{cwd:root,env:{...process.env,INSIGHT_BUSINESS_MANIFEST:join(directory,'manifest.json')},stdio:['ignore','pipe','pipe']});
 for(const [stream,output] of [[child.stdout,process.stdout],[child.stderr,process.stderr]])stream.on('data',b=>{log+=b.toString();output.write(b);});
 const observed=new Set();let observing=false;
 const timer=setInterval(async()=>{if(observing)return;observing=true;try{const current=log.match(/Automation run: (.+)/)?.[1];if(!current)return;
  for(const name of await readdir(join(current,'scenarios'))){const folder=join(current,'scenarios',name);let selected;try{selected=await json(join(folder,'case.json'));}catch{continue;}
   if(!observed.has(selected.id)){observed.add(selected.id);console.log('Business scenario started:',selected.id);}
   try{const done=await json(join(folder,'result.json'));if(!observed.has(done.id+'-done')){observed.add(done.id+'-done');console.log('Business scenario passed:',done.id);}}catch{}
   try{const progress=await json(join(folder,'progress.json')),key=selected.id+'-'+progress.trials.length;if(!observed.has(key)){observed.add(key);console.log('Business timed trials completed:',selected.id,progress.trials.length);}}catch{}
  }
 }catch{}finally{observing=false;}},10000);
 try{exitCode=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>resolve(code??1));});}finally{clearInterval(timer);}
 await writeFile(join(directory,'automation.log'),log,{mode:0o600});assert.equal(exitCode,0,'Gherkin business acceptance failed; retained diagnostics '+directory);
 const automation=log.match(/Automation run: (.+)/)?.[1];assert.ok(automation);const reports=[];
 for(const name of await readdir(join(automation,'scenarios'))){const path=join(automation,'scenarios',name,'result.json');try{reports.push(await json(path));}catch(e){if(e.code!=='ENOENT')throw e;}}
 const full=extra.length===0;if(full)assert.deepEqual(reports.map(r=>r.id).sort(),Array.from({length:25},(_,i)=>'BS-'+String(i+1).padStart(2,'0')));
 if(full)assert.equal(reports.find(r=>r.id==='BS-21').trials[0].resultDigest,reports.find(r=>r.id==='BS-22').trials[0].resultDigest,'One- and three-worker baseline findings differ');
 assert.ok(reports.length);assert.ok(reports.every(r=>r.state==='passed'&&r.publicCliOnly&&r.cleanupComplete&&r.artifactSha256===m.artifactSha256));assert.deepEqual(await inputs(),sourceHashes,'Acceptance inputs changed during execution');
 for(const input of m.inputs)assert.equal(sha(await readFile(input.path)),input.sha256,'EXE changed during acceptance');
 await save(join(directory,'report.json'),{schema:1,state:'passed',scope:full?'All 25 business Gherkin scenarios':'Selected business Gherkin development run',baseRevision,sourceHashes,artifactSha256:m.artifactSha256,inputSha256:m.inputs.map(i=>i.sha256),corpus:m.inputs.map(({version,sha256,exports})=>({version,sha256,exports})),automationCommit:(await exec('git',['-C','tests/vendor/EyeAuras.Automation','rev-parse','HEAD'],{cwd:root})).stdout.trim(),protocol:await json(join(root,'tests/acceptance/fixtures/benchmark-protocol.json')),scenarios:reports.sort((a,b)=>a.id.localeCompare(b.id)),runtime:{...m.runtime,node:process.versions.node,dotnet:(await exec('dotnet',['--version'])).stdout.trim(),platform:process.platform,architecture:process.arch},cleanupComplete:false});
}catch(error){failed=error;console.error(error);process.exitCode=1;}
finally{
  if(m){try{const profiles=[...new Set((await readFile(join(directory,'profiles.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse))];for(const profile of profiles){assert.ok(profile===m.profile||profile.startsWith(m.profile+'-'));const cli=new PublicCli(m,join(directory,'cleanup',profile),profile);await cli.call(['ghidra','server','disconnect']);}
  if(!failed){const report=await json(join(directory,'report.json'));report.cleanupComplete=true;await save(join(directory,'report.json'),report);console.log('Business Gherkin acceptance passed:',directory);}
 }catch(cleanup){console.error('Owned suite cleanup failed:',cleanup);process.exitCode=1;}}
}
