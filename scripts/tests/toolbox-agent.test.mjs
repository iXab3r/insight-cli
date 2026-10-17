import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {fileURLToPath} from 'node:url';
const execute=promisify(execFile),runner=fileURLToPath(new URL('../toolbox/run-agent.mjs',import.meta.url));
test('real model evaluator requires separate explicit model-cost opt-in',async()=>{
 await assert.rejects(execute(process.execPath,[runner,'not-read.json'],{env:{...process.env,INSIGHT_NATIVE_DISPOSABLE:'1',INSIGHT_RUN_AGENT_EVAL:''}}),/explicit opt-in/);
});
test('synthetic evaluator transport outcomes never become semantic acceptance',async t=>{
 if(process.platform==='win32'){t.skip('Synthetic executable fixture is POSIX; real host acceptance remains native.');return;}
 for(const [name,program,expected]of [
  ['model-failed','process.exitCode=9','failed'],
  ['model-finished','console.log("synthetic completed event")','needs_review'],
  ['input-changed','require("node:fs").writeFileSync("input.bin","changed")','failed'],
  ['deadline','process.on("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000)','failed'],
 ]){
  const root=await mkdtemp(join(tmpdir(),'agent-protocol-'));t.after(()=>rm(root,{recursive:true,force:true}));const packageRoot=join(root,'package with spaces'),project=join(root,'project with spaces');
  await mkdir(join(packageRoot,'dist/src'),{recursive:true});await mkdir(join(packageRoot,'skill-bundle'));await mkdir(project);
  await writeFile(join(packageRoot,'package.json'),JSON.stringify({name:'@eyeauras/insight-cli',version:'synthetic'}));await writeFile(join(packageRoot,'.cli-package-build.json'),JSON.stringify({artifact:'synthetic'}));
  await writeFile(join(packageRoot,'skill-bundle/SKILL.md'),'Synthetic protocol fixture, no actual skills or research.');
  await writeFile(join(packageRoot,'dist/src/bin.js'),'console.log(JSON.stringify({running:false}));');
  const artifact=join(root,'artifact.tgz'),preload=join(root,'preload with spaces.mjs'),codexExecutable=join(root,'synthetic-codex');
  await writeFile(artifact,'synthetic artifact');await writeFile(preload,'// No storage changes or authentication');await writeFile(join(project,'input.bin'),'owned input');
  await writeFile(codexExecutable,'#!'+process.execPath+'\n'+program+'\n',{mode:0o755});
  const manifest={packageRoot,project,preload,artifact,codexExecutable,outputDirectory:join(root,'result'),inputs:['input.bin'],prompt:'Synthetic fixture. No model request is made.',model:'synthetic-do-not-infer',timeoutSeconds:name==='deadline'?1:30};
  const path=join(root,'manifest.json');await writeFile(path,JSON.stringify(manifest));let failure;
  try{await execute(process.execPath,[runner,path],{env:{...process.env,INSIGHT_NATIVE_DISPOSABLE:'1',INSIGHT_RUN_AGENT_EVAL:'1'},timeout:(manifest.timeoutSeconds+35)*1000});}catch(error){failure=error;}
  const result=JSON.parse(await readFile(join(root,'result/result.json'),'utf8'));assert.equal(result.state,expected,name);assert.equal(result.semanticReviewRequired,true);assert.equal(result.toolSpecificCleanupReviewRequired,true);assert.ok(result.promptSha256&&result.artifactSha256&&result.skillBundleSha256);
  if(expected==='failed')assert.ok(failure,name);else assert.equal(failure,undefined);
  if(name==='input-changed')assert.equal(result.inputsUnchanged,false);if(name==='deadline')assert.equal(result.timedOut,true);
 }
});
