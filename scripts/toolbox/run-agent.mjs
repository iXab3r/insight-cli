// Opt-in real Codex trial. Exit zero means the model finished; it is never a semantic pass.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir,realpath} from 'node:fs/promises';
import {join,resolve,relative,isAbsolute,sep} from 'node:path';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const execute=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
assert.equal(process.env.INSIGHT_RUN_AGENT_EVAL,'1','Real model inference requires explicit opt-in');
const manifest=JSON.parse(await readFile(resolve(process.argv[2]),'utf8'));
const {packageRoot,project,preload,outputDirectory,artifact,inputs,prompt,model}=manifest;
assert.ok([packageRoot,project,preload,outputDirectory,artifact].every(p=>typeof p==='string'&&isAbsolute(p)));
assert.ok(Array.isArray(inputs)&&inputs.length&&typeof prompt==='string'&&prompt.trim()&&typeof model==='string');
const cli=join(packageRoot,'dist/src/bin.js'),pkg=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));
assert.equal(pkg.name,'@eyeauras/insight-cli');
const packageBuild=JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8')).artifact;
const skillHash=createHash('sha256');
async function skills(path,base=path){for(const entry of (await readdir(path,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
 assert.ok(!entry.isSymbolicLink(),'Use the physical installed bundle');const at=join(path,entry.name);
 if(entry.isDirectory())await skills(at,base);else{const bytes=await readFile(at);skillHash.update(JSON.stringify([relative(base,at),bytes.length])).update(bytes);}
}}
await skills(join(packageRoot,'skill-bundle'));
const projectRoot=await realpath(project),inputIdentities=[];
for(const name of inputs){assert.ok(typeof name==='string'&&!isAbsolute(name));const path=await realpath(join(projectRoot,name));const local=relative(projectRoot,path);assert.ok(local&&!isAbsolute(local)&&local!=='..'&&!local.startsWith('..'+sep));inputIdentities.push({path:name,sha256:sha(await readFile(path))});}
await mkdir(outputDirectory,{recursive:true,mode:0o700});assert.deepEqual(await readdir(outputDirectory),[],'Use a new result directory');
// A login shell can replace PATH and drop NODE_OPTIONS, accidentally selecting a user's
// unrelated global installation/profile. Bind both the executable and its private preload
// in a per-trial launcher; this is test isolation, never a second production CLI.
assert.notEqual(process.platform,'win32','The independent Codex trial launcher currently supports POSIX hosts only. Windows native CLI proofs have a separate gate.');
const launcherDirectory=join(outputDirectory,'bin'),launcher=join(launcherDirectory,'insight-cli'),invocations=join(outputDirectory,'candidate-invocations.jsonl');
await mkdir(launcherDirectory,{mode:0o700});
const launcherSource=join(launcherDirectory,'launch.mjs');
await writeFile(launcherSource,`import{appendFileSync}from'node:fs';import{spawn}from'node:child_process';appendFileSync(${JSON.stringify(invocations)},JSON.stringify({at:new Date().toISOString(),argv:process.argv.slice(2)})+'\\n',{mode:0o600});const child=spawn(${JSON.stringify(process.execPath)},['--import',${JSON.stringify(pathToFileURL(preload).href)},${JSON.stringify(cli)},...process.argv.slice(2)],{stdio:'inherit',env:{...process.env,NODE_OPTIONS:''}});child.on('error',()=>{process.exitCode=1;});child.on('exit',(code,signal)=>{if(signal)process.kill(process.pid,signal);else process.exitCode=code??1;});\n`,{mode:0o600});
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
await writeFile(launcher,'#!/bin/sh\nexec '+quote(process.execPath)+' '+quote(launcherSource)+' "$@"\n',{mode:0o700});
const environment={...process.env,NODE_OPTIONS:'--import '+pathToFileURL(preload).href,PATH:launcherDirectory+':'+(manifest.path??process.env.PATH??'')};
const codex=manifest.codexExecutable??(await execute(process.platform==='win32'?'where':'which',['codex'])).stdout.trim().split(/\r?\n/)[0];
const toml=v=>typeof v==='object'?'{'+Object.entries(v).map(([k,v])=>JSON.stringify(k)+'='+toml(v)).join(',')+'}':JSON.stringify(v);
const config={allow_login_shell:false,'shell_environment_policy.set':{NODE_OPTIONS:environment.NODE_OPTIONS,PATH:environment.PATH},model_reasoning_effort:manifest.reasoningEffort??'low',developer_instructions:'This is a disposable acceptance environment. The selected installed toolbox executable is '+launcher+'. Use that exact executable for insight-cli commands, including retries with normal host permission escalation. Other global insight-cli installations and profiles belong to the user and are outside this trial. Preserve the selected runtime storage/profile. This instruction selects the installed executable only; choose the analytical tools and method yourself.'};
const args=['exec','--ignore-user-config','--approve-for-me','--ephemeral','--skip-git-repo-check','--json','--model',model,'-C',project,'-o',join(outputDirectory,'final.md'),...Object.entries(config).flatMap(([k,v])=>['-c',k+'='+toml(v)]),prompt];
const identity={schema:1,packageVersion:pkg.version,packageBuild,artifactSha256:sha(await readFile(artifact)),skillBundleSha256:skillHash.digest('hex'),inputs:inputIdentities,promptSha256:sha(prompt),model,reasoningEffort:config.model_reasoning_effort,executionBinding:{schema:2,allowLoginShell:false,explicitCandidateLauncher:true,explicitPrivatePreload:true}};
await writeFile(join(outputDirectory,'trial.json'),JSON.stringify({...identity,prompt},null,2)+'\n',{mode:0o600});
// Let the public CLI select/start its own owner. An operator's different Node can be incompatible.
const timeoutSeconds=manifest.timeoutSeconds??900;assert.ok(Number.isInteger(timeoutSeconds)&&timeoutSeconds>=1&&timeoutSeconds<=900);
let child,code,error,ownerStopped=false,stdout='',stderr='',overflow=false,timedOut=false,force;const started=Date.now();
const stop=()=>{child?.kill('SIGTERM');force??=setTimeout(()=>child?.kill('SIGKILL'),1500);};
try{
 child=spawn(codex,args,{cwd:project,env:environment,stdio:['ignore','pipe','pipe']});
 const capture=(kind,b)=>{if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)+b.length>32*1024**2){overflow=true;stop();return;}if(kind==='stdout')stdout+=b;else stderr+=b;};
 child.stdout.on('data',b=>capture('stdout',b));child.stderr.on('data',b=>capture('stderr',b));
 const timer=setTimeout(()=>{timedOut=true;stop();},timeoutSeconds*1000);
 try{code=await new Promise((ok,bad)=>{child.once('error',bad);child.once('exit',c=>ok(c));});}finally{clearTimeout(timer);clearTimeout(force);}
}catch(e){error=e.code??e.name;}
finally{
 await writeFile(join(outputDirectory,'events.jsonl'),stdout,{mode:0o600});await writeFile(join(outputDirectory,'stderr.log'),stderr,{mode:0o600});
 try{const reply=await execute(process.execPath,[cli,'ipc-server','stop','--json'],{env:environment,cwd:project,timeout:30000,maxBuffer:65536});ownerStopped=JSON.parse(reply.stdout).running===false;}catch{ownerStopped=false;}
 let inputsUnchanged=true;for(const input of inputIdentities)if(sha(await readFile(join(project,input.path)))!==input.sha256)inputsUnchanged=false;
 const artifactUnchanged=sha(await readFile(artifact))===identity.artifactSha256;
 const candidateInvocations=await readFile(invocations,'utf8').then(s=>s.trim().split('\n').filter(Boolean).length).catch(e=>{if(e.code==='ENOENT')return 0;throw e;});
 const result={...identity,state:code===0&&!overflow&&!timedOut&&!error&&ownerStopped&&inputsUnchanged&&artifactUnchanged?'needs_review':'failed',exitCode:code??null,error,outputLimitExceeded:overflow,timedOut,elapsedMs:Date.now()-started,operatorNode:process.version,inputsUnchanged,artifactUnchanged,ownerStopped,candidateInvocations,semanticReviewRequired:true,toolSpecificCleanupReviewRequired:true};
 await writeFile(join(outputDirectory,'result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({state:result.state,ownerStopped,outputDirectory}));if(result.state==='failed')process.exitCode=1;
}
