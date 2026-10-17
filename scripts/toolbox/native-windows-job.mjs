// Disposable Windows-only native acceptance. No user target is attached or terminated.
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,readdir,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';import {pathToFileURL} from 'node:url';import {spawn} from 'node:child_process';import {setTimeout as delay} from 'node:timers/promises';
assert.equal(process.platform,'win32');assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const module=pathToFileURL(resolve('skills/ghidra-coordinator/dist/src/tool-runtime/run.js')).href;
const root=await mkdtemp(join(tmpdir(),'insight-job-native-'));
const fixture=join(root,'owned fixture-Ω.cjs');
await writeFile(fixture,`const {spawn}=require('node:child_process'),fs=require('node:fs');if(process.argv[2]==='grandchild'){setInterval(()=>{},1000);}else{const g=spawn(process.execPath,[__filename,'grandchild'],{stdio:'ignore'});fs.writeFileSync(process.argv[2],JSON.stringify({pid:process.pid,grandchild:g.pid}));console.log(JSON.stringify(process.argv.slice(3)));if(process.argv[3]==='complete'){g.kill();setTimeout(()=>process.exit(7),100);}else if(process.argv[3]==='flood'){setTimeout(()=>process.stdout.write('x'.repeat(5*1024**2)),300);}setInterval(()=>{},1000);}`);
async function waitFor(fn,description){for(let n=0;n<600;n++){const v=await fn();if(v)return v;await delay(50);}throw Error('Timed out: '+description);}
const exists=async p=>readFile(p,'utf8').then(JSON.parse,()=>undefined);
const alive=pid=>{try{process.kill(pid,0);return true;}catch{return false;}};
const identityModule=await import(pathToFileURL(resolve('skills/ghidra-coordinator/dist/src/tool-runtime/identity.js')).href);
const observer=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'}),observerClosed=new Promise(ok=>observer.once('close',ok));
const evidence=[],owners=[];
try{
 const observerBirth=await identityModule.processIdentity(observer.pid);assert.equal(observerBirth.strong,true);
 for(const mode of ['complete','timeout','launcher-kill','owner-kill','flood']){
  const directory=join(root,mode),marker=join(directory,'subject.json');await mkdir(directory);
  const ownerSource=`import {runTool} from ${JSON.stringify(module)};try{const r=await runTool({appArguments:{AppDataDirectory:${JSON.stringify(directory)}},signal:new AbortController().signal,environment:{PATH:process.env.PATH}},{tool:'fixture',role:'job-native',executable:process.execPath,arguments:[${JSON.stringify(fixture)},${JSON.stringify(marker)},${JSON.stringify(mode)},'space value','quote"value','Ω','trailing\\\\'],nativeDeadline:true,observedSubject:${JSON.stringify({pid:observer.pid,birth:observerBirth.birth})},timeoutMs:${mode==='timeout'?4000:15000},acceptedCodes:[7]});console.log(JSON.stringify({ok:true,result:r}));}catch(e){console.log(JSON.stringify({ok:false,code:e.code,result:e.result}));process.exitCode=1;}`;
  const source=join(directory,'owner.mjs');await writeFile(source,ownerSource);const owner=spawn(process.execPath,[source],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';owner.stdout.on('data',b=>stdout+=b);owner.stderr.on('data',b=>stderr+=b);const ended=new Promise(ok=>owner.once('close',ok));owners.push({owner,ended,directory});
  let subject;try{subject=await waitFor(()=>exists(marker),'owned subject launch');}catch(error){console.error('Owned job launch failed',mode,stdout.slice(0,4096),stderr.slice(0,4096));const runs=join(directory,'runtime/runs');for(const name of await readdir(runs).catch(()=>[])){for(const file of ['error.json','job-specification.json','job-launcher-phase.txt','job-started.json','job-result.json','stdout.log','stderr.log']){const value=await readFile(join(runs,name,file),'utf8').catch(()=>undefined);if(value)console.error(file,value.slice(0,4096));}}throw error;}
  const processDirectory=join(directory,'runtime/processes');
  const record=await waitFor(async()=>{const names=await readdir(processDirectory).catch(()=>[]);if(!names.length)return;const r=await exists(join(processDirectory,names[0]));return r?.pid?r:undefined;},'durable launcher record');
  if(mode==='launcher-kill')process.kill(record.pid,'SIGKILL');
  if(mode==='owner-kill')owner.kill('SIGKILL');
  await ended;
  await waitFor(()=>!alive(subject.pid)&&!alive(subject.grandchild)&&!alive(record.pid),'job process tree cleanup');
  if(mode==='complete'){const value=JSON.parse(stdout.trim());assert.equal(value.ok,true,stderr+stdout);assert.equal(value.result.exitCode,7);assert.deepEqual(JSON.parse(value.result.stdout.trim()),['complete','space value','quote"value','Ω','trailing\\']);}
  else if(mode!=='owner-kill'){const value=JSON.parse(stdout.trim());assert.equal(value.ok,false,stderr+stdout);if(mode==='timeout')assert.match(value.code,/timeout/);if(mode==='flood')assert.match(value.code,/output.limit/);}
  assert.equal(alive(observer.pid),true,'Borrowed subject must survive owned job cleanup');evidence.push({mode,subjectGone:true,grandchildGone:true,launcherGone:true,borrowedSubjectPreserved:true});
 }
 const {runTool}=await import(module),context=directory=>({appArguments:{AppDataDirectory:directory},signal:new AbortController().signal,environment:{PATH:process.env.PATH}});
 const bound={pid:observer.pid,birth:observerBirth.birth};
 const mutexDirectory=join(root,'native-mutex');await mkdir(mutexDirectory);const firstMarker=join(mutexDirectory,'first.json'),secondMarker=join(mutexDirectory,'must-not-start.json'),abort=new AbortController();
 const first=runTool({...context(mutexDirectory),signal:abort.signal},{tool:'fixture',role:'mutex-owner',executable:process.execPath,arguments:[fixture,firstMarker,'wait'],nativeDeadline:true,nativeMutex:'procmon',observedSubject:bound,timeoutMs:15000}).catch(error=>error);
 const running=await waitFor(()=>exists(firstMarker),'first native mutex capture');
 try{await assert.rejects(runTool(context(mutexDirectory),{tool:'fixture',role:'mutex-contender',executable:process.execPath,arguments:[fixture,secondMarker,'wait'],nativeDeadline:true,nativeMutex:'procmon',observedSubject:bound,timeoutMs:10000}),error=>/Another owned Process Monitor capture is active/.test(error.result?.stderr??''));assert.equal(await exists(secondMarker),undefined);}finally{abort.abort();await first;}
 await waitFor(()=>!alive(running.pid)&&!alive(running.grandchild),'mutex fixture cleanup');assert.equal(alive(observer.pid),true);evidence.push({mode:'native-singleton-exclusion',secondLaunchRefused:true,subjectGone:true,grandchildGone:true,borrowedSubjectPreserved:true});
 const refusedMarker=join(root,'wrong-birth-must-not-start.json');await assert.rejects(runTool(context(join(root,'wrong-birth')),{tool:'fixture',role:'wrong-borrowed-identity',executable:process.execPath,arguments:[fixture,refusedMarker,'wait'],nativeDeadline:true,observedSubject:{pid:observer.pid,birth:String(BigInt(observerBirth.birth)+1n)},timeoutMs:10000}),error=>/Observed process identity changed or exited/.test(error.result?.stderr??''));assert.equal(await exists(refusedMarker),undefined);assert.equal(alive(observer.pid),true);evidence.push({mode:'borrowed-birth-mismatch',launchRefused:true,borrowedSubjectPreserved:true});
 await writeFile('toolbox-windows-job.json',JSON.stringify({schema:1,platform:process.platform,architecture:process.arch,node:process.version,cases:evidence,passed:true},null,2)+'\n');
 console.log(JSON.stringify({passed:true,cases:evidence.length}));
}finally{if(observer.exitCode===null&&observer.signalCode===null)observer.kill('SIGTERM');await observerClosed;for(const {owner,ended}of owners){if(owner.exitCode===null&&owner.signalCode===null)owner.kill('SIGKILL');await ended;}await delay(500);await rm(root,{recursive:true,force:true,maxRetries:3,retryDelay:500}).catch(e=>console.error('Owned fixture cleanup pending:',e.code));}
