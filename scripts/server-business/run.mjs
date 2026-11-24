// One Automation invocation; each scenario executes its own public-CLI business workflow.
// A red scenario remains red. Collect all outcomes and retain failed copies and transcripts.
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,readdir,realpath,stat} from 'node:fs/promises';
import {resolve,join,dirname,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {PublicCli,save,exec} from '../business/public-cli.mjs';
import {outcomes} from './workflows.mjs';
import {scenarioManifest} from './isolation.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url));
const required=k=>{assert.ok(process.env[k],'Missing '+k);return process.env[k];};
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.ok(!process.env.CI);assert.equal(process.platform,'win32','This follow-up currently targets Windows; the historical business runner targets macOS.');
const hash=b=>createHash('sha256').update(b).digest('hex');
for(const k of ['INSIGHT_SERVER_BUSINESS_OUTPUT','INSIGHT_GLOBAL_CLI','INSIGHT_SERVER_BUSINESS_ARCHIVE','INSIGHT_JAVA','INSIGHT_GHIDRA_HOME'])assert.ok(!required(k).toLowerCase().includes('ec2-native'),'Protected data path');
const base=await realpath(required('INSIGHT_SERVER_BUSINESS_OUTPUT')),directory=await mkdtemp(join(base,'sb-'));
const cli=await realpath(required('INSIGHT_GLOBAL_CLI')),packageRoot=resolve(dirname(cli),'../..'),archive=await realpath(required('INSIGHT_SERVER_BUSINESS_ARCHIVE'));
const pkg=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));assert.equal(pkg.name,'@eyeauras/insight-cli');
assert.equal(cli,await realpath(join(packageRoot,pkg.bin['insight-cli'])));
// Short owned paths also avoid the Windows Java NUL/long-directory boundary.
const archiveSha256=hash(await readFile(archive)),environment={APPDATA:join(directory,'r'),LOCALAPPDATA:join(directory,'l'),HOME:join(directory,'h'),XDG_CONFIG_HOME:join(directory,'c'),TEMP:join(directory,'t'),TMP:join(directory,'t'),TMPDIR:join(directory,'t')};
for(const path of Object.values(environment))await mkdir(path,{recursive:true});
const m={schema:1,isolation:'per-scenario',directory,cli,archive,archiveSha256,packageRoot,version:pkg.version,profile:'sb',environment,java:await realpath(required('INSIGHT_JAVA')),ghidra:await realpath(required('INSIGHT_GHIDRA_HOME'))};
for(const path of [base,cli,archive,m.java,m.ghidra])assert.ok(!path.toLowerCase().includes('ec2-native'),'Protected canonical path');
m.workspace=join(environment.APPDATA,'insight-cli',m.profile,'workspace');
console.log('Server business diagnostics:',directory);
const manifest=join(directory,'manifest.json');await save(manifest,m);
const ids=outcomes.map((_,i)=>'GS-'+String(i+1).padStart(2,'0'));
for(const id of ids){const selected=scenarioManifest(m,id);for(const path of Object.values(selected.environment))await mkdir(path,{recursive:true});await save(join(selected.directory,'manifest.json'),selected);}
// Bind the actual installed payload to the archive before and after execution.
async function verifyPackage(){
 const entries={},pending=[];const {t}=createRequire(join(root,'package.json'))('tar');
 await t({file:archive,onReadEntry(entry){
  if(entry.type==='Directory')return;assert.equal(entry.type,'File');assert.ok(entry.path.startsWith('package/'));
  const path=entry.path.slice(8),target=resolve(packageRoot,path),r=relative(packageRoot,target);assert.ok(r&&!r.startsWith('..')&&!isAbsolute(r));
  const h=createHash('sha256');entry.on('data',b=>h.update(b));pending.push(new Promise((ok,bad)=>{entry.on('error',bad);entry.on('end',async()=>{try{const digest=h.digest('hex');assert.equal(hash(await readFile(target)),digest,path);entries[path]=digest;ok();}catch(e){bad(e);}});}));
 }});await Promise.all(pending);assert.ok(Object.keys(entries).length>500);return entries;
}
async function sources(){
 const hashes={};
 for(const dir of ['scripts/server-business','tests/acceptance/Bindings','tests/acceptance/Features','tests/automation/Host']){
  async function visit(at){for(const item of await readdir(join(root,at),{withFileTypes:true})){if(['bin','obj'].includes(item.name))continue;const path=join(at,item.name);if(item.isDirectory())await visit(path);else if(!path.endsWith('.feature.cs'))hashes[path]=hash(await readFile(join(root,path)));}}await visit(dir);
 }
 for(const path of ['scripts/business/public-cli.mjs','scripts/run-automation.mjs','automation.json','global.json','tests/acceptance/Insight.Acceptance.csproj','tests/acceptance/packages.lock.json'])hashes[path]=hash(await readFile(join(root,path)));
 return hashes;
}
const sourceHashes=await sources(),full=process.argv.length===2;
const report={schema:1,state:'running',startedAt:new Date().toISOString(),installedVersion:pkg.version,archiveSha256,sourceHashes,scenarios:[],cleanupComplete:false,protectedDataAccessed:false,
 isolation:'Independent control root, owned server, repository and profile state per scenario',
 scope:full?`${outcomes.length} native Ghidra Server business workflows; not the historical BS-01–BS-25 suite`:'Selected native Ghidra Server business workflows',selection:process.argv.slice(2),
 baseRevision:(await exec('git',['rev-parse','HEAD'],{cwd:root})).stdout.trim(),automationCommit:(await exec('git',['-C','tests/vendor/EyeAuras.Automation','rev-parse','HEAD'],{cwd:root})).stdout.trim()};
report.runtime={node:process.version,platform:process.platform,architecture:process.arch,dotnet:(await exec('dotnet',['--version'],{cwd:root})).stdout.trim(),java:(await exec(m.java,['-version'])).stderr.trim(),
 ghidra:(await readFile(join(m.ghidra,'Ghidra/application.properties'),'utf8')).split(/\r?\n/).filter(line=>/^application\.(version|release.name|build.date)=/.test(line))};
let log='',error,exit=1;
try{
 const before=await verifyPackage();await save(join(directory,'installed-payload.json'),before);
 const child=spawn(process.execPath,[join(root,'scripts/run-automation.mjs'),'test','--suite','acceptance','--tag','server-business','--property','RestoreLockedMode=true','--timeout-seconds','28800',...process.argv.slice(2)],{
  cwd:root,windowsHide:true,env:{...process.env,INSIGHT_SERVER_BUSINESS_MANIFEST:manifest},stdio:['ignore','pipe','pipe']});
 for(const [stream,out] of [[child.stdout,process.stdout],[child.stderr,process.stderr]])stream.on('data',b=>{log+=b;out.write(b);});
 const seen=new Set();let observing=false;
 const timer=setInterval(async()=>{if(observing)return;observing=true;try{const at=log.match(/Automation run: (.+)/)?.[1]?.trim();if(!at)return;
  for(const name of await readdir(join(at,'scenarios'))){const folder=join(at,'scenarios',name);let selected;try{selected=JSON.parse(await readFile(join(folder,'case.json'),'utf8'));}catch{continue;}
   if(!seen.has(selected.id)){seen.add(selected.id);console.log('Business scenario started:',selected.id);}
   try{const result=JSON.parse(await readFile(join(folder,'result.json'),'utf8'));if(!seen.has(result.id+'-done')){seen.add(result.id+'-done');console.log('Business scenario completed:',result.id,result.state,result.error?.message??'');}}catch{}
  }
 }catch{}finally{observing=false;}},10000);
 try{exit=await new Promise((ok,bad)=>{child.once('error',bad);child.once('exit',code=>ok(code??1));});}finally{clearInterval(timer);}
 await writeFile(join(directory,'automation.log'),log);
 const automation=log.match(/Automation run: (.+)/)?.[1]?.trim();assert.ok(automation,'No Automation run directory');report.automation=automation;
 for(const folder of await readdir(join(automation,'scenarios'))){try{report.scenarios.push(JSON.parse(await readFile(join(automation,'scenarios',folder,'result.json'),'utf8')));}catch(e){if(e.code!=='ENOENT')throw e;}}
 report.scenarios.sort((a,b)=>a.id.localeCompare(b.id));
 report.passed=report.scenarios.filter(s=>s.state==='passed').length;report.failed=report.scenarios.filter(s=>s.state==='failed').length;
 const trx=await readFile(join(automation,'tests.trx'));report.trxSha256=hash(trx);report.trxCounters=trx.toString().match(/<Counters\s+[^>]+/)?.[0];
 assert.deepEqual(await verifyPackage(),before,'Installed payload changed during the run');report.installedPayloadUnchanged=true;
 assert.deepEqual(await sources(),sourceHashes,'Acceptance inputs changed during execution');report.acceptanceInputsUnchanged=true;
 if(full)assert.deepEqual(report.scenarios.map(s=>s.id),Array.from({length:outcomes.length},(_,i)=>'GS-'+String(i+1).padStart(2,'0')),'Missing/duplicate scenario outcomes');
 report.state=exit===0&&report.failed===0&&report.scenarios.length>0?'passed':'failed';
}catch(e){error=e;report.state='failed';report.error={message:e.message,stack:e.stack};}
finally{
 const cleanupErrors=[];
 // Completed drivers stop their own services. Recover only owned interrupted/failed
 // teardown paths; untouched selections never acquire a profile just for cleanup.
 for(const id of ids){
  if(report.scenarios.some(s=>s.id===id&&s.serviceCleanupComplete))continue;
  const selected=scenarioManifest(m,id);
  try{await stat(join(selected.environment.APPDATA,'insight-cli','profiles.json'));}catch(e){if(e.code==='ENOENT')continue;cleanupErrors.push(e.message);continue;}
  const client=new PublicCli(selected,join(directory,'suite-cleanup',id));
  for(const [args,options]of [[['ghidra','server','disconnect'],{}],[['ipc-server','stop'],{global:true}]])try{await client.call(args,options);}catch(e){cleanupErrors.push(id+': '+e.message);}
 }
 report.cleanupComplete=cleanupErrors.length===0;
 if(cleanupErrors.length){report.state='failed';report.cleanupError=cleanupErrors.join('\n');}
 report.finishedAt=new Date().toISOString();await save(join(directory,'report.json'),report);
 console.log(JSON.stringify({state:report.state,passed:report.passed,failed:report.failed,cleanupComplete:report.cleanupComplete,directory}));
 if(error)console.error(error);process.exitCode=report.state==='passed'?0:1;
}
