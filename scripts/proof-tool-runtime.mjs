// Opt-in global installed public CLI gate. Product code is never imported.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,mkdtemp,cp,readdir,stat,mkdir,symlink} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
const exec=promisify(execFile),[cli,exe,assembly,reportPath,external,ghidraArchive,ilspyArchive,dotnetArchive]=process.argv.slice(2);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');assert.ok(dotnetArchive);
const root=await mkdtemp('/private/tmp/insight-tool-runtime-proof-'),calls=[],checks={},sha=b=>createHash('sha256').update(b).digest('hex');
await mkdir(join(root,'bin'));await symlink(process.execPath,join(root,'bin/node'));
const environment={...process.env,PATH:join(root,'bin')+':/usr/bin:/bin'};for(const key of ['JAVA_HOME','GHIDRA_HOME','GHIDRA_MCP_HOME','DOTNET_ROOT'])delete environment[key];
const exeSha=sha(await readFile(exe)),assemblySha=sha(await readFile(assembly)),report={schema:1,state:'running',scope:'global installed CLI; mirrored delivery, Ghidra and ILSpy, recovery and safe removal',platform:process.platform,architecture:process.arch,node:process.version,inputSha256:{exe:exeSha,assembly:assemblySha},checks,calls};
let profile,sequence=0;
async function call(args,{global=false,success=true,result=false}={}){
 const start=performance.now(),n=++sequence;let r,code=0;
 try{r=await exec(cli,[...(global?[]:['--profile',profile]),...args,'--json'],{cwd:root,env:environment,timeout:1200000,maxBuffer:8*1024**2});}catch(e){r=e;code=typeof e.code==='number'?e.code:1;}
 await writeFile(join(root,n+'.stdout'),r.stdout??'',{mode:0o600});await writeFile(join(root,n+'.stderr'),r.stderr??'',{mode:0o600});calls.push({command:args.slice(0,3).join(' '),code,seconds:(performance.now()-start)/1000});
 assert.equal(code===0,success,'Unexpected CLI outcome: '+args.slice(0,3).join(' ')+'; transcript '+root+'/'+n);return JSON.parse(success||result?r.stdout:r.stderr);
}
const scoped=(s,args,options)=>call(['ghidra',...args,'--session',s.session,'--target',s.target],options);
try{
 if(process.env.INSIGHT_TOOL_RUNTIME_CONTINUE_REPORT){
  // Explicit development continuation, never used by the release/Automation gate.
  report.ghidra=JSON.parse(await readFile(process.env.INSIGHT_TOOL_RUNTIME_CONTINUE_REPORT,'utf8'));profile=process.env.INSIGHT_TOOL_RUNTIME_CONTINUE_PROFILE;assert.ok(profile);report.developmentContinuation=true;
 }else{
  const legacyPath=join(root,'managed-runtime.json'),start=performance.now();
  const r=await exec(process.execPath,[fileURLToPath(new URL('./proof-managed-runtime.mjs',import.meta.url)),cli,exe,legacyPath,external,ghidraArchive],{cwd:root,env:environment,timeout:2400000,maxBuffer:4*1024**2});
  report.ghidra=JSON.parse(await readFile(legacyPath,'utf8'));assert.equal(report.ghidra.state,'passed');profile=JSON.parse(r.stdout.trim().split('\n').at(-1)).profiles[0];report.ghidraGateSeconds=(performance.now()-start)/1000;
 }
 assert.equal(report.ghidra.state,'passed');const skill=await call(['skill'],{global:true});report.installedBuild=JSON.parse(await readFile(join(dirname(skill.path),'.cli-package-build.json'),'utf8'));report.installedVersion=JSON.parse(await readFile(join(dirname(skill.path),'package.json'),'utf8')).version;
 const a=await call(['ghidra','open',exe,'--session','new']),b=await call(['ghidra','open',exe,'--session','new']);assert.equal(a.target,b.target);const entry=report.ghidra.entry;
 const parallel=await Promise.all([scoped(a,['functions','decompile','--address',entry]),scoped(b,['functions','decompile','--address',entry])]);assert.ok(parallel.every(v=>v.code.includes('case 3')));checks.parallelPublicClients=true;
 const trial=Date.now(),shared='Shared core A conflict evidence '+trial,local='Shared core B retained evidence '+trial,disjoint='B safe field retained atomically '+trial;
 await scoped(a,['comments','set','--address',entry,'--kind','plate','--text',shared]);await scoped(b,['comments','set','--address',entry,'--kind','plate','--text',local]);await scoped(b,['comments','set','--address',entry,'--kind','repeatable','--text',disjoint]);
 const merged=await scoped(a,['merge']);const conflict=await scoped(b,['merge'],{success:false,result:true});assert.equal(conflict.state,'conflict');
 const witness=await call(['ghidra','open','--target',a.target,'--session','new']);assert.equal((await scoped(witness,['comments','get','--address',entry,'--kind','plate'])).text,shared);assert.notEqual((await scoped(witness,['comments','get','--address',entry,'--kind','repeatable'])).text,disjoint);
 await scoped(b,['refresh']);assert.equal((await scoped(b,['comments','get','--address',entry,'--kind','plate'])).text,local);assert.equal((await scoped(b,['comments','get','--address',entry,'--kind','repeatable'])).text,disjoint);
 await scoped(b,['comments','set','--address',entry,'--kind','plate','--text',local,'--resolve-conflict','--expect-shared',shared]);assert.equal((await scoped(b,['merge'])).state,'merged');checks.atomicConflictAndRefresh=true;
 await scoped(witness,['close']);const list=await call(['tools','processes','--tool','ghidra']);let ar=list.items.find(r=>r.session===a.session&&r.target===a.target&&r.role==='context'),br=list.items.find(r=>r.session===b.session&&r.target===b.target&&r.role==='context');assert.ok(ar&&br);assert.notEqual(ar.pid,br.pid);
 await call(['tools','processes','stop',ar.id]);assert.equal((await call(['sessions','status',a.session,'--target',a.target])).ghidra.state,'stopped');checks.saveAwareProcessStop=true;
 const acknowledged='Acknowledged work survives process kill and owner replacement';await scoped(b,['comments','set','--address',entry,'--kind','post','--text',acknowledged]);
 const owner=await call(['ipc-server','status'],{global:true});assert.equal(owner.running,true);process.kill(owner.pid,'SIGKILL');await delay(300);
 const recovered=await call(['tools','processes','show',br.id]);assert.equal(recovered.pid,br.pid);assert.equal(recovered.state,'running');assert.equal((await scoped(b,['comments','get','--address',entry,'--kind','post'])).text,acknowledged);checks.authenticatedOwnerCrashRecovery=true;
 assert.equal((await call(['tools','processes','kill',br.id])).state,'killed');await call(['ghidra','open','--session',b.session,'--target',b.target]);assert.equal((await scoped(b,['comments','get','--address',entry,'--kind','post'])).text,acknowledged);checks.contextKillRetainsAcknowledgedWork=true;
 const server=(await call(['tools','processes','--tool','ghidra'])).items.find(r=>r.role==='server');assert.ok(server);await call(['tools','processes','kill',server.id]);await call(['ghidra','server','start']);assert.equal((await scoped(b,['comments','get','--address',entry,'--kind','post'])).text,acknowledged);assert.equal((await scoped(b,['merge'])).state,'merged');checks.serverKillRetainsLocalWork=true;
 await scoped(b,['close']);await call(['ghidra','server','stop']);
 const download=await call(['ilspy','download']);assert.equal(download.items.length,2);assert.equal((await call(['ilspy','download','--offline'])).state,'downloaded');
 const installed=await call(['ilspy','install','--offline']);assert.equal(installed.mode,'managed');const managedExe=installed.executable;assert.ok(managedExe.includes('/runtime/tools/ilspy/'));assert.equal((await call(['ilspy','doctor'])).state,'verified');checks.privateDotnetMirroredDelivery=true;
 const target=(await call(['targets','add',assembly])).target,types=await call(['ilspy','types','--target',target]);assert.match(types.content,/ResearchFixture.Policy/);
 const [code,il,resources]=await Promise.all([call(['ilspy','decompile','--target',target,'--type','ResearchFixture.Policy','--session',b.session]),call(['ilspy','il','--target',target,'--type','ResearchFixture.Policy']),call(['ilspy','resources','--target',target])]);
 assert.match(code.content,/CalculateCost/);assert.match(code.content,/GetTickCount/);assert.match(code.content,/\^ (?:0x5[Aa]|90)/);assert.match(il.content,/xor/);assert.match(resources.content,/ResearchFixture.settings.json/);
 const textFile=join(root,'Policy.cs');await call(['ilspy','decompile','--target',target,'--type','ResearchFixture.Policy','--output',textFile]);assert.match(await readFile(textFile,'utf8'),/CalculateCost/);
 const resource=await call(['ilspy','resource','--target',target,'--name','ResearchFixture.settings.json','--output',join(root,'resources')]);assert.ok(resource.files.length);const resourceFile=join(resource.outputDirectory,resource.files[0].name);assert.equal(JSON.parse(await readFile(resourceFile,'utf8')).retryLimit,7);
 const project=await call(['ilspy','project','--target',target,'--output',join(root,'project')]);assert.ok(project.files.some(f=>f.name.endsWith('.csproj')));assert.ok(project.files.some(f=>f.name.endsWith('.cs')));
 const table=await call(['ilspy','metadata','--target',target,'--table','MethodDef']);assert.match(table.content,/CalculateCost/);
 const saved=await call(['artifacts','save',join(root,'project')]);assert.ok(saved.files>=project.files.length);checks.usefulManagedResearchAndPlainSavedFiles=true;
 const ilspyRuns=await call(['tools','processes','--tool','ilspy','--all']);assert.ok(ilspyRuns.items.some(r=>r.target===target&&r.session===b.session));assert.ok(ilspyRuns.items.every(r=>['exited','failed'].includes(r.state)));checks.multiToolTargetAndRunInventory=true;
 const invalid=join(root,'not-managed.dll');await writeFile(invalid,'invalid managed input');const failed=await call(['ilspy','types',invalid],{success:false});assert.equal(failed.error.code,'tool.exit.code');checks.failedToolRetainsDiagnostics=true;
 const externalRoot=join(root,'external-ilspy');await cp(dirname(dirname(managedExe)),externalRoot,{recursive:true});const externalDotnet=join(externalRoot,'dotnet','dotnet'),externalDll=join(externalRoot,'ilspy/tools/net10.0/any/ilspycmd.dll'),shim=join(root,'external-ilspycmd');
 const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";await writeFile(shim,'#!/bin/sh\nDOTNET_ROOT='+quote(dirname(externalDotnet))+' exec '+quote(externalDotnet)+' '+quote(externalDll)+' "$@"\n',{mode:0o755});const shimSha=sha(await readFile(shim));
 await call(['ilspy','uninstall']);assert.equal((await call(['targets','show',target])).binarySha256,assemblySha);assert.match(await readFile(saved.path+'/'+project.files.find(f=>f.name.endsWith('.cs')).name,'utf8'),/namespace/);checks.uninstallRetainsBothToolsResearch=true;
 assert.equal((await call(['ilspy','install','--archive',ilspyArchive,'--dotnet-archive',dotnetArchive,'--offline'])).mode,'managed');assert.match((await call(['ilspy','types','--target',target])).content,/ResearchFixture.Policy/);await call(['ilspy','uninstall']);checks.offlineLocalArchiveReinstall=true;
 assert.equal((await call(['ilspy','install','--executable',shim,'--offline'])).mode,'external');assert.match((await call(['ilspy','decompile','--target',target,'--type','ResearchFixture.Policy'])).content,/GetTickCount/);await call(['ilspy','uninstall','--purge-cache']);assert.equal(sha(await readFile(shim)),shimSha);assert.ok((await stat(externalDotnet)).isFile());checks.externalIlspyAndSafeUninstall=true;
 assert.equal((await call(['tools','processes'])).items.length,0);assert.equal(sha(await readFile(exe)),exeSha);assert.equal(sha(await readFile(assembly)),assemblySha);checks.noLiveOwnedToolProcesses=true;checks.unchangedInputs=true;
 report.findings={native:'CRC error selector in real 7zr.exe with merged annotations',managed:['Tiered CalculateCost arithmetic','Byte XOR decoding with 0x5a','PInvoke kernel32!GetTickCount','Embedded retryLimit=7 and telemetry endpoint']};report.state='passed';
}catch(error){report.state='failed';report.failure=String(error);throw error;}
finally{await writeFile(reportPath,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({state:report.state,checks,transcripts:root,profile}));}
