// Opt-in public global-CLI acceptance. No product imports or backend seams.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,mkdtemp,realpath,stat,mkdir} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
const exec=promisify(execFile),[executable,input,output,...extra]=process.argv.slice(2);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');
assert.ok(executable&&input&&output);const external=extra[0],officialArchive=extra[1];assert.ok(officialArchive,'Official Ghidra zip required for macOS native overlay acceptance');assert.ok(external,'Explicit external Ghidra launcher required for the external-mode proof');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex'),inputSha=sha(await readFile(input));
assert.equal(inputSha,'256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282');
const root=await realpath(await mkdtemp('/tmp/insight-managed-runtime-proof-')),profile='runtime-proof-'+randomUUID(),externalProfile=profile+'-external',calls=[],scopes=[];
const environment={...process.env,PATH:'/opt/homebrew/bin:/usr/bin:/bin'};delete environment.JAVA_HOME;delete environment.GHIDRA_HOME;delete environment.GHIDRA_MCP_HOME;
let sequence=0;
async function call(args,{selected=profile,global=false,success=true}={}){
 const started=process.hrtime.bigint(),n=++sequence;let result,code=0;
 try{result=await exec(executable,[...(global?[]:['--profile',selected]),...args,'--json'],{cwd:root,env:environment,timeout:1200000,maxBuffer:8*1024*1024});}
 catch(e){code=typeof e.code==='number'?e.code:1;result=e;}
 await writeFile(join(root,n+'.stdout'),result.stdout??'',{mode:0o600});await writeFile(join(root,n+'.stderr'),result.stderr??'',{mode:0o600});
 calls.push({command:args.slice(0,3).join(' '),code,seconds:Number(process.hrtime.bigint()-started)/1e9});
 assert.equal(code===0,success,'CLI outcome differs: '+args.slice(0,3).join(' ')+'; transcript '+root+'/'+n);
 return JSON.parse(success?result.stdout:result.stderr);
}
const scoped=(s,args,options={})=>call(['ghidra',...args,'--session',s.session,'--target',s.target],options);
const report={schema:1,state:'running',package:'@eyeauras/insight-cli',version:'0.2.0',scope:'global public CLI; fresh managed install and external launcher; real 7zr research and publication',inputSha256:inputSha,runnerNode:process.version,cliNode:(await exec('/usr/bin/env',['node','--version'],{env:environment})).stdout.trim(),platform:process.platform,architecture:process.arch,checks:{},calls};
async function stopOwned(selected){for(const s of scopes.filter(s=>s.profile===selected).reverse())await scoped(s,['close'],{selected});await call(['ghidra','server','stop'],{selected});}
try{
 const skill=await call(['skill'],{global:true});const packageRoot=dirname(skill.path);const metadata=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));assert.equal(metadata.version,'0.2.0');report.installedBuild=JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8'));
 for(const name of [profile,externalProfile]){await call(['profile','create',name],{global:true});await call(['permissions','grant','Update'],{selected:name});await call(['permissions','grant','Destructive'],{selected:name});}
 const initial=await call(['ghidra','status']);assert.equal(initial.mode,'unconfigured');assert.deepEqual(initial.missing,['jdk','ghidra']);assert.equal((await call(['ghidra','server','status'])).state,'runtime_not_ready');
 report.checks.freshProfileWithoutRuntimePaths=true;
 const downloaded=await call(['ghidra','download']);assert.equal(downloaded.items.length,2);report.artifacts=downloaded.items.map(({name,sha256,license})=>({name,sha256,license}));
 assert.equal((await call(['ghidra','download','--offline'])).state,'downloaded');report.checks.pinnedDownloadsAndOfflineCache=true;
 const installed=await call(['ghidra','install','--offline']);assert.equal(installed.mode,'managed');assert.ok(installed.java.includes('/runtime/installations/'));assert.ok(installed.ghidraHome.includes('/runtime/installations/'));report.runtimeFingerprint=installed.fingerprint;
 const doctor=await call(['ghidra','doctor']);assert.equal(doctor.state,'verified');assert.equal(doctor.server,true);assert.equal(doctor.decompiler,true);assert.equal(doctor.debugger.state,'ready');report.checks.nativeInstallAndDoctor=true;
 await call(['ghidra','server','start']);assert.equal((await call(['ghidra','server','status'])).connected,true);report.checks.explicitOwnedServerLifecycle=true;
 const a=await call(['ghidra','open',input,'--session','new']);scopes.push({...a,profile});assert.equal(a.state,'ready');const b=await call(['ghidra','open',input,'--session','new']);scopes.push({...b,profile});assert.equal(a.target,b.target);
 const strings=await scoped(a,['strings','search','--contains','CRC Failed','--limit','30']);let address=strings.items.find(s=>s.text==='CRC Failed')?.address,fn;
 for(let depth=0;depth<3&&!fn;depth++){const refs=await scoped(a,['xrefs','to','--address',address,'--limit','30']);fn=refs.items.find(r=>r.function?.address)?.function.address;address=refs.items.find(r=>r.from)?.from;}
 assert.ok(fn);const code=await scoped(a,['functions','decompile','--address',fn]);assert.equal(code.truncated,false);assert.match(code.code,/case 3/);report.entry=fn;
 const local='B retained local CRC diagnostic research';await scoped(b,['comments','set','--address',fn,'--kind','repeatable','--text',local]);
 const shared='A verified CRC diagnostic selector with a managed Ghidra runtime';await scoped(a,['comments','set','--address',fn,'--kind','plate','--text',shared]);assert.equal((await scoped(a,['merge'])).sharedRevision,'R2');
 await scoped(b,['refresh']);assert.equal((await scoped(b,['comments','get','--address',fn,'--kind','plate'])).text,shared);assert.equal((await scoped(b,['comments','get','--address',fn,'--kind','repeatable'])).text,local);assert.equal((await scoped(b,['merge'])).sharedRevision,'R3');report.checks.multiClientRealExeResearchMergeRefresh=true;
 const busy=await call(['ghidra','uninstall'],{success:false});assert.equal(busy.error.code,'coordinator.busy');const busyServer=await call(['ghidra','server','stop'],{success:false});assert.equal(busyServer.error.code,'coordinator.busy');report.checks.busyRuntimeAndServerProtected=true;
 const material=join(root,'research.md');await writeFile(material,'Existing project evidence format stays intact.\n');const saved=await call(['artifacts','save',material]);await stopOwned(profile);
 await call(['ghidra','uninstall']);assert.equal((await call(['ghidra','status'])).state,'not_ready');assert.equal((await call(['targets','list'])).items[0].target,a.target);assert.equal(await readFile(saved.path,'utf8'),'Existing project evidence format stays intact.\n');report.checks.uninstallPreservesResearchAndArtifacts=true;
 const ghidra=downloaded.items.find(x=>x.name.startsWith('ghidra')),jdk=downloaded.items.find(x=>x.name.startsWith('temurin'));
 const reinstalled=await call(['ghidra','install','--archive',ghidra.path,'--archive-sha256',ghidra.sha256,'--java-archive',jdk.path,'--java-archive-sha256',jdk.sha256,'--offline']);assert.equal(reinstalled.fingerprint,installed.fingerprint);
 const resumed=await call(['ghidra','open','--session',b.session,'--target',b.target]);assert.equal(resumed.state,'ready');assert.equal((await scoped(b,['comments','get','--address',fn,'--kind','repeatable'])).text,local);await scoped(b,['close']);await call(['ghidra','server','stop']);report.checks.localArchivesAndResearchContinuation=true;
 assert.equal(sha(await readFile(officialArchive)),'b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d');
 const official=await call(['ghidra','install','--archive',officialArchive,'--java-archive',jdk.path,'--offline']);assert.equal(official.mode,'managed');assert.notEqual(official.fingerprint,installed.fingerprint);
 await call(['ghidra','open','--session',b.session,'--target',b.target]);assert.equal((await scoped(b,['comments','get','--address',fn,'--kind','repeatable'])).text,local);await scoped(b,['close']);await call(['ghidra','server','stop']);report.checks.officialZipWithManagedMacNatives=true;
 const source=join(root,'debug-fixture.c'),debugExe=join(root,'debug-fixture');
 await writeFile(source,'volatile unsigned long count=0; __attribute__((noinline)) int step(int x){return x+7;} int main(void){for(;;)count+=step(1);}'+'\n');
 await exec('/usr/bin/clang',['-O0','-g',source,'-o',debugExe],{cwd:root,timeout:60000});
 const debug=await call(['ghidra','open',debugExe,'--session','new']);scopes.push({...debug,profile});
 const offers=await scoped(debug,['debugger','launch-offers']);assert.ok(offers.value.items.some(o=>o.title==='lldb'));
 const launched=await scoped(debug,['debugger','launch','--timeout-seconds','90']);assert.ok(launched.trace);
 await scoped(debug,['debugger','interrupt']);const registers=await scoped(debug,['debugger','registers']);assert.ok(Object.keys(registers.value).some(k=>/^(pc|rip|eip)$/i.test(k)));
 await scoped(debug,['close']);await call(['ghidra','server','stop']);report.checks.managedGuiAndLiveDebugger=true;
 const extension=join(root,'RuntimeProof');await mkdir(join(extension,'ghidra_scripts'),{recursive:true});
 await writeFile(join(extension,'Module.manifest'),'');await writeFile(join(extension,'extension.properties'),'name=RuntimeProof\nversion=12.1.2\ndescription=Owned managed runtime acceptance\n');
 await writeFile(join(extension,'ghidra_scripts/ManagedRuntimeScript.java'),'import ghidra.app.script.GhidraScript; public class ManagedRuntimeScript extends GhidraScript { public void run() throws Exception { setPostComment(toAddr(0x436fea), "Managed runtime extension verified"); }}\n');
 const inspected=await call(['ghidra','extensions','inspect','--directory',extension]);await call(['ghidra','extensions','install','--directory',extension,'--sha256',inspected.sha256]);
 await call(['ipc-server','stop'],{global:true});
 await call(['ghidra','open','--session',b.session,'--target',b.target]);await scoped(b,['scripts','run','--script-name','extension:RuntimeProof/ManagedRuntimeScript.java']);
 assert.equal((await scoped(b,['comments','get','--address',fn,'--kind','post'])).text,'Managed runtime extension verified');await scoped(b,['close']);await call(['ghidra','server','stop']);report.checks.managedBaseAndIsolatedExtension=true;
 const externalHash=sha(await readFile(external));
 const selected=await call(['ghidra','install','--executable',external,'--java-archive',jdk.path,'--offline'],{selected:externalProfile});assert.equal(selected.mode,'external');assert.ok((await stat(join(selected.ghidraHome,'Ghidra/application.properties'))).isFile());assert.ok(selected.java.includes('/runtime/installations/'));
 const x=await call(['ghidra','open',input,'--session','new'],{selected:externalProfile});scopes.push({...x,profile:externalProfile});assert.equal(x.state,'ready');assert.match((await scoped(x,['functions','decompile','--address',fn],{selected:externalProfile})).code,/case 3/);
 await scoped(x,['comments','set','--address',fn,'--kind','plate','--text','External Ghidra launcher and managed JDK verified'],{selected:externalProfile});assert.equal((await scoped(x,['merge'],{selected:externalProfile})).sharedRevision,'R2');
 const y=await call(['ghidra','open','--target',x.target,'--session','new'],{selected:externalProfile});scopes.push({...y,profile:externalProfile});assert.equal((await scoped(y,['comments','get','--address',fn,'--kind','plate'],{selected:externalProfile})).text,'External Ghidra launcher and managed JDK verified');
 await stopOwned(externalProfile);await call(['ghidra','uninstall','--purge-cache'],{selected:externalProfile});assert.equal(sha(await readFile(external)),externalHash);assert.ok((await stat(selected.ghidraHome)).isDirectory());report.checks.externalLauncherRealExeMergeAndSafeUninstall=true;
 assert.equal(sha(await readFile(input)),inputSha);report.checks.unchangedInput=true;report.state='passed';
}catch(error){report.state='failed';report.failure='Inspect retained CLI transcripts; publication is never blindly replayed.';throw error;}
finally{await writeFile(output,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({state:report.state,checks:report.checks,transcripts:root,profiles:[profile,externalProfile]}));}
