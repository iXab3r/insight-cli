import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,stat,symlink,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync,crc32} from 'node:zlib';
import {Header} from 'tar';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {cacheArtifact,extractArchive,fileSha256} from '../src/tool-runtime/archives.js';
import {externalGhidra,runtimeProcesses,runtimeWrite} from '../src/runtime-manager.js';
import {runtimeSelection,runtimeValues} from '../src/runtime-selection.js';
import {stopLocalServer,GhidraServer} from '../src/server.js';
import {runtimeCatalog} from '../src/runtime-catalog.js';
const artifact={name:'fixture',url:'https://example.invalid/pinned',sha256:'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',format:'tgz' as const,root:'root',license:'test'};
async function temporary(t:test.TestContext){const root=await realpath(await mkdtemp(join(tmpdir(),'insight-runtime-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test('runtime and server status on an empty profile require no native inputs or workspace',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),app=f.createApplication(runtime=>createInsightCli({runtime}));
 const status=await f.json(app,['ghidra','status']) as any;assert.equal(status.mode,'unconfigured');assert.deepEqual(status.missing,['jdk','ghidra']);
 const server=await f.json(app,['ghidra','server','status']) as any;assert.equal(server.connected,false);assert.equal(server.state,'runtime_not_ready');
 await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'workspace')));
 const partial=await f.run(app,['ghidra','status','--session','s_missing','--json']);assert.notEqual(partial.exitCode,0);assert.match(partial.stderr,/target/);
});
test('runtime acquisition and removal remain behind Factory permissions; offline miss leaves selection absent',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),app=f.createApplication(runtime=>createInsightCli({runtime}));
 for(const args of [['ghidra','download'],['ghidra','install'],['ghidra','uninstall']]){const denied=await f.run(app,[...args,'--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);}
 await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'runtime')));
 await f.run(app,['permissions','grant','Update']);const missing=await f.run(app,['ghidra','install','--offline','--json']);assert.notEqual(missing.exitCode,0);assert.match(missing.stderr,/not cached/);
 assert.equal(runtimeSelection(f.appArguments.AppDataDirectory),undefined);
});
test('download streams pinned bytes, reuses cache offline, rejects corruption without replacing it',async t=>{
 const root=await temporary(t);let calls=0;const fetcher=(async()=>{calls++;return new Response('hello');}) as typeof fetch;
 const path=await cacheArtifact(artifact,root,fetcher,new AbortController().signal);assert.equal(calls,1);assert.equal(await fileSha256(path),artifact.sha256);
 assert.equal(await cacheArtifact(artifact,root,fetcher,new AbortController().signal,true),path);assert.equal(calls,1);
 await writeFile(path,'corrupt');await assert.rejects(cacheArtifact(artifact,root,fetcher,new AbortController().signal),/Cached runtime archive/);assert.equal(calls,1);assert.equal(await readFile(path,'utf8'),'corrupt');
});
test('lost or hash-mismatched downloads cannot become complete cache entries',async t=>{
 const root=await temporary(t),fetcher=(async()=>new Response('wrong')) as typeof fetch;
 await assert.rejects(cacheArtifact(artifact,root,fetcher,new AbortController().signal),/SHA256/);await assert.rejects(stat(join(root,artifact.sha256+'.tgz')));
 let calls=0;await assert.rejects(cacheArtifact(artifact,root,(async()=>{calls++;throw Error('network');}) as typeof fetch,new AbortController().signal,true),/not cached/);assert.equal(calls,0);
});
function tarball(entries:{path:string;type?:'File'|'SymbolicLink';linkpath?:string;body?:string}[]){const buffers=[];for(const entry of entries){const data=Buffer.from(entry.body??''),header=new Header({path:entry.path,type:entry.type??'File',linkpath:entry.linkpath,size:data.length,mode:0o755});header.encode();buffers.push(header.block!,data,Buffer.alloc((512-data.length%512)%512));}buffers.push(Buffer.alloc(1024));return gzipSync(Buffer.concat(buffers));}
test('portable extraction preserves executables and rejects traversal and escaping links',async t=>{
 const root=await temporary(t),file=join(root,'runtime.tgz');await writeFile(file,tarball([{path:'runtime/bin/tool',body:'native'}]));await extractArchive(file,join(root,'valid'),'tgz');assert.equal(await readFile(join(root,'valid/runtime/bin/tool'),'utf8'),'native');if(process.platform!=='win32')assert.ok((await stat(join(root,'valid/runtime/bin/tool'))).mode&0o100);
 for(const entry of [{path:'../escape',body:'no'},{path:'/absolute',body:'no'},{path:'runtime/link',type:'SymbolicLink' as const,linkpath:'../../escape'}]){await writeFile(file,tarball([entry]));await assert.rejects(extractArchive(file,join(root,'unsafe-'+Math.random()),'tgz'),/unsafe|escapes/);}
 await assert.rejects(stat(join(root,'escape')));
});
test('external executable resolves a complete installation and never accepts a target EXE',async t=>{
 const root=await temporary(t),home=join(root,'sdk');await mkdir(join(home,'Ghidra'),{recursive:true});await writeFile(join(home,'Ghidra/application.properties'),'application.version=12.1.2');await writeFile(join(home,'ghidraRun'),'launcher');await writeFile(join(home,'sample.exe'),'not launcher');
 const cellar=join(root,'cellar');await mkdir(join(cellar,'bin'),{recursive:true});await mkdir(join(cellar,'libexec/Ghidra'),{recursive:true});await writeFile(join(cellar,'libexec/Ghidra/application.properties'),'application.version=12.1.2');await writeFile(join(cellar,'bin/ghidraRun'),'wrapper');assert.equal(await externalGhidra(join(cellar,'bin/ghidraRun')),join(cellar,'libexec'));
 assert.equal(await externalGhidra(join(home,'ghidraRun')),home);assert.equal(await externalGhidra(home),home);await assert.rejects(externalGhidra(join(home,'sample.exe')),/not a target EXE/);
});
test('passive process inventory conservatively blocks live receipts and honors verified stopped receipts',async t=>{
 const root=await temporary(t),processRoot=join(root,'workspace/ghidra-native/context/c/one');await mkdir(processRoot,{recursive:true});
 const receipt={pid:process.pid,tokenSecret:'fixture',kind:'context',context:'c',session:'s_owned',target:'t'};await runtimeWrite(join(processRoot,'process.json'),receipt);assert.equal((await runtimeProcesses(root)).length,1);assert.equal((await runtimeProcesses(root))[0]?.session,'s_owned');
 await runtimeWrite(join(processRoot,'stopped.json'),{pid:process.pid,tokenSecret:'other'});assert.equal((await runtimeProcesses(root)).length,1);
 await runtimeWrite(join(processRoot,'stopped.json'),{pid:process.pid,tokenSecret:'fixture'});assert.equal((await runtimeProcesses(root)).length,0);
});
test('explicit selection fails closed after uninstall instead of falling back to configured external paths',async t=>{
 const root=await temporary(t),id='a'.repeat(64),selection={schema:1,mode:'managed',id,ghidraHome:join(root,'runtime/installations',id,'ghidra'),java:join(root,'runtime/installations',id,'jdk/bin/java'),fingerprint:'b'.repeat(64),selectedAt:'now'};
 await runtimeWrite(join(root,'runtime/selection.json'),selection);assert.throws(()=>runtimeValues(root,{java:'/external/java',ghidraHome:'/external/ghidra'}),/not installed/);
 await runtimeWrite(join(root,'runtime/installations',id,'ready.json'),{});assert.equal(runtimeValues(root,{}).java,selection.java);
 await runtimeWrite(join(root,'runtime/selection.json'),{...selection,ghidraHome:'/outside'});assert.throws(()=>runtimeSelection(root),/outside/);
});
test('catalog pins complete platform artifacts and never selects an unsupported architecture silently',()=>{
 for(const [os,arch]of [['darwin','arm64'],['darwin','x64'],['linux','x64'],['win32','x64']]){const catalog=runtimeCatalog(os,arch,'25.0');for(const item of [catalog.java,catalog.ghidra]){assert.match(item.sha256,/^[a-f0-9]{64}$/);assert.match(item.url,/^https:/);}}
 assert.throws(()=>runtimeCatalog('linux','arm64'),/No verified/);assert.throws(()=>runtimeCatalog('darwin','arm64','22'),/macOS 14/);
});
test('failed local installation preserves the prior selection and retains bounded diagnostics',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]}),app=f.createApplication(runtime=>createInsightCli({runtime}));
 const selection={schema:1,mode:'external',ghidraHome:join(f.root,'existing-ghidra'),java:join(f.root,'existing-java'),fingerprint:'f'.repeat(64),selectedAt:'original'};
 const selectionPath=join(f.appArguments.AppDataDirectory,'runtime/selection.json');await runtimeWrite(selectionPath,selection);const original=await readFile(selectionPath,'utf8');
 const archive=join(f.root,'unsafe.tgz'),java=join(f.root,'java');await writeFile(archive,tarball([{path:'../escape',body:'unsafe'}]));await writeFile(java,'unused');
 const failed=await f.run(app,['ghidra','install','--archive',archive,'--java',java,'--offline','--json']);assert.notEqual(failed.exitCode,0);assert.match(failed.stderr,/unsafe path/);
 assert.equal(await readFile(selectionPath,'utf8'),original);
 const result=JSON.parse(failed.stdout);assert.ok(result.diagnostics.includes('stages'));const retained=JSON.parse(await readFile(join(result.diagnostics,'failure.json'),'utf8'));assert.equal(retained.state,'failed');
 const consumed=join(f.appArguments.AppDataDirectory,'runtime/cache',(await fileSha256(archive))+'.tgz'),bytes=await readFile(consumed);await writeFile(archive,'later source edit');assert.deepEqual(await readFile(consumed),bytes);
 await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'runtime/escape')));
});
test('runtime removal deletes owned components and preserves external code, research and materials',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]}),app=f.createApplication(runtime=>createInsightCli({runtime})),root=f.appArguments.AppDataDirectory,id='c'.repeat(64),installation=join(root,'runtime/installations',id),external=join(f.root,'external');
 for(const path of [join(installation,'jdk'),external,join(root,'workspace'),join(root,'materials')])await mkdir(path,{recursive:true});
 await writeFile(join(external,'ghidraRun'),'external code');await writeFile(join(root,'workspace/workspace.sqlite'),'retained journal');await writeFile(join(root,'materials/evidence.md'),'retained evidence');
 await runtimeWrite(join(root,'runtime/selection.json'),{schema:1,mode:'external',id,java:join(installation,'jdk/bin/java'),ghidraHome:external,fingerprint:'d'.repeat(64),selectedAt:'now'});
 const value=await f.json(app,['ghidra','uninstall']) as any;assert.equal(value.externalInstallationPreserved,true);await assert.rejects(stat(installation));
 assert.equal(await readFile(join(external,'ghidraRun'),'utf8'),'external code');assert.equal(await readFile(join(root,'workspace/workspace.sqlite'),'utf8'),'retained journal');assert.equal(await readFile(join(root,'materials/evidence.md'),'utf8'),'retained evidence');
 assert.throws(()=>runtimeValues(root,{}),/uninstalled/);
});
test('managed Ghidra accepts a retained profile alias but rejects an installation redirected outside it',async t=>{
 const root=await temporary(t),profile=join(root,'profile'),alias=join(root,'profile-alias'),id='a'.repeat(64),home=join(profile,'runtime/installations',id,'ghidra');
 await mkdir(home,{recursive:true});await symlink(profile,alias,process.platform==='win32'?'junction':'dir');
 const selected={schema:1,mode:'managed',id,ghidraHome:join(alias,'runtime/installations',id,'ghidra'),java:join(alias,'runtime/installations',id,'jdk/bin/java'),fingerprint:'b'.repeat(64),selectedAt:'now'};
 await runtimeWrite(join(profile,'runtime/selection.json'),selected);await runtimeWrite(join(profile,'runtime/installations',id,'ready.json'),{});
 assert.deepEqual(runtimeSelection(profile),selected);assert.deepEqual(runtimeSelection(alias),selected);assert.equal(runtimeValues(profile,{}).ghidraHome,selected.ghidraHome);
 const outside=join(root,'outside');await mkdir(outside);await rm(home,{recursive:true});await symlink(outside,home,process.platform==='win32'?'junction':'dir');
 assert.throws(()=>runtimeSelection(profile),/outside/);await rm(home,{recursive:true});
 await runtimeWrite(join(profile,'runtime/selection.json'),{...selected,uninstalledAt:'later'});assert.equal(runtimeSelection(profile)?.uninstalledAt,'later');assert.throws(()=>runtimeValues(profile,{}),/uninstalled/);
});

test('runtime replacement refuses a live context before acquisition and never signals its PID',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]}),app=f.createApplication(runtime=>createInsightCli({runtime}));
 await runtimeWrite(join(f.appArguments.AppDataDirectory,'workspace/ghidra-native/context/c/r/process.json'),{pid:process.pid,kind:'context',context:'c',target:'t',tokenSecret:'fixture'});
 for(const command of [['ghidra','install','--offline'],['ghidra','uninstall']]){const result=await f.run(app,[...command,'--json']);assert.notEqual(result.exitCode,0);assert.equal(JSON.parse(result.stderr).error.code,'coordinator.busy');}
 await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'runtime')));
});

test('orphan probe cleanup never signals a process whose authenticated identity differs',async t=>{
 const root=await temporary(t);await runtimeWrite(join(root,'server/local.json'),{pid:process.pid,instance:'owned-fixture',port:22000,identityPort:22003,tokenSecret:'fixture-token'});
 const context={secrets:{require:async()=> 'owned-test-token'},fetch:async()=>new Response(JSON.stringify({pid:process.pid+1,instance:'owned-fixture',port:22000}))} as any;
 await assert.rejects(stopLocalServer(root,context),/no longer belongs/);assert.equal(JSON.parse(await readFile(join(root,'server/local.json'),'utf8')).pid,process.pid);
});

test('stopping the local server preserves automatic startup; explicit disconnect disables it',async t=>{
 const root=await temporary(t);await runtimeWrite(join(root,'server/connection.json'),{enabled:true});
 const server=new GhidraServer(root,{} as any,{profile:{values:{}}} as any);
 assert.equal((await server.administration('stop',{})).connected,false);assert.equal(JSON.parse(await readFile(join(root,'server/connection.json'),'utf8')).enabled,true);
 await server.administration('disconnect',{});assert.equal(JSON.parse(await readFile(join(root,'server/connection.json'),'utf8')).enabled,false);
});

function zipFile(name:string,body:string,mode=0o100755){
 const filename=Buffer.from(name),data=Buffer.from(body),local=Buffer.alloc(30),central=Buffer.alloc(46),end=Buffer.alloc(22),crc=crc32(data);
 local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(filename.length,26);
 central.writeUInt32LE(0x02014b50);central.writeUInt16LE(3*256+20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(crc,16);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);central.writeUInt16LE(filename.length,28);central.writeUInt32LE((mode*65536)>>>0,38);
 end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+filename.length,12);end.writeUInt32LE(local.length+filename.length+data.length,16);
 return Buffer.concat([local,filename,data,central,filename,end]);
}
test('portable zip extraction preserves native executable modes and refuses links or traversal',async t=>{
 const root=await temporary(t),file=join(root,'fixture.zip');await writeFile(file,zipFile('sdk/bin/tool','native'));await extractArchive(file,join(root,'valid'),'zip');assert.equal(await readFile(join(root,'valid/sdk/bin/tool'),'utf8'),'native');
 if(process.platform!=='win32')assert.ok((await stat(join(root,'valid/sdk/bin/tool'))).mode&0o100);
 for(const [name,mode]of [['../escape',0o100644],['sdk/link',0o120777]] as const){await writeFile(file,zipFile(name,'../../escape',mode));await assert.rejects(extractArchive(file,join(root,'invalid-'+mode),'zip'));}
 await assert.rejects(stat(join(root,'escape')));
});

test('vendor-only acquisition is explicit, pinned and cacheable without an implicit mirror fallback',async t=>{
 const {createHash}=await import('node:crypto');const {catalogArtifact}=await import('../src/tool-runtime/catalog.js');
 const root=await mkdtemp(join(tmpdir(),'vendor-cache-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const bytes=Buffer.from('owned vendor fixture'),artifact={...catalogArtifact('477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'),size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
 assert.equal(artifact.delivery?.publisher,'Microsoft');assert.equal(artifact.url,'https://download.sysinternals.com/files/ProcessMonitor.zip');
 let requests=0;const fetcher=(async(url:string)=>{requests++;assert.equal(url,artifact.url);return new Response(bytes);}) as typeof fetch,signal=new AbortController().signal;
 await assert.rejects(cacheArtifact(artifact,root,fetcher,signal),/explicit vendor download/);assert.equal(requests,0);
 const path=await cacheArtifact(artifact,root,fetcher,signal,false,true);assert.equal(requests,1);assert.equal(await fileSha256(path),artifact.sha256);
 assert.equal(await cacheArtifact(artifact,root,fetcher,signal,true),path);assert.equal(requests,1);
 await writeFile(path,'corrupt');await assert.rejects(cacheArtifact(artifact,root,fetcher,signal,false,true),/Cached runtime archive/);assert.equal(requests,1);
 const other=await mkdtemp(join(tmpdir(),'vendor-mismatch-'));t.after(()=>rm(other,{recursive:true,force:true}));
 await assert.rejects(cacheArtifact({...artifact,sha256:'f'.repeat(64)},other,fetcher,signal,false,true),/pinned SHA256/);assert.equal(requests,2);
});

test('runtime cleanup accepts a proven alias and rejects an inner validation-stage escape',async t=>{
 const {RuntimeManager}=await import('../src/runtime-manager.js'),root=await temporary(t),profile=join(root,'profile'),alias=join(root,'alias'),id='a'.repeat(8)+'-aaaa-aaaa-aaaa-'+ 'a'.repeat(12);
 await mkdir(profile);await symlink(profile,alias,process.platform==='win32'?'junction':'dir');
 const context={appArguments:{AppDataDirectory:profile},profile:{name:'default',values:{analysisDirectory:alias}}} as any,manager=new RuntimeManager(context) as any;
 const stage=join(profile,'runtime/stages',id),validation=join(stage,'validation');await runtimeWrite(join(validation,'server/local.json'),{phase:'seeded'});
 await manager.cleanupProbes();
 await rm(validation,{recursive:true});const outside=join(root,'outside');await runtimeWrite(join(outside,'server/local.json'),{phase:'seeded'});await symlink(outside,validation,process.platform==='win32'?'junction':'dir');
 await assert.rejects(manager.cleanupProbes(),/outside its owned storage/);
});
