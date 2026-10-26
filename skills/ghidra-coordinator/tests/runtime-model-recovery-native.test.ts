import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join,dirname,delimiter} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {promisify} from 'node:util';
import {execFile} from 'node:child_process';
import type {CommandContext} from '@eyeauras/cli-factory';
import {nativeHelpers,moduleJars,packagedMcpJar,nativeJvmDirectories,type NativeInputs} from '../src/native-inputs.js';
import {javaClasspathArguments} from '../src/tool-runtime/java-arguments.js';
import {Workspace} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import {GhidraServer} from '../src/server.js';
import {initialRoot} from '../src/initial-model.js';
const exec=promisify(execFile),home=process.env.INSIGHT_TEST_GHIDRA_HOME,java=process.env.INSIGHT_TEST_JAVA;

test('disposable native repository: upgrade absence, concurrent preparation, R3 annotations, independent readback and ownership/race guards',
 {skip:!home||!java,timeout:240000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'insight-upgrade-native-')),secrets=new Map<string,string>();
 const c={appArguments:{AppDataDirectory:root},profile:{name:'fixture',values:{}},environment:process.env,signal:new AbortController().signal,fetch:globalThis.fetch,progress:()=>{},
  secrets:{get:async(k:string)=>secrets.get(k),set:async(k:string,v:string)=>{secrets.set(k,v);},require:async(k:string)=>{assert.ok(secrets.has(k));return secrets.get(k)!;}}} as unknown as CommandContext;
 const jars=[packagedMcpJar,...await moduleJars(home!)],fingerprint='b'.repeat(64);
 const inputs:NativeInputs={java:java!,ghidraHome:home!,mcpJar:packagedMcpJar,jars,classpath:jars.join(delimiter),ghidraVersion:'12.1.2',fingerprint,debuggerWheels:[]};
 const server=new GhidraServer(join(root,'owned-server'),inputs,c),workspace=new Workspace(join(root,'workspace'),'fixture');
 let passed=false;t.after(async()=>{await server.stop();workspace.close();if(passed)await rm(root,{recursive:true,force:true});else console.error('Retained disposable fixture diagnostics:',root);});
 const binding=await server.ensure(),classes=await nativeHelpers(join(root,'owned-server'),inputs),cp=classes+delimiter+inputs.classpath;
 async function run(main:string,args:string[],role:'reader'|'publisher'='reader'){
  const call=join(root,'calls',randomUUID());await mkdir(call,{recursive:true});
  const argv=['-Djava.awt.headless=true','-Dghidra.home='+home!,...nativeJvmDirectories(call),'-cp',root+delimiter+cp,main,...args];
  return exec(java!,await javaClasspathArguments(call,'ghidra',java!,argv),{env:{...process.env,...await server.credentials(binding,role)},windowsHide:true,timeout:60000,maxBuffer:1024*1024});
 }
 const helper=join(root,'RecoveryFixture.java');await writeFile(helper,`package db;
 import java.nio.file.*;import ghidra.GhidraApplicationLayout;import ghidra.framework.*;import ghidra.framework.data.OpenMode;import ghidra.framework.store.db.PackedDatabase;import ghidra.program.database.ProgramDB;import ghidra.util.task.TaskMonitor;
 class RecoveryFixture{public static void main(String[] a)throws Exception{Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
 if(a[0].equals("checkout")||a[0].equals("release")){var manager=new com.xebyte.headless.GhidraServerManager();manager.connect();var r=manager.server().getRepository(a[1]);r.connect();if(a[0].equals("checkout"))System.out.println("CHECKOUT "+r.checkout("/",a[2],ghidra.framework.store.CheckoutType.EXCLUSIVE,"disposable fixture").getCheckoutId());else r.terminateCheckout("/",a[2],Long.parseLong(a[3]),false);System.exit(0);}
 var db=PackedDatabase.getPackedDatabase(Path.of(a[1]).toFile(),false,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);Object owner=new Object();var p=new ProgramDB(db,OpenMode.UPDATE,TaskMonitor.DUMMY,owner);
 try{int tx=p.startTransaction("Fixture annotation");try{p.getListing().setComment(p.getMinAddress(),ghidra.program.model.listing.CodeUnit.EOL_COMMENT,a[3]);}finally{p.endTransaction(tx,true);}p.saveToPackedFile(Path.of(a[2]).toFile(),TaskMonitor.DUMMY);}finally{p.release(owner);}System.exit(0);}}`);
 const javac=join(dirname(java!),'javac'+(process.platform==='win32'?'.exe':'')),compile=join(root,'compile');await mkdir(compile);
 await exec(javac,await javaClasspathArguments(compile,'ghidra',javac,['-proc:none','-cp',cp,'-d',root,helper]),{windowsHide:true});
 const input=join(root,'fixture.bin'),bytes=Buffer.from('554889e5b82a0000005dc3','hex');await writeFile(input,bytes);const target=await workspace.importTarget(input);
 const settings={autoAnalyze:false,loader:'BinaryLoader',language:'x86:LE:64:default',compilerSpec:'windows',loaderOptions:{'Base Address':'0x10000','File Offset':'0x0','Length':'0xb'}};
 const a=workspace.reserveOpen(target.id,'new',settings,'agent-A'),b=workspace.reserveOpen(target.id,'new',settings,'agent-B');workspace.beginModelInitialization(target.id);
 const at=initialRoot(workspace,target.id);await mkdir(at,{recursive:true});const intent={schema:1,id:randomUUID(),target:target.id,sha256:target.binarySha256,input:await workspace.artifacts.verify(target.input),settings,
  origin:binding.origin,repository:binding.repository,readerUser:binding.readerUser,publisherUser:binding.publisherUser,runtimeFingerprint:'a'.repeat(64)};
 const original=JSON.stringify(intent);await writeFile(join(at,'intent.json'),original);
 await writeFile(join(at,'import.json'),JSON.stringify({phase:'importing',pid:process.pid}));assert.equal((await server.initialRecovery(binding,at,fingerprint)).state,'unknown','Live old worker blocks');
 await writeFile(join(at,'import.json'),JSON.stringify({phase:'importing',pid:2147483647}));
 await writeFile(join(at,'publication.json'),JSON.stringify({phase:'promote_intent',pid:2147483647}));assert.equal((await server.initialRecovery(binding,at,fingerprint)).state,'unknown','Unknown publication blocks absent path');await rm(join(at,'publication.json'));
 const prepared=await server.initialRecovery(binding,at,fingerprint);assert.equal(prepared.state,'absent');const next=join(at,String(prepared.root)),nextIntent=await readFile(join(next,'intent.json'),'utf8');
 assert.equal((await server.initialRecovery(binding,at,fingerprint)).root,prepared.root);assert.equal(await readFile(join(next,'intent.json'),'utf8'),nextIntent);
 const settled=await Promise.allSettled([server.initialImport(next),server.initialImport(next)]);for(const result of settled)if(result.status==='rejected')throw result.reason;
 const concurrent=settled.map(r=>(r as PromiseFulfilledResult<Record<string,unknown>>).value);assert.ok(concurrent.some(r=>r.state==='prepared'));assert.ok(concurrent.every(r=>['busy','prepared'].includes(String(r.state))));
 for(const operation of ['stage','verify-stage','promote','verify'] as const)assert.equal((await server.initialPublication(binding,next,operation)).snapshotBuffersVerified,true);
 const imported=JSON.parse(await readFile(join(next,'import.json'),'utf8'));let snapshot=join(next,imported.snapshot);
 for(let revision=2;revision<=3;revision++){
  const changed=join(root,'R'+revision+'.gzf');await run('db.RecoveryFixture',['edit',snapshot,changed,'annotation R'+revision]);
  const id='q_'+randomUUID(),journal=join(root,'publication-'+id+'.json');assert.equal((await server.publish(binding,'/'+target.id+'.bin',changed,revision-1,id,journal,target.binarySha256)).version,revision);snapshot=changed;
 }
 const candidate=await server.initialRecovery(binding,at,fingerprint);assert.equal(candidate.state,'candidate');assert.equal(candidate.version,3);
 const held=await run('db.RecoveryFixture',['checkout',binding.repository,target.id+'.bin'],'publisher'),checkout=/CHECKOUT (\d+)/.exec(held.stdout)![1]!;
 assert.equal((await server.initialRecovery(binding,at,fingerprint,String(candidate.receipt))).state,'unknown','Live checkout blocks readback');
 await run('db.RecoveryFixture',['release',binding.repository,target.id+'.bin',checkout],'publisher');
 const changed=join(root,'R4.gzf');await run('db.RecoveryFixture',['edit',snapshot,changed,'annotation R4']);const id='q_'+randomUUID();
 await server.publish(binding,'/'+target.id+'.bin',changed,3,id,join(root,'publication-'+id+'.json'),target.binarySha256);
 assert.equal((await server.initialRecovery(binding,at,fingerprint,String(candidate.receipt))).state,'unknown','Revision advance blocks stale candidate');
 const privateSnapshot=await workspace.captureSnapshot(snapshot);workspace.saveContext(b.context,0,{workingSnapshot:privateSnapshot,baseSnapshot:privateSnapshot,baseRevision:3,scalars:[{address:'10000',field:'comment.eol',original:'annotation R3',local:'private edit'}]});const pending=workspace.context(b.context);
 const backend=new GhidraContexts(workspace,inputs,c,undefined,undefined,server);assert.deepEqual(await Promise.all([backend.recoverModel(target.id),backend.fork(c).recoverModel(target.id)]),[true,true]);
 assert.equal(workspace.model(target.id).sharedRevision,4);assert.deepEqual(workspace.context(b.context),pending);assert.equal(await readFile(join(at,'intent.json'),'utf8'),original);
 const selectors=join(root,'comments.json');await writeFile(selectors,JSON.stringify([{address:'10000',field:'comment.eol'}]));const observed=await server.fields(await workspace.artifacts.verify(workspace.model(target.id).sharedSnapshot!),selectors);
 assert.equal((observed.fields as Record<string,{value:string}>)['10000@comment.eol']!.value,'annotation R4');
 const status=await server.programStatus(binding,'/'+target.id+'.bin');assert.equal(status.version,4);assert.deepEqual(status.checkouts,[]);passed=true;
});
