import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rename,rm} from 'node:fs/promises';
import {join,delimiter,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {nativeHelpers,moduleJars,packagedMcpJar,nativeJvmDirectories,type NativeInputs} from '../src/native-inputs.js';
const delay=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const run=promisify(execFile),home=process.env.INSIGHT_TEST_GHIDRA_HOME,java=process.env.INSIGHT_TEST_JAVA;

test('native first import honors explicit analysis and persists real monitor messages/counters/cancellation',{skip:!home||!java,timeout:180000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'insight native-\u00e9 '));t.after(()=>rm(root,{recursive:true,force:true}));
 const jars=[packagedMcpJar,...await moduleJars(home!)];
 const inputs:NativeInputs={java:java!,ghidraHome:home!,mcpJar:packagedMcpJar,jars,classpath:jars.join(delimiter),ghidraVersion:'12.1.2',fingerprint:'native-progress-fixture',debuggerWheels:[]};
 const classes=await nativeHelpers(root,inputs),cp=classes+delimiter+inputs.classpath;
 const probe=join(root,'ProgressProbe.java');await writeFile(probe,`import java.nio.file.*; class ProgressProbe {public static void main(String[] a)throws Exception{try(var p=new InsightImportProgress(Path.of(a[0]),a[1])){p.phase("analysis");p.setMessage("Fixture analyzer");p.initialize(100);p.incrementProgress(7);Thread.sleep(2200);p.cancel();p.state(p.isCancelled()?"cancelled":"failed");}}}`);
 await run(join(dirname(java!),'javac'+(process.platform==='win32'?'.exe':'')),['-proc:none','-cp',cp,'-d',root,probe]);
 const failureProbe=join(root,'ProgressFailureProbe.java');await writeFile(failureProbe,`import java.nio.file.*; class ProgressFailureProbe {public static void main(String[] a)throws Exception{Path root=Path.of(a[0]),file=root.resolve("progress.json"),retained=root.resolve("retained-progress.json");try(var p=new InsightImportProgress(root,a[1])){p.phase("analysis");Files.move(file,retained);Files.createDirectory(file);Thread.sleep(2600);Files.delete(file);Files.move(retained,file);p.state("prepared");}}}`);
 await run(join(dirname(java!),'javac'+(process.platform==='win32'?'.exe':'')),['-proc:none','-cp',cp,'-d',root,failureProbe]);
 const transientRoot=join(root,'transient-observation-failure');await mkdir(transientRoot);
 await run(java!,['-cp',root+delimiter+cp,'ProgressFailureProbe',transientRoot,'t_'+'a'.repeat(32)]);
 assert.equal(JSON.parse(await readFile(join(transientRoot,'progress.json'),'utf8')).state,'prepared');
 const monitorRoot=join(root,'monitor');await mkdir(monitorRoot);const target='t_'+'a'.repeat(32);
 await run(java!,['-cp',root+delimiter+cp,'ProgressProbe',monitorRoot,target]);
 const monitor=JSON.parse(await readFile(join(monitorRoot,'progress.json'),'utf8'));
 assert.equal(monitor.message,'Fixture analyzer');assert.equal(monitor.completed,7);assert.equal(monitor.total,100);assert.equal(monitor.state,'cancelled');assert.equal(monitor.indeterminate,false);
 for(const {analyze,blockProgress} of [{analyze:false,blockProgress:false},{analyze:true,blockProgress:false},{analyze:true,blockProgress:true}]){
  const at=join(root,String(analyze)+(blockProgress?'-unwritable-progress':''));await mkdir(at);const input=join(at,'fixture.bin');const bytes=Buffer.from('554889e5b82a0000005dc3','hex');await writeFile(input,bytes);
  await writeFile(join(at,'intent.json'),JSON.stringify({schema:1,id:'00000000-0000-0000-0000-000000000000',target,sha256:createHash('sha256').update(bytes).digest('hex'),input,settings:{autoAnalyze:analyze,loader:'BinaryLoader',language:'x86:LE:64:default',compilerSpec:'windows',loaderOptions:{'Base Address':'0x10000','File Offset':'0x0','Length':'0xb'}}}));
  const previous={schema:1,target,phase:'analysis',state:'timed_out',pid:2147483647,startedAt:'2026-10-26T00:00:00Z',updatedAt:'2026-10-26T01:00:00Z',message:'Previous analyzer',completed:7,total:23,indeterminate:false};await writeFile(join(at,'progress.json'),JSON.stringify(previous));
  const execution=run(java!,['-Djava.awt.headless=true','-Dghidra.home='+home!,...nativeJvmDirectories(at),'-cp',cp,'InsightInitialImport',at],{timeout:60000,maxBuffer:1024*1024}).then(result=>({result}),error=>({error}));
  if(blockProgress){
   try{
    const deadline=Date.now()+15000;let current;
    while(Date.now()<deadline){try{current=JSON.parse(await readFile(join(at,'progress.json'),'utf8'));if(typeof current.attempt==='string')break;}catch{}await delay(10);}
    assert.equal(typeof current?.attempt,'string','Importer did not establish its observation before the I/O fault');
    // A directory blocks atomic file replacement on every platform, without touching import receipts.
    await rename(join(at,'progress.json'),join(at,'retained-observation.json'));await mkdir(join(at,'progress.json'));
   }catch(error){await execution;throw error;}
  }
  const outcome=await execution;if('error' in outcome)throw outcome.error;const result=outcome.result;
  assert.deepEqual(JSON.parse(result.stdout),{state:'prepared'});const receipt=JSON.parse(await readFile(join(at,'import.json'),'utf8'));
  assert.equal(receipt.metadata.auto_analyzed,analyze);assert.equal(createHash('sha256').update(await readFile(join(at,receipt.snapshot))).digest('hex'),receipt.snapshotSha256);
  if(blockProgress){assert.match(result.stderr,/progress is unavailable/);assert.equal(JSON.parse(await readFile(join(at,'retained-observation.json'),'utf8')).attempt,receipt.snapshot);}
  else {const observed=JSON.parse(await readFile(join(at,'progress.json'),'utf8'));assert.equal(observed.state,'prepared');assert.equal(observed.attempt,receipt.snapshot);}
  const history=(await readdir(at)).filter(name=>/^progress-history-[a-f0-9-]{36}\.json$/.test(name));assert.equal(history.length,1);assert.deepEqual(JSON.parse(await readFile(join(at,history[0]!),'utf8')),previous);
 }
});
