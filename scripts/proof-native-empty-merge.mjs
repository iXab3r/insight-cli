// Opt-in installed-package regression for #125. All writes use a fresh disposable fixture.
// Run only as part of the host's serialized native acceptance, never from npm test.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,readdir,realpath,stat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const o={};
for(let i=2;i<process.argv.length;i++){
 const key=process.argv[i];
 if(key==='--ack-disposable')o.ack=true;
 else{
  assert.ok(['--package-root','--archive','--source-revision','--ghidra-home','--java','--output-base'].includes(key));
  o[key.slice(2)]=process.argv[++i];
 }
}
assert.equal(o.ack,true,'Explicit --ack-disposable is required');
assert.match(o['source-revision']??'',/^[a-f0-9]{40}$/);
for(const key of ['package-root','archive','ghidra-home','java','output-base'])o[key]=await realpath(resolve(o[key]));
assert.ok(!Object.keys(process.env).some(k=>/^(CI|TEAMCITY_VERSION|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
const output=await mkdtemp(join(o['output-base'],'native-empty-merge-'));
const load=path=>import(pathToFileURL(path).href),hash=bytes=>createHash('sha256').update(bytes).digest('hex'),pkg=o['package-root'];
const manifest=JSON.parse(await readFile(join(pkg,'package.json'),'utf8'));
assert.equal(manifest.name,'@eyeauras/insight-cli');
const {createCliFixture}=await load(join(pkg,'node_modules/@eyeauras/cli-factory/dist/src/testing.js'));
const {ProfileSecrets}=await load(join(pkg,'node_modules/@eyeauras/cli-factory/dist/src/index.js'));
const {createInsightCli}=await load(join(pkg,'dist/src/cli.js'));
const {Workspace}=await load(join(pkg,'dist/src/workspace.js'));
const {GhidraServer}=await load(join(pkg,'dist/src/server.js'));
const {HttpBridge}=await load(join(pkg,'dist/src/transport.js'));
const {nativeInputs}=await load(join(pkg,'dist/src/native-inputs.js'));
const values={analysisDirectory:null,java:o.java,ghidraHome:o['ghidra-home'],maxContexts:4},inputs=await nativeInputs(values);
const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
const app=f.createApplication(runtime=>createInsightCli({runtime})),ws=join(f.appArguments.AppDataDirectory,'workspace'),events=[],checks={};
const c={appArguments:f.appArguments,profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,
 fetch,secrets:new ProfileSecrets(f.secretStore,'insight-cli','default'),progress(){}};
let workspace,server,binding,success=false,failure;
const select=scope=>['--session',scope.session,'--target',scope.target],context=scope=>workspace.context(scope);
async function cli(args,allowFailure=false){
 const result=await f.run(app,[...args,'--json']);events.push({args,...result});
 await writeFile(join(output,'events.json'),JSON.stringify(events,null,2));
 console.log(JSON.stringify({command:args.slice(0,3),exitCode:result.exitCode}));
 if(allowFailure)return result;
 assert.equal(result.exitCode,0,result.stderr);return JSON.parse(result.stdout);
}
async function latest(scope){
 return server.nativeRead(binding,{operation:'latest',path:'/'+scope.target+'.bin',sourceSha:workspace.target(scope.target).binarySha256});
}
async function fields(scope,version,fingerprint,addresses){
 const result=await server.nativeRead(binding,{operation:'fields',path:'/'+scope.target+'.bin',sourceSha:workspace.target(scope.target).binarySha256,
  version,fingerprint,selectors:addresses.map(address=>({address,field:'comment.eol'}))});
 return addresses.map(address=>result.fields[address+'@comment.eol'].value);
}
async function edit(scope,address,text){
 // Native edits deliberately bypass facade mutation diagnostics; zero diagnostics cannot mean no work.
 const peer=JSON.parse(await readFile(join(context(scope).nativeCheckout.root,'process.json'),'utf8'));
 const code=`import ghidra.app.script.GhidraScript;public class NativeNoWorkEdit extends GhidraScript {
  public void run()throws Exception{int tx=currentProgram.startTransaction("Disposable native edit");
   try{currentProgram.getListing().setComment(toAddr(0x${address}),ghidra.program.model.listing.CodeUnit.EOL_COMMENT,${JSON.stringify(text)});}
   finally{currentProgram.endTransaction(tx,true);}}}`;
 const result=await new HttpBridge(peer.endpoint,fetch,undefined,await c.secrets.require(peer.tokenSecret),120000)
  .call('/run_script_inline',{program:peer.program,code});
 assert.equal(result.success,true);assert.equal(context(scope).scalars.length+context(scope).complexChanges.length,0);
 await cli(['ghidra','save',...select(scope)]);
}
async function updateJournal(scope,checkout,caller){
 const request=workspace.scopedRequest(scope,caller);assert.ok(request);
 return JSON.parse(await readFile(join(checkout.root,'operations',request.id+'-update.json'),'utf8'));
}
console.log(JSON.stringify({event:'owned_native_empty_merge_fixture',root:f.root,output,version:manifest.version}));
try{
 const input=join(f.root,'fixture.bin'),bytes=Buffer.alloc(512,0xc3);await writeFile(input,bytes);
 const a=await cli(['ghidra','open',input,'--session','new','--loader','ghidra.app.util.opinion.BinaryLoader','--language','x86:LE:64:default',
  '--image-base','1000','--loader-options','{"Base Address":"0"}']);
 workspace=new Workspace(ws,'default');server=new GhidraServer(ws,inputs,c);binding=await server.ensure();assert.equal((await latest(a)).version,1);
 await cli(['ghidra','save',...select(a)]);
 const explicitArgs=['ghidra','merge',...select(a),'--request-id','empty-explicit'],explicit=await cli(explicitArgs);
 assert.equal(explicit.state,'empty');assert.equal(explicit.sharedRevision,'R1');assert.equal(context(a).nativeCheckout.state,'dropped');
 assert.deepEqual(await cli(explicitArgs),explicit);assert.equal((await latest(a)).version,1);checks.untouchedExplicitSaveMerge=true;
 await cli(['ghidra','open',...select(a)]);
 await cli(['ghidra','sync-policy','set',...select(a),'--publish','after-save','--refresh','manual']);
 const autoArgs=['ghidra','save',...select(a),'--request-id','empty-after-save'],auto=await cli(autoArgs);
 assert.equal(auto.automatic.publication.state,'empty');assert.equal(auto.automatic.publication.sharedRevision,'R1');
 assert.equal(context(a).nativeCheckout.state,'dropped');assert.deepEqual(await cli(autoArgs),auto);assert.equal((await latest(a)).version,1);
 checks.untouchedAfterSave=true;
 await cli(['ghidra','sync-policy','set',...select(a),'--publish','manual','--refresh','manual']);await cli(['ghidra','open',...select(a)]);
 const b=await cli(['ghidra','open','--target',a.target,'--session','new']),beforeB=context(b).nativeCheckout;
 await edit(a,'1000','INCOMING_NO_LOCAL_WORK');
 assert.equal((await cli(['ghidra','merge',...select(a),'--request-id','real-native-edit'])).sharedRevision,'R2');
 const published=await latest(a);assert.equal(published.version,2);checks.realEditWithZeroDiagnosticsPublished=true;
 assert.equal(context(b).nativeCheckout.checkoutId,beforeB.checkoutId);assert.equal(context(b).nativeCheckout.baseVersion,1);
 assert.equal(context(b).scalars.length+context(b).complexChanges.length,0);
 const incomingArgs=['ghidra','merge',...select(b),'--request-id','empty-after-incoming'],incoming=await cli(incomingArgs);
 assert.equal(incoming.state,'empty');assert.equal(incoming.sharedRevision,'R2');assert.equal(context(b).nativeCheckout.state,'dropped');
 const update=await updateJournal(b,beforeB,'empty-after-incoming');
 assert.equal(update.baseVersion,1);assert.equal(update.headVersion,2);assert.equal(update.backupExpected,true);
 assert.equal(update.result.state,'updated');assert.equal(update.result.checkoutId,beforeB.checkoutId);assert.equal(update.result.baseVersion,2);
 assert.equal(update.result.nativeMergeInvocations,1,'Must exercise the dirty native resolver path, not only clean Update');
 assert.equal(update.result.modified,false);assert.equal(update.result.saved.fingerprint,published.fingerprint);
 const keep=update.result.disposableBackups[b.target+'.bin.keep'];assert.equal(keep.schema,1);assert.match(keep.fingerprint,/^[a-f0-9]{64}$/);
 assert.deepEqual(await cli(incomingArgs),incoming);assert.deepEqual(await updateJournal(b,beforeB,'empty-after-incoming'),update);
 const after=await latest(b);assert.equal(after.version,2);assert.equal(after.fingerprint,published.fingerprint);assert.equal(after.checkouts.length,0);
 assert.deepEqual(await fields(b,2,after.fingerprint,['1000']),['INCOMING_NO_LOCAL_WORK']);
 assert.equal(await stat(join(beforeB.root,'view.rep')).catch(e=>{assert.equal(e.code,'ENOENT');return undefined;}),undefined);
 checks.incomingNativeNoopSavedCleanAtR2=true;checks.exactReadbackAndEmptyCleanup=true;checks.completedRequestDidNotReplay=true;

 // A genuine private contribution on the same native Update path must stay dirty and publish.
 await cli(['ghidra','open',...select(a)]);await cli(['ghidra','open',...select(b)]);
 const dirtyB=context(b).nativeCheckout;
 await edit(a,'1001','INCOMING_DISJOINT');await edit(b,'1002','PRIVATE_ZERO_DIAGNOSTICS');
 assert.equal((await cli(['ghidra','merge',...select(a)])).sharedRevision,'R3');
 const dirty=await cli(['ghidra','merge',...select(b),'--request-id','dirty-zero-diagnostics']);
 assert.equal(dirty.state,'merged');assert.equal(dirty.sharedRevision,'R4');assert.equal(dirty.applied,0);
 const dirtyUpdate=await updateJournal(b,dirtyB,'dirty-zero-diagnostics');
 assert.equal(dirtyUpdate.result.checkoutId,dirtyB.checkoutId);assert.equal(dirtyUpdate.result.baseVersion,3);
 assert.equal(dirtyUpdate.result.modified,true);assert.equal(dirtyUpdate.result.nativeMergeInvocations,1);
 const combined=await latest(b);assert.equal(combined.version,4);
 assert.deepEqual(await fields(b,4,combined.fingerprint,['1000','1001','1002']),['INCOMING_NO_LOCAL_WORK','INCOMING_DISJOINT','PRIVATE_ZERO_DIAGNOSTICS']);
 checks.dirtyZeroDiagnosticContributionRetainedAndPublished=true;

 // Native conflict refusal must retain the original private checkout and its saved buffers.
 await cli(['ghidra','open',...select(a)]);await cli(['ghidra','open',...select(b)]);
 await edit(a,'1003','SHARED_CONFLICT');await edit(b,'1003','PRIVATE_CONFLICT');const conflictB=context(b).nativeCheckout;
 assert.equal((await cli(['ghidra','merge',...select(a)])).sharedRevision,'R5');
 const conflictArgs=['ghidra','merge',...select(b),'--request-id','retained-native-conflict'];
 assert.notEqual((await cli(conflictArgs,true)).exitCode,0);
 const conflict=await updateJournal(b,conflictB,'retained-native-conflict');
 assert.equal(conflict.result.state,'conflict');assert.equal(conflict.result.baseVersion,4);assert.equal(conflict.result.checkoutId,conflictB.checkoutId);
 assert.deepEqual(conflict.result.saved,conflict.before);assert.equal(context(b).nativeCheckout.state,'active');
 assert.equal(context(b).nativeCheckout.baseVersion,4);assert.equal(context(b).nativeCheckout.checkoutId,conflictB.checkoutId);
 assert.equal((await cli(['ghidra','comments','get',...select(b),'--address','1003','--kind','eol'])).text,'PRIVATE_CONFLICT');
 const sharedConflict=await latest(b);assert.equal(sharedConflict.version,5);
 assert.deepEqual(await fields(b,5,sharedConflict.fingerprint,['1003']),['SHARED_CONFLICT']);
 assert.notEqual((await cli(conflictArgs,true)).exitCode,0);assert.deepEqual(await updateJournal(b,conflictB,'retained-native-conflict'),conflict);
 checks.nativeConflictPreservedCheckoutAndBuffers=true;
 let checkins=0;
 for(const scope of [a,b]){
  const parent=join(ws,'ghidra-native','context',context(scope).id);
  for(const root of await readdir(parent,{withFileTypes:true}))if(root.isDirectory()){
   let names;try{names=await readdir(join(parent,root.name,'operations'));}catch(e){if(e.code==='ENOENT')continue;throw e;}
   checkins+=names.filter(name=>name.endsWith('-checkin.json')).length;
  }
 }
 assert.equal(checkins,4,'Only real contributions create check-in journals; no-work/conflict attempts do not');
 assert.equal(hash(await readFile(input)),hash(bytes));checks.inputBytesPreserved=true;
 assert.equal((await nativeInputs(values)).fingerprint,inputs.fingerprint);checks.runtimeUnchanged=true;success=true;
}catch(error){failure={code:error.code??error.name,message:error.message};throw error;}
finally{
 workspace?.close();
 try{await app.dispose();await new GhidraServer(ws,inputs,c).stop();checks.cleanupCallsCompleted=true;}
 finally{
  const result={schema:1,success,scope:'Installed package API native no-op/dirty/conflicting incoming Update, native ancestry, request retries and independent readback',
   root:f.root,output,version:manifest.version,sourceRevisionArgument:o['source-revision'],archiveSha256:hash(await readFile(o.archive)),
   packageBuild:JSON.parse(await readFile(join(pkg,'.cli-package-build.json'),'utf8')),harnessSha256:hash(await readFile(new URL(import.meta.url))),
   runtimeFingerprint:inputs.fingerprint,checks,...(failure?{failure}:{}),limits:['Disposable raw x86 fixture','No global executable IPC coverage',
    'Conflicted private work is intentionally retained','Does not reconcile or retry previously unknown operations']};
  await writeFile(join(output,'result.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
 }
}
