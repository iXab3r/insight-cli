// Main CLI acceptance: real default backend; owned inputs/profile/server, no backend injection.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {ProfileSecrets,PlatformSecretStore} from '@eyeauras/cli-factory';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {nativeInputs} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {HttpBridge} from '../skills/ghidra-coordinator/dist/src/transport.js';
import {readFile,writeFile,readdir,mkdir,realpath,cp} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {runNpm} from './npm-command.mjs';
const options={};for(let i=2;i<process.argv.length;i++){
 const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;else if(arg==='--installed')options.installed=true;else if(arg==='--faults')options.faults=true;
 else{assert.ok(['--ghidra-home','--java','--output-base','--global-entry','--global-package'].includes(arg));options[arg.slice(2)]=process.argv[++i];}
}
if(options['global-entry']){assert.ok(options['global-package']);options.installed=true;}
assert.equal(options.ack,true);for(const key of ['ghidra-home','java','output-base'])assert.ok(options[key]);
assert.ok(!options.faults||options.installed,'Owner-kill acceptance requires the installed IPC path');
for(const key of ['ghidra-home','java','output-base']){options[key]=await realpath(resolve(options[key]));assert.ok(!options[key].toLowerCase().includes('ec2-native'));}
assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
process.env.TEMP=process.env.TMP=process.env.TMPDIR=options['output-base'];
const sourceRoot=resolve('skills/ghidra-coordinator'),hash=b=>createHash('sha256').update(b).digest('hex');
const sourceHashes={};
async function inventory(directory){for(const entry of await readdir(join(sourceRoot,directory),{withFileTypes:true})){const path=directory+'/'+entry.name;
 if(entry.isDirectory())await inventory(path);else if(entry.isFile()&&/\.(ts|java)$/.test(path))sourceHashes[path]=hash(await readFile(join(sourceRoot,path)));}}
await inventory('src');await inventory('references/native');sourceHashes['../scripts/proof-native-cli.mjs']=hash(await readFile(new URL('./proof-native-cli.mjs',import.meta.url)));
sourceHashes['../scripts/npm-command.mjs']=hash(await readFile(new URL('./npm-command.mjs',import.meta.url)));
const values={analysisDirectory:null,java:options.java,ghidraHome:options['ghidra-home'],maxContexts:4};
const runtimeBefore=await nativeInputs(values);
const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
console.log(JSON.stringify({event:'owned_main_cli_fixture',root:f.root}));await writeFile(join(f.root,'source-inventory.json'),JSON.stringify(sourceHashes,null,2));
let installation,installedEntry,packageSha256,installedSecrets;
const exec=promisify(execFile);
if(options['global-entry']){
 installedEntry=await realpath(resolve(options['global-entry']));assert.ok(!installedEntry.toLowerCase().includes('ec2-native'));
 installation=resolve(dirname(installedEntry),'../..');const pkg=JSON.parse(await readFile(join(installation,'package.json')));
 assert.equal(pkg.name,'@eyeauras/insight-cli');assert.equal(installedEntry,await realpath(join(installation,pkg.bin['insight-cli'])));
 assert.equal(pkg.version,JSON.parse(await readFile(join(sourceRoot,'package.json'))).version);
 packageSha256=hash(await readFile(options['global-package']));installedSecrets=new PlatformSecretStore(f.appArguments);
 for(const name of Object.keys(sourceHashes).filter(n=>n.startsWith('references/native/')))assert.equal(hash(await readFile(join(installation,name))),sourceHashes[name]);
 async function installedBuild(directory=''){for(const entry of await readdir(join(sourceRoot,'dist/src',directory),{withFileTypes:true})){const name=join(directory,entry.name);
  if(entry.isDirectory())await installedBuild(name);else if(name.endsWith('.js'))assert.equal(hash(await readFile(join(installation,'dist/src',name))),hash(await readFile(join(sourceRoot,'dist/src',name))),name);}}
 await installedBuild();
}else if(options.installed){
 installation=join(f.root,'installed');await mkdir(installation);await mkdir(join(installation,'artifacts'));
 const packed=JSON.parse((await runNpm(['pack','--offline','--ignore-scripts','--json','--workspace','@eyeauras/insight-cli','--pack-destination',join(installation,'artifacts')],{cwd:process.cwd()})).stdout)[0];
 packageSha256=hash(await readFile(join(installation,'artifacts',packed.filename)));
 const manifest=JSON.parse(await readFile('package.json')),lock=JSON.parse(await readFile('package-lock.json')),cliManifest=JSON.parse(await readFile(join(sourceRoot,'package.json')));
 const owned={name:'owned-native-cli-proof',version:'0.0.0',private:true,type:'module',files:['entry.mjs','fixture.json','.cli-package-build.json'],dependencies:{...manifest.dependencies,'@eyeauras/insight-cli':'file:artifacts/'+packed.filename},devDependencies:manifest.devDependencies};
 lock.name=owned.name;lock.version=owned.version;lock.packages['']=owned;
 for(const [path,item]of Object.entries(lock.packages))if(item.link||path.startsWith('skills/'))delete lock.packages[path];
 lock.packages['node_modules/@eyeauras/insight-cli']={version:cliManifest.version,resolved:owned.dependencies['@eyeauras/insight-cli'],integrity:'sha512-'+createHash('sha512').update(await readFile(join(installation,'artifacts',packed.filename))).digest('base64'),dependencies:cliManifest.dependencies,engines:cliManifest.engines,bin:cliManifest.bin,license:cliManifest.license};
 await writeFile(join(installation,'package.json'),JSON.stringify(owned));await writeFile(join(installation,'package-lock.json'),JSON.stringify(lock));await cp('vendor',join(installation,'vendor'),{recursive:true});
 await runNpm(['ci','--offline','--ignore-scripts','--no-audit','--no-fund'],{cwd:installation,timeout:60000,maxBuffer:262144});
 const config={appArguments:{AppName:'insight-cli',Profile:'default',Environment:{AppDomainDirectory:installation,ApplicationExecutablePath:join(installation,'entry.mjs'),EnvironmentAppData:join(f.root,'roaming'),EnvironmentLocalAppData:join(f.root,'local'),ProcessId:1}}};
 await writeFile(join(installation,'fixture.json'),JSON.stringify(config));installedEntry=join(installation,'entry.mjs');
 await writeFile(installedEntry,`import {readFileSync,appendFileSync} from 'node:fs';import {AppArguments,PlatformSecretStore} from '@eyeauras/cli-factory';import {runHosted} from '@eyeauras/cli-factory-ipc';import {createDefinition} from '@eyeauras/insight-cli';import {join} from 'node:path';
const config=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url))),appArguments=new AppArguments(config.appArguments),store=new PlatformSecretStore(appArguments);
const secretStore={get:(...a)=>store.get(...a),delete:(...a)=>store.delete(...a),set(service,account,value){appendFileSync(join(appArguments.AppDataDirectory,'fixture-secret-keys.jsonl'),JSON.stringify({service,account})+'\\n');return store.set(service,account,value);}};
process.exitCode=await runHosted({entryPoint:import.meta.url,createDefinition:()=>createDefinition({runtime:{appArguments,secretStore}})});`);
 const {writePackageBuildManifest}=await import('@eyeauras/cli-factory-ipc/build');await writePackageBuildManifest(installation);
 installedSecrets=new PlatformSecretStore(f.appArguments);
}
async function installedCommand(args){try{const result=await exec(process.execPath,[installedEntry,...(options['global-entry']?['--profile','default']:[]),...args],{
 cwd:options['global-entry']?f.root:installation,...(options['global-entry']?{env:{...process.env,APPDATA:join(f.root,'roaming'),LOCALAPPDATA:join(f.root,'local')}}:{}),windowsHide:true,timeout:600000,maxBuffer:4*1024*1024});return {exitCode:0,...result};}
 catch(error){return {exitCode:error.code??1,stdout:error.stdout??'',stderr:error.stderr??''};}}
const createApplication=()=>options.installed?{dispose:async()=>{const r=await installedCommand(['ipc-server','stop','--json']);assert.equal(r.exitCode,0,r.stderr);}}:f.createApplication(runtime=>createInsightCli({runtime}));
let app=createApplication();
const workspace=join(f.appArguments.AppDataDirectory,'workspace'),events=[];
const select=s=>['--session',s.session,'--target',s.target];
async function cli(args,expectedFailure=false){
 const value=options.installed?await installedCommand([...args,'--json']):await f.run(app,[...args,'--json']);const event={args,exitCode:value.exitCode,stdout:value.stdout,stderr:value.stderr};events.push(event);
 await writeFile(join(f.root,'cli-events.json'),JSON.stringify(events,null,2));
 console.log(JSON.stringify({event:'main_cli_step',command:args.slice(0,3),exitCode:value.exitCode}));
 if(expectedFailure){assert.notEqual(value.exitCode,0);return value;}
 assert.equal(value.exitCode,0,value.stderr);return JSON.parse(value.stdout);
}
function context(scope){const db=new DatabaseSync(join(workspace,'workspace.sqlite'),{readOnly:true});try{return JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(scope.session,scope.target).data);}finally{db.close();}}
const script=(s,code,id)=>cli(['ghidra','scripts','run-inline',...select(s),'--code',code,...(id?['--request-id',id]:[])]);
const baseCode=`import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;import ghidra.program.model.data.*;import ghidra.program.model.address.*;import ghidra.program.model.symbol.SourceType;
public class FixtureBaseline extends GhidraScript {public void run()throws Exception {int tx=currentProgram.startTransaction("Fixture baseline");boolean ok=false;try{
 for(int i=0;i<2;i++){var at=toAddr(0x1000+0x20*i);if(!currentProgram.getMemory().contains(at)||!currentProgram.getMemory().contains(at.add(15)))throw new IllegalStateException("Fixture function outside memory");currentProgram.getFunctionManager().createFunction("baseline_"+i,at,new AddressSet(at,at.add(15)),SourceType.USER_DEFINED);
 var type=new StructureDataType("Record"+i,0);type.add(IntegerDataType.dataType,"count",null);currentProgram.getDataTypeManager().addDataType(type,DataTypeConflictHandler.DEFAULT_HANDLER);
 var old=new StructureDataType("Obsolete"+i,0);old.add(IntegerDataType.dataType,"old",null);currentProgram.getDataTypeManager().addDataType(old,DataTypeConflictHandler.DEFAULT_HANDLER);}
 ok=true;}finally{currentProgram.endTransaction(tx,ok);}}}`;
const editCode=index=>`import ghidra.app.script.GhidraScript;import ghidra.program.model.listing.*;import ghidra.program.model.data.*;import ghidra.program.model.symbol.SourceType;
public class Worker${index} extends GhidraScript {public void run()throws Exception {
 if(System.getenv().keySet().stream().anyMatch(k->k.matches("(?i).*(SERVER_PASSWORD|PUBLISHER_PASSWORD).*")))throw new SecurityException("Publisher credential in worker");
 if(currentProgram.getDomainFile().getParent().getProjectData().getRepository().isConnected())throw new SecurityException("Worker connected to repository");
 int tx=currentProgram.startTransaction("Native worker ${index}");boolean ok=false;try{
 var f=currentProgram.getFunctionManager().getFunctionAt(toAddr(${0x1000+index*0x20}));f.setName("actor_${index}",SourceType.USER_DEFINED);f.setReturnType(${index?'DoubleDataType':'FloatDataType'}.dataType,SourceType.USER_DEFINED);
 var manager=currentProgram.getDataTypeManager();var type=(Structure)manager.getDataType("/Record${index}");type.add(LongLongDataType.dataType,"worker_${index}",null);
 var added=new StructureDataType("Created${index}",0);added.add(new PointerDataType(type,manager),"record",null);manager.addDataType(added,DataTypeConflictHandler.DEFAULT_HANDLER);
 manager.remove(manager.getDataType("/Obsolete${index}"),monitor);currentProgram.getListing().setComment(toAddr(${0x1000+index*0x20}),ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,"worker ${index}");
 ok=true;}finally{currentProgram.endTransaction(tx,ok);}}}`;
let receipt;
const cleanupContext={appArguments:f.appArguments,profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,fetch,
 secrets:new ProfileSecrets(installedSecrets??f.secretStore,'insight-cli','default'),progress(){}};
try{
 const input=join(f.root,'fixture.bin');await writeFile(input,Buffer.alloc(0x400,0xc3));
 const a=await cli(['ghidra','open',input,'--session','new','--loader','ghidra.app.util.opinion.BinaryLoader','--language','x86:LE:64:default','--image-base','1000','--loader-options','{"Base Address":"0"}']);
 await script(a,baseCode);assert.equal((await cli(['ghidra','merge',...select(a)])).sharedRevision,'R2');
 await cli(['ghidra','open',...select(a)]);
 const b=await cli(['ghidra','open',input,'--session','new']);
 const beforeA=context(a).nativeCheckout,beforeB=context(b).nativeCheckout;assert.notEqual(beforeA.checkoutId,beforeB.checkoutId);
 assert.equal(beforeA.baseVersion,2);assert.equal(beforeB.baseVersion,2);assert.notEqual(beforeA.root,beforeB.root);
 await Promise.all([script(a,editCode(0)),script(b,editCode(1))]);
 const savedB=context(b);await cli(['ghidra','close',...select(b)]);await cli(['ghidra','open',...select(b)]);
 assert.equal(context(b).nativeCheckout.root,beforeB.root);assert.equal(context(b).nativeCheckout.checkoutId,beforeB.checkoutId);
 assert.equal((await cli(['ghidra','functions','get',...select(b),'--address','1020'])).name,'actor_1');
 // Dispose/recreate the actual primary owner, not just its worker.
 await app.dispose();app=createApplication();
 await cli(['ghidra','open',...select(b)]);assert.equal(context(b).nativeCheckout.root,beforeB.root);
 assert.equal((await cli(['ghidra','merge',...select(a),'--request-id','publish-a'])).sharedRevision,'R3');
 assert.equal(context(a).nativeCheckout.state,'dropped');
 const updated=await cli(['ghidra','refresh',...select(b),'--request-id','update-b']);assert.equal(updated.sharedRevision,'R3');assert.equal(updated.nativeMergeInvocations,1);
 assert.equal(context(b).nativeCheckout.root,beforeB.root);assert.equal(context(b).nativeCheckout.checkoutId,beforeB.checkoutId);assert.equal(context(b).nativeCheckout.baseVersion,3);
 await cli(['ghidra','open',...select(b)]);
 const updatedFloat=await cli(['ghidra','functions','get',...select(b),'--address','1000']),updatedDouble=await cli(['ghidra','functions','get',...select(b),'--address','1020']);
 assert.equal(updatedFloat.name,'actor_0');assert.equal(updatedFloat.signature,'float actor_0(void)');
 assert.equal(updatedDouble.name,'actor_1');assert.equal(updatedDouble.signature,'double actor_1(void)');
 assert.equal((await cli(['ghidra','merge',...select(b),'--request-id','publish-b'])).sharedRevision,'R4');assert.equal(context(b).nativeCheckout.state,'dropped');
 const reader=await cli(['ghidra','open',input,'--session','new']);
 const publishedFloat=await cli(['ghidra','functions','get',...select(reader),'--address','1000']),publishedDouble=await cli(['ghidra','functions','get',...select(reader),'--address','1020']);
 assert.equal(publishedFloat.name,'actor_0');assert.equal(publishedFloat.signature,'float actor_0(void)');
 assert.equal(publishedDouble.name,'actor_1');assert.equal(publishedDouble.signature,'double actor_1(void)');
 const server=new GhidraServer(workspace,await nativeInputs(values),cleanupContext),binding=await server.ensure();
 const sourceSha=JSON.parse(await readFile(join(beforeA.root,'native-owner.json'))).sourceSha;
 const authoritative=await server.nativeRead(binding,{operation:'latest',path:'/'+a.target+'.bin',sourceSha});
 assert.equal(authoritative.state,'verified');assert.equal(authoritative.version,4);
 for(let i=0;i<2;i++)for(const [name,exists]of [['Created'+i,true],['Obsolete'+i,false],['Record'+i,true]]){
  const observed=await server.nativeRead(binding,{operation:'inspect',path:'/'+a.target+'.bin',sourceSha,version:4,parameters:{kind:'type',name}});
  assert.equal(observed.value.exists,exists,name);if(name.startsWith('Record'))assert.ok(observed.value.type.fields.some(f=>f.name==='worker_'+i));
 }
 const dropped=[beforeA.root,beforeB.root];
 for(const root of dropped)assert.ok(!(await readdir(root)).some(n=>n==='view.rep'||n==='view.gpr'));
 // Another publication cycle must create one new checkout, then dispose it without exporting snapshots.
 await cli(['ghidra','open',...select(a)]);const nextA=context(a).nativeCheckout;assert.notEqual(nextA.root,beforeA.root);
 await cli(['ghidra','sync-policy','set',...select(a),'--publish','after-save','--refresh','manual']);
 // Exercise an actual native edit without facade mutation diagnostics, as with GUI work.
 const nativePeer=JSON.parse(await readFile(join(nextA.root,'process.json')));
 const nativeEdited=await new HttpBridge(nativePeer.endpoint,fetch,undefined,await cleanupContext.secrets.require(nativePeer.tokenSecret),120000).call('/run_script_inline',{
  program:nativePeer.program,code:'import ghidra.app.script.GhidraScript; public class NativeOutsideFacade extends GhidraScript {public void run()throws Exception {int tx=currentProgram.startTransaction("native edit");try{currentProgram.getListing().setComment(toAddr(0x1000),ghidra.program.model.listing.CodeUnit.EOL_COMMENT,"second publication cycle");}finally{currentProgram.endTransaction(tx,true);}}}'});
 assert.equal(nativeEdited.success,true);assert.equal(context(a).scalars.length+context(a).complexChanges.length,0);
 const nativeSaved=await cli(['ghidra','save',...select(a)]);assert.equal(nativeSaved.automatic.publication.sharedRevision,'R5');dropped.push(nextA.root);
 await cli(['ghidra','sync-policy','set',...select(a),'--publish','manual','--refresh','manual']);
 const clean=await cli(['ghidra','refresh',...select(reader)]);assert.equal(clean.sharedRevision,'R5');assert.equal(clean.nativeMergeInvocations,0);
 const d=await cli(['ghidra','open',input,'--session','new']);
 for(const [who,name]of [[reader,'first_conflict'],[d,'second_conflict']])await cli(['ghidra','functions','rename',...select(who),'--address','1000','--name',name]);
 const retained=context(d);
 assert.equal((await cli(['ghidra','merge',...select(reader)])).sharedRevision,'R6');dropped.push(context(reader).nativeCheckout.root);
 const conflict=await cli(['ghidra','refresh',...select(d),'--request-id','conflicting-update'],true);assert.equal(JSON.parse(conflict.stdout).state,'conflict');
 assert.equal(context(d).workingSnapshot.id,retained.workingSnapshot.id);
 assert.equal(context(d).nativeCheckout.root,retained.nativeCheckout.root);assert.equal(context(d).nativeCheckout.checkoutId,retained.nativeCheckout.checkoutId);assert.equal(context(d).baseRevision,5);
 assert.equal((await cli(['ghidra','functions','get',...select(d),'--address','1000'])).name,'second_conflict');
 const status=await cli(['sessions','status',d.session,'--target',d.target]);assert.equal(status.ghidra.engine,'ghidra-native');assert.ok(status.ghidra.conflicts.some(c=>c.engine==='ghidra-native'));
 const failedPublish=await cli(['ghidra','merge',...select(d)],true);assert.equal(JSON.parse(failedPublish.stdout).state,'conflict');
 let finalVersion=6,lostReply;
 if(options.faults){
  await cli(['ghidra','open',...select(a)]);await cli(['ghidra','comments','set',...select(a),'--address','1020','--kind','eol','--text','survives owner loss']);
  const held=context(a).nativeCheckout,owner=await cli(['ipc-server','status']);assert.ok(Number.isSafeInteger(owner.pid));
  const heldProcess=JSON.parse(await readFile(join(held.root,'process.json'))),record=JSON.parse(await readFile(join(f.appArguments.AppDataDirectory,'runtime','processes',heldProcess.toolProcessId+'.json')));
  assert.equal(record.ownerPid,owner.pid);assert.equal(record.metadata.contextRoot,held.root);
  const args=['ghidra','merge',...select(a),'--request-id','lost-native-commit'];const pending=installedCommand([...args,'--json']);let committed;
  for(let i=0;i<6000;i++){
   const db=new DatabaseSync(join(workspace,'workspace.sqlite'),{readOnly:true});let q;try{q=db.prepare('SELECT id FROM requests WHERE caller_id=?').get('lost-native-commit');}finally{db.close();}
   if(q)try{const journal=JSON.parse(await readFile(join(held.root,'operations',q.id+'-checkin.json')));if(journal.result?.state==='checked_in'){committed={id:q.id,journal};break;}}catch{}
   await new Promise(ok=>setTimeout(ok,50));
  }
  assert.ok(committed,'Native check-in completion journal did not appear');
  process.kill(owner.pid,'SIGKILL');const lost=await pending;
  await cli(['ghidra','open',...select(a)]);const replay=await cli(args);assert.equal(replay.sharedRevision,'R7');
  const observed=await server.programStatus(binding,'/'+a.target+'.bin');assert.equal(observed.version,7);assert.equal(observed.versions.filter(v=>v.comment==='insight native '+committed.id).length,1);
  assert.ok(!(await readdir(held.root)).some(n=>n==='view.rep'||n==='view.gpr'));dropped.push(held.root);
  await cli(['ghidra','merge',...select(a)]);const still=await server.programStatus(binding,'/'+a.target+'.bin');assert.equal(still.version,7);
  finalVersion=7;lostReply={ownerKilledAfterNativeCheckin:true,clientExitCode:lost.exitCode,historyMarkerUnique:true,replayedCheckin:false,recoveredProjectDropped:true};
 }
 // Explicit native discard must retain a keep file, change checkout identity and keep one project.
 await cli(['ghidra','open',...select(a)]);const discardBefore=context(a).nativeCheckout;
 await cli(['ghidra','comments','set',...select(a),'--address','1000','--kind','pre','--text','explicitly discarded fixture edit']);
 let discarded,discardLostReply;
 if(options.faults){
  const owner=await cli(['ipc-server','status']),heldProcess=JSON.parse(await readFile(join(discardBefore.root,'process.json')));
  const ledger=JSON.parse(await readFile(join(f.appArguments.AppDataDirectory,'runtime','processes',heldProcess.toolProcessId+'.json')));
  assert.equal(ledger.ownerPid,owner.pid);assert.equal(ledger.metadata.contextRoot,discardBefore.root);
  const args=['ghidra','changes','discard',...select(a),'--request-id','lost-native-discard'],pending=installedCommand([...args,'--json']);let completed;
  for(let i=0;i<6000;i++){
   const db=new DatabaseSync(join(workspace,'workspace.sqlite'),{readOnly:true});let q;try{q=db.prepare('SELECT id FROM requests WHERE caller_id=?').get('lost-native-discard');}finally{db.close();}
   if(q)try{const journal=JSON.parse(await readFile(join(discardBefore.root,'operations',q.id+'-discard.json')));if(journal.result?.state==='discarded'){completed={id:q.id,journal};break;}}catch{}
   await new Promise(ok=>setTimeout(ok,50));
  }
  assert.ok(completed,'Native discard completion journal did not appear');process.kill(owner.pid,'SIGKILL');const lost=await pending;
  discarded=await cli(args);assert.deepEqual(await cli(args),discarded);assert.equal(context(a).nativeCheckout.checkoutId,completed.journal.result.checkoutId);
  const journals=(await readdir(join(discardBefore.root,'operations'))).filter(n=>n.endsWith('-discard.json'));assert.deepEqual(journals,[completed.id+'-discard.json']);
  discardLostReply={ownerKilledAfterNativeDiscard:true,clientExitCode:lost.exitCode,newCheckoutRecovered:true,replayedDiscard:false};
 }else discarded=await cli(['ghidra','changes','discard',...select(a)]);
 const discardAfter=context(a).nativeCheckout;
 assert.equal(discardAfter.root,discardBefore.root);assert.notEqual(discardAfter.checkoutId,discardBefore.checkoutId);assert.equal(discardAfter.baseVersion,finalVersion);assert.ok(discarded.retainedKeepFile);
 const privateStatus=await server.nativeCheckout(binding,{root:discardAfter.root,owner:JSON.parse(await readFile(join(discardAfter.root,'native-owner.json'))),operation:'status',fileId:discardAfter.fileId,checkoutId:discardAfter.checkoutId});
 assert.equal(privateStatus.state,'ready');assert.ok(privateStatus.projectFiles.includes(discarded.retainedKeepFile));
 assert.equal((await cli(['ghidra','merge',...select(a)])).state,'empty');dropped.push(discardAfter.root);
 const disposed=context(a).nativeCheckout;await cli(['ghidra','close',...select(a)]);assert.deepEqual(context(a).nativeCheckout,disposed);
 const final=await server.nativeRead(binding,{operation:'latest',path:'/'+a.target+'.bin',sourceSha});assert.equal(final.version,finalVersion);
 assert.ok(final.checkouts.some(c=>c.id===retained.nativeCheckout.checkoutId&&c.version===5));
 assert.equal(final.checkouts.length,1);
 const remainingProjects=[];async function projects(path){for(const entry of await readdir(path,{withFileTypes:true})){if(entry.isDirectory()){if(entry.name==='view.rep')remainingProjects.push(path);else await projects(join(path,entry.name));}}}
 await projects(join(workspace,'ghidra-native','context'));assert.deepEqual(remainingProjects,[retained.nativeCheckout.root]);
 const processes=await Promise.all((await readdir(join(f.appArguments.AppDataDirectory,'runtime','processes'))).map(async n=>JSON.parse(await readFile(join(f.appArguments.AppDataDirectory,'runtime','processes',n)))));
 const roles=Object.fromEntries([...new Set(processes.map(p=>p.role))].sort().map(role=>[role,processes.filter(p=>p.role===role).length]));
 for(const legacy of ['publish','recover-publication','candidate','snapshot-fields','snapshot-inspect'])assert.equal(roles[legacy],undefined,'Legacy runtime role was used: '+legacy);
 const runtimeAfter=await nativeInputs(values);assert.equal(runtimeAfter.fingerprint,runtimeBefore.fingerprint,'Installed runtime changed during acceptance');
 const inputArtifacts=await readdir(join(workspace,'artifacts'));const packed=inputArtifacts.filter(n=>n.endsWith('.gzf'));
 // Only initial import is a packed snapshot; ordinary save/restart/merge/refresh do not export one.
 assert.equal(packed.length,1);
 const explicitOutput=join(f.root,'explicit-program.gzf'),exported=await cli(['ghidra','program','export',...select(d),'--output',explicitOutput]);
 assert.equal(hash(await readFile(explicitOutput)),exported.sha256);assert.equal(context(d).workingSnapshot.kind,'native');
 const selectors=join(f.root,'export-fields.json');await writeFile(selectors,JSON.stringify([{address:'1000',field:'function.name'}]));
 const inspectedExport=await server.fields(explicitOutput,selectors);assert.equal(inspectedExport.fields['1000@function.name'].value,'second_conflict');
 assert.equal((await readdir(join(workspace,'artifacts'))).filter(n=>n.endsWith('.gzf')).length,2);
 // Bounded detached inspection equals the single operation; exact older versions stay provable.
 const single=await server.nativeMigration(binding,{operation:'snapshot',snapshot:explicitOutput}),batch=await server.nativeMigration(binding,{operation:'snapshots',snapshots:[explicitOutput,explicitOutput]});
 assert.equal(batch.items.length,2);for(const item of batch.items)for(const key of ['state','fingerprint','programIdentity','sourceSha'])assert.equal(item[key],single[key],key);
 assert.equal(single.sourceSha,sourceSha);assert.match(single.fingerprint,/^[a-f0-9]{64}$/);
 const older=await server.nativeRead(binding,{operation:'migration-probe',path:'/'+a.target+'.bin',sourceSha,version:2}),newest=await server.nativeRead(binding,{operation:'migration-probe',path:'/'+a.target+'.bin',sourceSha});
 assert.equal(older.version,2);assert.equal(newest.version,finalVersion);assert.notEqual(older.fingerprint,newest.fingerprint);
 // An unchanged close releases its checkout; collection releases one left by an ended owner and keeps real work.
 const serverCheckouts=async()=>(await server.nativeRead(binding,{operation:'latest',path:'/'+a.target+'.bin',sourceSha})).checkouts.map(c=>c.id);
 // A shared repository lists every target; another target's server item is not local work.
 const otherInput=join(f.root,'other.bin');await writeFile(otherInput,Buffer.alloc(0x200,0x90));
 const other=await cli(['ghidra','open',otherInput,'--session','new','--loader','ghidra.app.util.opinion.BinaryLoader','--language','x86:LE:64:default','--image-base','1000','--loader-options','{"Base Address":"0"}']);
 // Its first analysis is private work until published.
 assert.equal((await cli(['ghidra','close',...select(other)])).checkout,'retained');await cli(['ghidra','open',...select(other)]);await cli(['ghidra','merge',...select(other)]);
 await cli(['ghidra','open',...select(other)]);assert.equal((await cli(['ghidra','close',...select(other)])).checkout,'released');
 await cli(['ghidra','open',...select(a)]);const unchanged=context(a).nativeCheckout;assert.equal(unchanged.baseVersion,finalVersion);
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'released');assert.equal(context(a).nativeCheckout.state,'dropped');
 assert.deepEqual(await serverCheckouts(),[retained.nativeCheckout.checkoutId]);assert.ok(!(await readdir(unchanged.root)).includes('view.rep'));
 // A file below a subfolder exists only in this project and must keep it.
 await cli(['ghidra','open',...select(a)]);const nested=context(a).nativeCheckout;
 await script(a,'import ghidra.app.script.GhidraScript;import ghidra.program.database.ProgramDB; public class NestedFile extends GhidraScript {public void run()throws Exception {var root=currentProgram.getDomainFile().getParent().getProjectData().getRootFolder();var p=new ProgramDB("nested",currentProgram.getLanguage(),currentProgram.getLanguage().getDefaultCompilerSpec(),this);try{root.createFolder("owned").createFile("nested",p,monitor);}finally{p.release(this);}}}');
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'retained');assert.ok((await readdir(nested.root)).includes('view.rep'));
 const nestedClosed=await server.nativeCheckout(binding,{root:nested.root,owner:JSON.parse(await readFile(join(nested.root,'native-owner.json'))),operation:'status',fileId:nested.fileId,checkoutId:nested.checkoutId});
 assert.ok(nestedClosed.projectFiles.includes('owned/nested'));assert.ok(!nestedClosed.projectFiles.includes(other.target+'.bin'));
 const g=await cli(['ghidra','open',input,'--session','new']);
 const closedWork=await cli(['ghidra','close',...select(d)]);assert.equal(closedWork.checkout,'retained');
 await cli(['ghidra','open',...select(g)]);const abandoned=context(g).nativeCheckout;await app.dispose();app=createApplication();
 const abandonedPid=JSON.parse(await readFile(join(abandoned.root,'process.json'))).pid;
 for(let i=0;i<600;i++){try{process.kill(abandonedPid,0);}catch{break;}await new Promise(ok=>setTimeout(ok,100));}
 const planned=await cli(['ghidra','gc','--dry-run']);assert.ok(planned.categories['native-checkouts'].items>=1);assert.ok((await readdir(abandoned.root)).includes('view.rep'));
 assert.deepEqual((await serverCheckouts()).sort(),[retained.nativeCheckout.checkoutId,nested.checkoutId,abandoned.checkoutId].sort());
 const collected=await cli(['ghidra','gc']);assert.equal(collected.categories['native-checkouts'].items,1);assert.equal(context(g).nativeCheckout.state,'dropped');
 assert.deepEqual((await serverCheckouts()).sort(),[retained.nativeCheckout.checkoutId,nested.checkoutId].sort());assert.ok(!(await readdir(abandoned.root)).includes('view.rep'));
 assert.equal((await cli(['ghidra','gc'])).bytes,0);
 await cli(['ghidra','open',...select(d)]);assert.equal((await cli(['ghidra','functions','get',...select(d),'--address','1000'])).name,'second_conflict');
 assert.equal(context(d).nativeCheckout.checkoutId,retained.nativeCheckout.checkoutId);
 await cli(['ghidra','open',...select(g)]);assert.equal((await cli(['ghidra','functions','get',...select(g),'--address','1000'])).name,'first_conflict');
 assert.equal((await cli(['ghidra','close',...select(g)])).checkout,'released');
 const collection={planned,collected};
 for(const [path,expected]of Object.entries(sourceHashes))assert.equal(hash(await readFile(path.startsWith('../scripts/')?new URL('./'+path.slice('../scripts/'.length),import.meta.url):join(sourceRoot,path))),expected,'Source changed during acceptance');
 receipt={schema:1,scope:options['global-entry']?'Actual global CLI entrypoint with isolated environment/profile':'main Factory CLI with default production backend',installedIpc:options.installed===true,
  globallyInstalledCli:!!options['global-entry'],runtimeArgumentsInjected:options.installed===true&&!options['global-entry'],...(options['global-entry']?{globalVersion:JSON.parse(await readFile(join(installation,'package.json'))).version}:{}),
  ...(packageSha256?{packageSha256}:{}),backendInjected:false,root:f.root,sourceHashes,
  sameNativeProjectAcrossWorkerAndOwnerRestart:true,credentiallessWorkerEdits:true,ordinaryCheckoutIdsPreserved:true,nativeUpdateVerified:true,nativeCheckinVerified:true,
  serverVersion:finalVersion,independentReadOnlyReadback:true,confirmedProjectsDropped:dropped,packedArtifacts:packed.length,cleanUpdateVerified:true,
  nativeConflictPreservesProjectCheckoutAndBase:true,conflictingPublicationRefused:true,repeatedPublicationCycles:true,...(lostReply?{lostReply}:{}),
  explicitNativeDiscardVerified:true,...(discardLostReply?{discardLostReply}:{}),afterSaveWithoutCliDiagnosticsVerified:true,closeAfterDisposalAllocatesNothing:true,remainingNativeProjects:remainingProjects,remainingServerCheckouts:final.checkouts,
  ordinaryRuntimeRoles:roles,legacyRuntimeRolesAbsentBeforeExplicitExport:true,explicitPackedExportVerified:true,workingViewRemainsNativeAfterExport:true,
  unchangedCloseReleased:true,abandonedCheckoutCollected:true,collection,
  runtimeFingerprint:runtimeBefore.fingerprint,runtimeJarCount:runtimeBefore.jars.length,installedRuntimeUnchanged:true,
  nativeContextBeforeRestart:savedB.nativeCheckout,engine:'ghidra-native',limitations:['Disposable raw binary fixture; no arbitrary-native-change or hostile-same-user sandbox guarantee']};
}catch(error){console.error('Main CLI fixture retained:',f.root);throw error;}
finally{
 await app.dispose();await new GhidraServer(workspace,await nativeInputs(values),cleanupContext).stop();
 if(installedSecrets){let keys=[];try{keys=(await readFile(join(f.appArguments.AppDataDirectory,'fixture-secret-keys.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(error){if(error.code!=='ENOENT')throw error;}
  for(const {service,account}of keys)await installedSecrets.delete(service,account);
  if(options['global-entry']){const local=JSON.parse(await readFile(join(workspace,'server','local.json')));
   for(const key of ['readerSecret','publisherSecret','keySecret','tokenSecret']){assert.ok(local[key].startsWith(local.instance+'-'));await cleanupContext.secrets.delete(local[key]);}}
 }
}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
