// Explicitly authorized disposable native research prototype; never opens a CLI profile.
import assert from 'node:assert/strict';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,readFile,writeFile,readdir,open,realpath,stat} from 'node:fs/promises';
import {join,resolve,dirname,basename,delimiter,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID,randomBytes} from 'node:crypto';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';

const options={};
for(let i=2;i<process.argv.length;i++){
 const arg=process.argv[i];
 if(arg==='--ack-disposable')options.ack=true;
 else {assert.ok(['--ghidra-home','--java','--mcp-jar','--output-base','--case','--function-conflict-ui'].includes(arg),'Unknown option');assert.ok(process.argv[i+1]);options[arg.slice(2)]=process.argv[++i];}
}
assert.ok(options.case===undefined||['return-types','checkout-lifecycle'].includes(options.case),'Unknown proof case');
assert.ok(options['function-conflict-ui']===undefined||options['function-conflict-ui']==='stock','Only the diagnostic stock UI control is supported');
assert.ok(!options['function-conflict-ui']||options.case==='return-types','Unsafe stock UI control is restricted to the offline diagnostic');
assert.equal(options.ack,true,'Pass --ack-disposable to authorize a new isolated server and test projects');
for(const key of ['ghidra-home','java','mcp-jar','output-base'])assert.ok(options[key],`Missing --${key}`);
const home=await realpath(resolve(options['ghidra-home'])),java=await realpath(resolve(options.java));
const bridge=await realpath(resolve(options['mcp-jar'])),base=await realpath(resolve(options['output-base']));
assert.ok(!home.toLowerCase().includes('ec2-native')&&!java.toLowerCase().includes('ec2-native'),'Do not use the protected profile');
assert.ok(!base.toLowerCase().includes('ec2-native')&&!bridge.toLowerCase().includes('ec2-native'),'Do not use the protected profile');
const root=await realpath(await mkdtemp(join(base,'native-merge-proof-')));
const id=randomUUID(),repository='native_merge_'+id.replaceAll('-','');
await writeFile(join(root,'owner.json'),JSON.stringify({schema:1,id,repository,scope:'disposable native merge proof'}),{flag:'wx',mode:0o600});
console.log(JSON.stringify({event:'owned_fixture_created',root}));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const runnerFile=fileURLToPath(import.meta.url),runnerHash=hash(await readFile(runnerFile)),startedAt=new Date().toISOString();
const runExec=promisify(execFile),children=new Set();
const suffix=process.platform==='win32'?'.exe':'';
const fixtureSources=fileURLToPath(new URL('../skills/ghidra-coordinator/tests/fixtures/native-merge/',import.meta.url));
const jars=[bridge];
async function collect(dir){for(const e of await readdir(dir,{withFileTypes:true})){const f=join(dir,e.name);if(e.isDirectory()&&e.name!=='data')await collect(f);else if(e.isFile()&&e.name.endsWith('.jar')&&basename(dir)==='lib')jars.push(f);}}
const quote=value=>'"'+value.replace(/[\\"\n\r]/g,c=>({'\\':'\\\\','"':'\\"','\n':'\\n','\r':'\\r'}[c]))+'"';
// Lifecycle workers inherit only operating-system essentials, never host credentials/JAVA_OPTIONS.
const inheritedEnv=options.case==='checkout-lifecycle'?Object.fromEntries(Object.entries(process.env).filter(([key])=>/^(SystemRoot|WINDIR|PATH|PATHEXT|COMSPEC|OS|PROCESSOR_ARCHITECTURE|NUMBER_OF_PROCESSORS)$/i.test(key))):process.env;
async function command(executable,args,cwd,timeout=120000,environment={}){
 const argumentFile=join(cwd,'arguments-'+randomUUID()+'.txt');
 await writeFile(argumentFile,args.map(quote).join('\n'),{flag:'wx',mode:0o600});
 const pending=runExec(executable,['@'+argumentFile],{cwd,windowsHide:true,timeout,maxBuffer:4*1024*1024,env:{...inheritedEnv,...environment}});
 children.add(pending.child);
 try{return await pending;}finally{children.delete(pending.child);}
}
const directories=dir=>['-Djava.awt.headless=true','-Dghidra.home='+home,'-Duser.home='+dir,'-Djava.io.tmpdir='+dir,
 '-Dapplication.cachedir='+join(dir,'cache'),'-Dapplication.settingsdir='+join(dir,'settings'),'-Dapplication.tempdir='+dir];
async function stop(child){
 if(child.exitCode!==null||child.signalCode!==null)return;
 child.kill();
 await Promise.race([new Promise(ok=>child.once('exit',ok)),delay(5000)]);
 if(child.exitCode===null&&child.signalCode===null){
  child.kill('SIGKILL');
  await Promise.race([new Promise(ok=>child.once('exit',ok)),delay(5000)]);
 }
 assert.ok(child.exitCode!==null||child.signalCode!==null,'Owned native process termination remains unverified');
}
let server,receipt;
try{
 assert.match(await readFile(join(home,'Ghidra/application.properties'),'utf8'),/^application.version=12\.1\.2\s*$/m);
 await collect(join(home,'Ghidra'));
 const runtimeInventory=await Promise.all(jars.map(async path=>({name:path===bridge?'bridge/GhidraMCP.jar':'ghidra/'+relative(home,path).split(sep).join('/'),sha256:hash(await readFile(path))})));
 await writeFile(join(root,'runtime-inventory.json'),JSON.stringify(runtimeInventory,null,2));
 const classes=join(root,'classes'),upstream=join(root,'upstream');await mkdir(classes);await mkdir(upstream);
 const sourceName='ghidra/app/merge/listing/ListingMergeManager.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Features/Base/lib/Base-src.zip'),sourceName],{cwd:upstream,windowsHide:true,timeout:30000});
 const upstreamPath=join(upstream,sourceName),original=await readFile(upstreamPath,'utf8');
 assert.equal(hash(original),'3b6ce2e22fd414d6cc63ce2a3be6c533f13524b9513767b932f6da8f2d9326d6','Pinned Ghidra listing source differs');
 let patched=original;
 const changes=[
  ['mergePanel.setTopComponent(conflictInfoPanel);','if (mergePanel != null) mergePanel.setTopComponent(conflictInfoPanel);'],
  ['private void setListingViewsToEntireProgram() {','private void setListingViewsToEntireProgram() {\n\t\tif (mergePanel == null) return;'],
  ['private void emptyListingViewForPrograms() {','private void emptyListingViewForPrograms() {\n\t\tif (mergePanel == null) return;']
 ];
 for(const [before,after]of changes){assert.equal(patched.split(before).length,2,'Pinned UI seam must occur exactly once');patched=patched.replace(before,after);}
 await writeFile(upstreamPath,patched);
 const fileDataName='ghidra/framework/data/GhidraFileData.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Framework/Project/lib/Project-src.zip'),fileDataName],{cwd:upstream,windowsHide:true,timeout:30000});
 const fileDataPath=join(upstream,fileDataName),fileData=await readFile(fileDataPath,'utf8');
 assert.equal(hash(fileData),'aafc9c66f42ce12c3f0e7847529d982545b4f760dd570db482133578e9d531e2');
 assert.equal(fileData.split('if (SystemUtilities.isInHeadlessMode()) {').length,3,'Exactly two pinned headless merge guards');
 const patchedFileData=fileData.replaceAll('if (SystemUtilities.isInHeadlessMode()) {','if (false /* Disposable native-headless merge proof driver installed */) {');
 await writeFile(fileDataPath,patchedFileData);
 const contextName='ghidra/app/merge/listing/ProgramContextMergeManager.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Features/Base/lib/Base-src.zip'),contextName],{cwd:upstream,windowsHide:true,timeout:30000});
 const contextPath=join(upstream,contextName),contextSource=await readFile(contextPath,'utf8');
 assert.equal(hash(contextSource),'f2a57f5100de73f980fab99a8ba1d79cf8ecee6257ba32686b78f3512e4c67bb');
 assert.equal(contextSource.split(changes[0][0]).length,2);
 const patchedContext=contextSource.replace(...changes[0]);await writeFile(contextPath,patchedContext);
 const externalName='ghidra/app/merge/listing/ExternalFunctionMerger.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Features/Base/lib/Base-src.zip'),externalName],{cwd:upstream,windowsHide:true,timeout:30000});
 const externalPath=join(upstream,externalName),externalSource=await readFile(externalPath,'utf8');
 assert.equal(hash(externalSource),'76aa623434213057e936c8abef1539844c41c30361891b4398665d673574f519');
 const externalChanges=['listingMergePanel.setTopComponent(conflictInfoPanel);','listingMergePanel.setTopComponent(listingConflictInfoPanel);'];
 let patchedExternal=externalSource;
 for(const before of externalChanges){assert.equal(patchedExternal.split(before).length,2);patchedExternal=patchedExternal.replace(before,'if (listingMergePanel != null) '+before);}
 await writeFile(externalPath,patchedExternal);
 const functionName='ghidra/app/merge/listing/AbstractFunctionMerger.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Features/Base/lib/Base-src.zip'),functionName],{cwd:upstream,windowsHide:true,timeout:30000});
 const functionPath=join(upstream,functionName),functionSource=await readFile(functionPath,'utf8');
 assert.equal(hash(functionSource),'9e4ea08167344d8527701dac0ed1607fd68e0670849c8b453463fcf8fccb4fb5');
 const functionBefore='final Address entryPt, final TaskMonitor monitor) {\n\n\t\tif (conflictPanel == null) {';
 assert.equal(functionSource.split(functionBefore).length,2);
 const patchedFunction=options['function-conflict-ui']==='stock'?functionSource:functionSource.replace(functionBefore,'final Address entryPt, final TaskMonitor monitor) {\n\n\t\tif (java.awt.GraphicsEnvironment.isHeadless()) {\n\t\t\tmergeManager.showListingMergePanel(entryPt);\n\t\t\tthrow new IllegalStateException("Headless function conflict was not rejected");\n\t\t}\n\n\t\tif (conflictPanel == null) {');
 await writeFile(functionPath,patchedFunction);
 const memoryName='ghidra/app/merge/memory/MemoryMergeManager.java';
 await runExec(join(dirname(java),'jar'+suffix),['xf',join(home,'Ghidra/Features/Base/lib/Base-src.zip'),memoryName],{cwd:upstream,windowsHide:true,timeout:30000});
 const memoryPath=join(upstream,memoryName),memorySource=await readFile(memoryPath,'utf8');
 assert.equal(hash(memorySource),'28b1fd583e694a7b48d37dcdebdae6674990ee0c2b3dbf3d44a726da33dd1129');
 const commentWriteBefore='if (myComment != null && !myComment.equals(origBlocks[index].getComment()) ||\n\t\t\t\t(myComment == null)) {';
 assert.equal(memorySource.split(commentWriteBefore).length,2);
 let patchedMemory=memorySource.replace(commentWriteBefore,'if (!java.util.Objects.equals(myComment, origBlocks[index].getComment())) {');
 const conflictStart=patchedMemory.indexOf('\tprivate boolean isCommentConflict(int index) {');
 assert.ok(conflictStart>0);let depth=0,conflictEnd;
 for(let n=patchedMemory.indexOf('{',conflictStart);n<patchedMemory.length;n++){
  if(patchedMemory[n]==='{')depth++;
  if(patchedMemory[n]==='}'&&--depth===0){conflictEnd=n+1;break;}
 }
 assert.ok(conflictEnd>conflictStart);
 patchedMemory=patchedMemory.slice(0,conflictStart)+`\tprivate boolean isCommentConflict(int index) {
        String original = origBlocks[index].getComment();
        String latest = latestBlocks[index].getComment();
        String mine = myBlocks[index].getComment();
        return !java.util.Objects.equals(mine, original) &&
            !java.util.Objects.equals(latest, original) && !java.util.Objects.equals(mine, latest);
    }`+patchedMemory.slice(conflictEnd);
 await writeFile(memoryPath,patchedMemory);
 const fixtureFiles=['HeadlessProgramMergeManager.java','NativeMergeFixture.java','ExtendedMergeCases.java','NativeReturnTypeRepro.java',...(options.case==='checkout-lifecycle'?['NativeCheckoutLifecycle.java','NativeLifecycleServerInit.java']:[])].map(name=>join(fixtureSources,name));
 const lifecycleModule=join(fixtureSources,'checkout-lifecycle.mjs');
 const sources=[...fixtureFiles,upstreamPath,fileDataPath,contextPath,externalPath,functionPath,memoryPath];
 const sourceHashes=Object.fromEntries(await Promise.all(fixtureFiles.map(async source=>[basename(source),hash(await readFile(source))])));
 sourceHashes['proof-native-merge.mjs']=runnerHash;
 if(options.case==='checkout-lifecycle')sourceHashes['checkout-lifecycle.mjs']=hash(await readFile(lifecycleModule));
 const retainedSources=join(root,'sources');await mkdir(retainedSources);
 for(const source of [...fixtureFiles,runnerFile])await writeFile(join(retainedSources,basename(source)),await readFile(source),{flag:'wx'});
 if(options.case==='checkout-lifecycle')await writeFile(join(retainedSources,'checkout-lifecycle.mjs'),await readFile(lifecycleModule),{flag:'wx'});
 await writeFile(join(root,'source-inventory.json'),JSON.stringify(sourceHashes,null,2),{flag:'wx'});
 const classpath=[classes,...jars].join(delimiter);
 await command(join(dirname(java),'javac'+suffix),['-proc:none','-cp',classpath,'-d',classes,...sources],root,60000);
 const privateEnv={HOME:root,USERPROFILE:root,TEMP:root,TMP:root,TMPDIR:root};
 if(options.case==='return-types'){
  let result;
  try{result=await command(java,[...directories(root),'-Xmx768m','-cp',classpath,'NativeReturnTypeRepro',root],root,120000,privateEnv);}
  catch(error){await writeFile(join(root,'native-return-types.json'),error.stdout??'');await writeFile(join(root,'native-return-types.log'),error.stderr??String(error));throw error;}
  await writeFile(join(root,'native-return-types.json'),result.stdout);await writeFile(join(root,'native-return-types.log'),result.stderr);
  const observed=JSON.parse(result.stdout),unsafeControl=options['function-conflict-ui']==='stock';
  assert.equal(observed.latest.returnType,'float');assert.equal(observed.mine.returnType,'double');
  assert.equal(observed.builtinsAbsentFromBaseline,true);assert.equal(observed.original.returnType,'int');
  assert.deepEqual(observed.mineAfter,observed.mine);assert.deepEqual(observed.latestAfter,observed.latest);
  assert.equal(observed.latest.typeId,observed.mine.typeId,'The minimal fixture must exercise colliding native local IDs');
  assert.equal(Object.values(observed.ResolvedMyDataTypes).includes('double'),true,'Native datatype remapping must retain double');
  assert.equal(observed.guiWindows,0);
  if(unsafeControl){assert.equal(observed.completed,true);assert.equal(observed.result.returnType,'float');assert.equal(observed.conflict,undefined);assert.match(result.stderr,/AbstractFunctionMerger.setupConflictPanel/);assert.match(result.stderr,/NullPointerException/);}
  else{assert.match(observed.conflict,/UnresolvedNativeConflict/);assert.equal(observed.completed,undefined);}
  for(const source of fixtureFiles)assert.equal(hash(await readFile(source)),sourceHashes[basename(source)]);
  assert.equal(hash(await readFile(runnerFile)),runnerHash);
  assert.deepEqual(await Promise.all(jars.map(async path=>hash(await readFile(path)))),runtimeInventory.map(f=>f.sha256));
  receipt={schema:1,scope:'minimal native return-type regression',ghidra:'12.1.2',stockFunctionConflictUi:unsafeControl,
   disposition:unsafeControl?'reproduced unsafe historical adapter behavior':'native conflict refused',sourceHashes,result:observed,
   upstreamFunctionMergerSha256:hash(functionSource),compiledFunctionMergerSha256:hash(patchedFunction),
   runtimeClasspathSha256:hash(JSON.stringify(runtimeInventory)),runtimeJarCount:jars.length,installedJarsUnchanged:true};
 }else{
 const serverRoot=join(root,'server'),data=join(serverRoot,'repositories');await mkdir(data,{recursive:true});
 const lifecycleSecrets=options.case==='checkout-lifecycle'?{publisher:randomBytes(32).toString('hex'),reader:randomBytes(32).toString('hex')}:null;
 if(lifecycleSecrets){
  const initialized=await command(java,[...directories(serverRoot),'-cp',classpath,'ghidra.server.NativeLifecycleServerInit',root],serverRoot,30000,{...privateEnv,PROOF_PUBLISHER_PASSWORD:lifecycleSecrets.publisher,PROOF_READER_PASSWORD:lifecycleSecrets.reader});
  await writeFile(join(serverRoot,'initialization.json'),initialized.stdout);await writeFile(join(serverRoot,'initialization.log'),initialized.stderr);
  assert.equal(JSON.parse(initialized.stdout).state,'ready');
 }
 let port;
 for(let attempt=0;attempt<40;attempt++){
  const candidate=20000+Math.floor(Math.random()*30000),held=[];
  try{for(let n=0;n<3;n++){const listener=createServer();await new Promise((ok,bad)=>{listener.once('error',bad);listener.listen(candidate+n,'127.0.0.1',ok);});held.push(listener);}port=candidate;break;}
  catch{}finally{for(const listener of held)await new Promise(ok=>listener.close(ok));}
 }
 assert.ok(port,'Could not reserve server ports');
 const storepass=randomBytes(24).toString('hex'),keystore=join(serverRoot,'certificate.p12');
 await runExec(join(dirname(java),'keytool'+suffix),['-genkeypair','-alias','owned','-keyalg','RSA','-keysize','2048','-dname','CN=GhidraServer','-ext','SAN=IP:127.0.0.1','-ext','KU=digitalSignature,keyEncipherment','-validity','2','-keystore',keystore,'-storetype','PKCS12','-storepass:env','NATIVE_MERGE_STOREPASS'],{cwd:serverRoot,windowsHide:true,timeout:30000,env:{...process.env,...privateEnv,NATIVE_MERGE_STOREPASS:storepass}});
 const serverArgs=[...directories(serverRoot),'-Dghidra.keystore='+keystore,'-Dghidra.password='+storepass,'-Xmx512m','-cp',classpath,'ghidra.server.remote.GhidraServer','-i','127.0.0.1','-ip','127.0.0.1','-p'+port,'-a0','-u',data];
 const serverFile=join(serverRoot,'server-arguments.txt');await writeFile(serverFile,serverArgs.map(quote).join('\n'),{mode:0o600,flag:'wx'});
 const log=await open(join(serverRoot,'server.log'),'wx',0o600);
 server=spawn(java,['@'+serverFile],{cwd:serverRoot,windowsHide:true,env:{...inheritedEnv,...privateEnv},stdio:['ignore',log.fd,log.fd]});children.add(server);await log.close();
 for(let n=0;n<900;n++){assert.equal(server.exitCode,null,'Owned server exited');let ready=false;try{ready=(await readFile(join(serverRoot,'server.log'),'utf8')).includes('Command watcher started');}catch{}if(ready)break;assert.ok(n<899,'Server readiness timeout');await delay(100);}
 if(lifecycleSecrets){
  const {proveCheckoutLifecycle}=await import('../skills/ghidra-coordinator/tests/fixtures/native-merge/checkout-lifecycle.mjs');
  receipt=await proveCheckoutLifecycle({root,id,port,java,classpath,directories,command,privateEnv,...lifecycleSecrets});
  for(const source of fixtureFiles)assert.equal(hash(await readFile(source)),sourceHashes[basename(source)]);
  assert.equal(hash(await readFile(lifecycleModule)),sourceHashes['checkout-lifecycle.mjs']);
  assert.equal(hash(await readFile(runnerFile)),runnerHash);
  assert.deepEqual(await Promise.all(jars.map(async path=>hash(await readFile(path)))),runtimeInventory.map(f=>f.sha256));
  Object.assign(receipt,{sourceHashes,startedAt,finishedAt:new Date().toISOString(),runtimeClasspathSha256:hash(JSON.stringify(runtimeInventory)),runtimeJarCount:jars.length,installedJarsUnchanged:true});
 }else{
 const config=join(serverRoot,'admin.conf');await writeFile(config,'ghidra.repositories.dir='+data.replaceAll('\\','/')+'\n');
 await command(java,[...directories(serverRoot),'-Djava.system.class.loader=ghidra.GhidraClassLoader','-cp',classpath,'ghidra.Ghidra','ghidra.server.ServerAdmin',config,'-add','mergeproof'],serverRoot,30000,privateEnv);
 for(let n=0;n<100;n++){let ready=false;try{ready=(await readFile(join(data,'users'),'utf8')).includes('mergeproof');}catch{}if(ready)break;assert.ok(n<99,'Owned user creation timeout');await delay(100);}
 const credentials={...privateEnv,GHIDRA_SERVER_HOST:'127.0.0.1',GHIDRA_SERVER_PORT:String(port),GHIDRA_SERVER_USER:'mergeproof',GHIDRA_SERVER_PASSWORD:'changeme'};
 const results=[];
 async function call(operation,actor,extra={},expectedFailure=false){
  const invocation=join(root,'calls',operation+'-'+actor+'-'+randomUUID());await mkdir(invocation,{recursive:true});
  const request=join(invocation,'request.json');await writeFile(request,JSON.stringify({root,id,operation,actor,...extra}),{flag:'wx',mode:0o600});
  let result,commandError;
  try{result=await command(java,[...directories(invocation),'-Xmx768m','-cp',classpath,'NativeMergeFixture',request],invocation,120000,credentials);}
  catch(error){result=error;commandError=error;}
  await writeFile(join(invocation,'stdout.json'),result.stdout??'');
  await writeFile(join(invocation,'stderr.log'),String(result.stderr??commandError?.stack??''));
  if(commandError&&!expectedFailure)throw commandError;
  if(expectedFailure)assert.equal(commandError?.code,1,'Expected native rejection, received success or a timeout');
  const value=JSON.parse(result.stdout.trim());results.push(value);console.log(JSON.stringify({event:'native_step',operation,actor,...(value.state?{state:value.state}:{}),...(value.nativeMergeInvocations!==undefined?{nativeMergeInvocations:value.nativeMergeInvocations}:{})}));return value;
 }
 await call('baseline','baseline');
 const actors=['agent0','agent1','agent2'];
 const checkouts=await Promise.all(actors.map(actor=>call('checkout',actor)));
 assert.equal(new Set(checkouts.map(r=>r.checkoutId)).size,3);assert.ok(checkouts.every(r=>r.baseVersion===1));
 const edits=await Promise.all(actors.map((actor,index)=>call('edit',actor,{index})));
 const newTypeIds=edits.flatMap((edit,index)=>Object.values(edit.local.extended['actor'+index].newTypeIdentities));
 assert.equal(new Set(newTypeIds).size,newTypeIds.length,'Distinct concurrent native type creations reused a UniversalID; publication is refused');
 for(let i=0;i<3;i++)for(let j=0;j<3;j++)assert.equal(edits[i].local['function'+j].name,i===j?'actor_'+j:'baseline_'+j,'Working copies must remain independent');
 const unpublished=await call('read','reader2');assert.equal(unpublished.versions.length,1);
 for(let i=0;i<3;i++)assert.equal(unpublished.program['function'+i].name,'baseline_'+i,'Local changes must remain unpublished');
 const publications=[];
 for(const actor of actors)publications.push(await call('checkin',actor));
 assert.equal(publications[0].nativeMergeInvocations,0);
 assert.ok(publications.slice(1).every(r=>r.nativeMergeInvocations===1),'Divergent actors must execute native three-way merge');
 const shared=await call('read','reader0');
 for(let i=0;i<3;i++){
  assert.equal(shared.program['function'+i].name,'actor_'+i);
  assert.equal(shared.program['function'+i].parameters[0].name,'record_'+i);
  assert.equal(shared.program['function'+i].returnType,i===1?'uint':'longlong');
  assert.match(shared.program['function'+i].parameters[0].type,new RegExp('Record'+i));
  assert.equal(shared.program['type'+i].fields[1].name,'actor_'+i+'_field');
  const expected=edits[i].local.extended['actor'+i],actual=shared.program.extended['actor'+i];
  for(const key of ['functionPath','locals','tags','instruction','comment','createdFunction','definedData','record','enumValue','union','typedef','typeBindings','deletedFunctionAbsent','deletedTypeAbsent','renamedType','label','references','bookmark','equate','property','option','block','register','external','externalPath','patchedByte'])
   assert.deepEqual(actual[key],expected[key],'Native merged '+key+' differs for actor '+i);
  assert.ok(actual.fragmentContainsCode&&actual.tree.includes('fragment_actor'+i));
  for(const key of ['locals','tags','instruction','comment','createdFunction','definedData','enumValue','union','typedef','label','references','bookmark','equate','property','option','register','external','externalPath'])assert.ok(actual[key]!==undefined&&actual[key]!==null,'Missing tested native '+key);
  assert.ok(actual.deletedFunctionAbsent&&actual.deletedTypeAbsent&&actual.renamedType);
  assert.ok(actual.typeBindings&&Object.values(actual.typeBindings).every(value=>value===true),'Native type-use bindings must resolve to the merged canonical types');
 }
 assert.equal(shared.versions.length,4);assert.equal(shared.checkouts.length,0);
 for(const actor of actors)assert.equal((await call('drop',actor)).copyDropped,true);
 const jointActors=['joint0','joint1','joint2'];
 await Promise.all(jointActors.map(actor=>call('checkout',actor)));
 await Promise.all(jointActors.map((actor,index)=>call('jointedit',actor,{index})));
 const jointPublications=[];for(const actor of jointActors)jointPublications.push(await call('checkin',actor));
 assert.deepEqual(jointPublications.map(r=>r.nativeMergeInvocations),[0,1,1]);
 const joint=await call('read','reader3');
 assert.equal(joint.program.function0.name,'joint_function');
 assert.equal(joint.program.function0.returnType,'uint');
 assert.equal(joint.program.function0.parameters[0].name,'joint_parameter');
 assert.ok(joint.program.extended.actor0.locals.some(v=>v.name==='joint_local'));
 assert.equal(joint.program.extended.actor0.block.comment,'','Intentional native block-comment deletion must survive later merges');
 assert.equal(joint.versions.length,7);
 for(const actor of jointActors)assert.equal((await call('drop',actor)).copyDropped,true);
 const conflictCheckouts=await Promise.all([0,1].map(index=>call('checkout','conflict'+index)));
 const conflictEdits=await Promise.all([0,1].map(index=>call('edit','conflict'+index,{index,conflict:true})));
 await call('checkin','conflict0');
 const rejected=await call('checkin','conflict1',{},true);assert.match(rejected.error,/UnresolvedNativeConflict/);
 const afterConflict=await call('read','reader1');assert.equal(afterConflict.versions.length,8);
 assert.equal(afterConflict.program.function0.name,'conflict_actor_0');
 const dropRejected=await call('drop','conflict1',{},true);assert.match(dropRejected.message,/unpublished checkout/);
 const retained=await call('local','conflict1');assert.deepEqual(retained.program,conflictEdits[1].local,'Every recorded local function and type field must survive conflict');
 assert.ok(retained.checkouts.some(c=>c.id===conflictCheckouts[1].checkoutId&&c.version===7),'The original unresolved checkout must survive');
 const conflictCases=[];let expectedHead=8;
 for(const [kind,prefix,reader]of [['function','fconflict','reader4'],['builtin-return','tconflict','reader8'],['builtin-return-reverse','uconflict','reader9'],['bytes','bconflict','reader5'],['block-comment','mconflict','reader6'],['block-comment-clear','nconflict','reader7']]){
  const clients=[prefix+'0',prefix+'1'];
  const held=await Promise.all(clients.map(actor=>call('checkout',actor)));
  const edited=await Promise.all(clients.map((actor,index)=>call('conflictedit',actor,{index,kind})));
  assert.deepEqual(edited[0].before,edited[1].before,'Conflict proposals must share the same recorded baseline');
  if(kind==='builtin-return'||kind==='builtin-return-reverse'){
   const target=kind==='builtin-return'?'function0':'function1';
   assert.notEqual(edited[0].local[target].returnType,edited[0].before[target].returnType,'First return proposal must change its baseline');
   assert.notEqual(edited[1].local[target].returnType,edited[1].before[target].returnType,'Second return proposal must change its baseline');
   assert.notEqual(edited[0].local[target].returnType,edited[1].local[target].returnType);
  }
  await call('checkin',clients[0]);expectedHead++;
  const failed=await call('checkin',clients[1],{},true);assert.match(failed.error,/UnresolvedNativeConflict/);
  const observed=await call('read',reader);assert.equal(observed.versions.length,expectedHead);
  if(kind==='function')assert.equal(observed.program.function0.returnType,'Record0 *');
  else if(kind==='builtin-return')assert.equal(observed.program.function0.returnType,'float');
  else if(kind==='builtin-return-reverse')assert.equal(observed.program.function1.returnType,'double');
  else if(kind==='bytes')assert.equal(observed.program.extended.conflictByte,0x10);
  else if(kind==='block-comment')assert.equal(observed.program.extended.actor1.block.comment,'');
  else assert.equal(observed.program.extended.actor2.block.comment,'changed_comment');
  const privateView=await call('local',clients[1]);assert.deepEqual(privateView.program,edited[1].local);
  assert.ok(privateView.checkouts.some(c=>c.id===held[1].checkoutId&&c.version===expectedHead-1));
  assert.equal((await call('drop',clients[1],{},true)).state,'failed');
  conflictCases.push({kind,serverVersion:expectedHead,localProjectionPreserved:true,checkoutPreserved:true,unpublishedCopyDropRefused:true});
 }
 for(const source of fixtureFiles)assert.equal(hash(await readFile(source)),sourceHashes[basename(source)],'Compiled fixture source changed during proof');
 assert.equal(hash(await readFile(runnerFile)),runnerHash,'Runner changed during proof');
 assert.deepEqual(await Promise.all(jars.map(async path=>hash(await readFile(path)))),runtimeInventory.map(f=>f.sha256),'Installed runtime JARs changed during proof');
 receipt={schema:2,scope:'extended native headless multi-agent merge prototype',platform:process.platform,ghidra:'12.1.2',agents:3,
  normalIndependentCheckouts:true,functionsAndSignaturesCombined:true,structureChangesCombined:true,nativeDivergentMerges:4,
  stockResolverSelection:true,sharedFunctionIndependentChangesCombined:true,conflictCases,
  testedCategories:['function names','signatures and parameters','stack locals','namespaces and labels','function creation and deletion','instructions','defined data','memory bytes','memory block attributes','structures, type renames and deletions','enums','unions','typedefs','type-use dependencies','references','comments','bookmarks','equates','user properties','program options','program trees','function tags','register context','external functions and library paths'],
  returnConflictUsesTypesPresentBeforeConflictCheckouts:true,distinctCreatedTypeUniversalIdsVerified:true,
  resolvedHeadlessAdapterCase:{case:'Concurrent first-time float/double returns on one function',
   cause:'Missing headless function-conflict seam: null GUI panel exception is swallowed before the rejection hook',
   previousEvidence:'native-merge-proof-A8uqWN/authoritative-readback.json',
   resolution:'Route the native conflict to the headless rejection hook before GUI setup; native type detection/remapping is unchanged'},
  conflictRefused:true,conflictingLocalWorkRetained:true,unpublishedCopyDropRefused:true,independentServerReadback:true,guiWindows:0,
  upstreamListingSha256:hash(original),patchedListingSha256:hash(patched),uiSeamPatches:changes.length,
  upstreamProjectFileSha256:hash(fileData),patchedProjectFileSha256:hash(patchedFileData),headlessGuardPatches:2,copiesDropped:6,
  upstreamProgramContextSha256:hash(contextSource),patchedProgramContextSha256:hash(patchedContext),programContextUiPatches:1,
  upstreamExternalMergerSha256:hash(externalSource),patchedExternalMergerSha256:hash(patchedExternal),externalUiPatches:2,
  upstreamFunctionMergerSha256:hash(functionSource),patchedFunctionMergerSha256:hash(patchedFunction),functionConflictUiPatches:1,
  nativeCompatibilityFix:{class:'MemoryMergeManager',upstreamSha256:hash(memorySource),patchedSha256:hash(patchedMemory),
   reason:'Unchanged null comment wrongly clears latest; delete-vs-update conflict detection is asymmetric',
   unpatchedLossReproducedIn:'native-merge-proof-4VUDaO',checks:['unchanged null preserves incoming comment','intentional clear survives later merges','clear-vs-update conflict','update-vs-clear conflict']},
  sourceHashes,startedAt,finishedAt:new Date().toISOString(),runtimeClasspathSha256:hash(JSON.stringify(runtimeInventory)),runtimeJarCount:jars.length,installedJarsUnchanged:true,
  limitations:['Synthetic native program; bounded observations are not full database equivalence','Stock resolver selection; headless adapter and one documented native memory-comment compatibility fix, not an unmodified-stock support claim','No conflict resolution or migration/GC implemented','No public CLI integration, crash recovery or separate-user publication authorization proof','Memory layout changes and arbitrary overlapping structural changes are not claimed']};
 await writeFile(join(root,'results.json'),JSON.stringify(results,null,2));
 }
 }
}catch(error){receipt=undefined;console.error(String(error.stderr??error.stack));process.exitCode=1;}
finally{for(const child of [...children].reverse())await stop(child);}
if(receipt)receipt.ownedNativeProcessesExited=[...children].every(child=>child.exitCode!==null||child.signalCode!==null);
if(receipt){await writeFile(join(root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
console.log(JSON.stringify({event:'fixture_retained',root,success:!!receipt}));
