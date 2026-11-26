// Focused, opt-in native safety proof. All database writes belong to one newly created disposable fixture.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {ProfileSecrets} from '@eyeauras/cli-factory';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {Workspace} from '../skills/ghidra-coordinator/dist/src/workspace.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,nativeHelpers,nativeJvmDirectories} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {javaClasspathArguments} from '../skills/ghidra-coordinator/dist/src/tool-runtime/java-arguments.js';
import {readFile,writeFile,readdir,mkdir,realpath,rename} from 'node:fs/promises';
import {join,resolve,relative,isAbsolute,dirname,delimiter} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID,createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){
 const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;
 else{assert.ok(['--ghidra-home','--java','--output-base'].includes(arg));options[arg.slice(2)]=process.argv[++i];}
}
assert.equal(options.ack,true);for(const key of ['ghidra-home','java','output-base']){assert.ok(options[key]);options[key]=await realpath(resolve(options[key]));}
assert.ok(!Object.keys(process.env).some(k=>/^(CI|TEAMCITY_VERSION|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
const values={analysisDirectory:null,ghidraHome:options['ghidra-home'],java:options.java,maxContexts:4};
const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
console.log(JSON.stringify({event:'disposable_native_disposal_fixture',root:f.root}));
const ws=join(f.appArguments.AppDataDirectory,'workspace'),select=s=>['--session',s.session,'--target',s.target];
let app=f.createApplication(runtime=>createInsightCli({runtime}));const events=[],checks={};
const inputs=await nativeInputs(values),c={appArguments:f.appArguments,profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,fetch,
 secrets:new ProfileSecrets(f.secretStore,'insight-cli','default'),progress(){}};
const server=new GhidraServer(ws,inputs,c),exec=promisify(execFile);let binding,workspace;
const owned=async path=>{const actual=await realpath(path),inside=relative(await realpath(f.root),actual);assert.ok(inside&&!isAbsolute(inside)&&!inside.startsWith('..'));return actual;};
function context(scope){const db=new DatabaseSync(join(ws,'workspace.sqlite'),{readOnly:true});try{return JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(scope.session,scope.target).data);}finally{db.close();}}
async function cli(args){const result=await f.run(app,[...args,'--json']);events.push({args,...result});console.log(JSON.stringify({command:args.slice(0,3),exitCode:result.exitCode}));assert.equal(result.exitCode,0,result.stderr);return JSON.parse(result.stdout);}
const references=async target=>{try{return await readdir(join(ws,'ghidra-native','shared-views',target,'opened'));}catch(error){if(error.code==='ENOENT')return [];throw error;}};
async function native(checkout,operation,parameters={}){
 await owned(checkout.root);const owner=JSON.parse(await readFile(join(checkout.root,'native-owner.json')));
 const result=await server.nativeCheckout(binding,{root:checkout.root,owner,fileId:checkout.fileId,checkoutId:checkout.checkoutId,operation,...parameters});
 events.push({native:operation,root:checkout.root,parameters,result});return result;
}
let classes,compileRoot;
async function mutate(checkout,operation,parameters={}){
 const call=join(f.root,'mutation-'+randomUUID());await mkdir(call);await owned(checkout.root);
 const q=join(call,'request.json');await writeFile(q,JSON.stringify({root:checkout.root,owner:JSON.parse(await readFile(join(checkout.root,'native-owner.json'))),fileId:checkout.fileId,checkoutId:checkout.checkoutId,...parameters}));
 const args=['-Djava.awt.headless=true','-Dghidra.home='+inputs.ghidraHome,...nativeJvmDirectories(call),'-cp',compileRoot+delimiter+classes+delimiter+inputs.classpath,'NativeDisposalFixture',operation,q];
 await exec(inputs.java,await javaClasspathArguments(call,'ghidra',inputs.java,args),{env:{...process.env,...await server.credentials(binding,'publisher')},windowsHide:true,timeout:60000,maxBuffer:1024*1024});
}
async function directCheckout(target){
 const reservation=workspace.reserveOpen(target,'new',workspace.model(target).settings);workspace.recordRequest(reservation.request.id,'failed',{state:'fixture_control'});
 return (await new GhidraContexts(workspace,inputs,c,undefined,undefined,server).createNative(reservation.context)).nativeCheckout;
}
try{
 const file=join(f.root,'fixture.bin');await writeFile(file,Buffer.alloc(512,0x90));
 const a=await cli(['ghidra','open',file,'--session','new','--loader','ghidra.app.util.opinion.BinaryLoader','--language','x86:LE:64:default','--image-base','1000','--loader-options','{"Base Address":"0"}']);
 const first=context(a),names=await references(a.target);assert.ok(names.length>0,'Expected Ghidra open rewrite in this pinned native fixture');
 const reference=JSON.parse(await readFile(join(ws,'ghidra-native','shared-views',a.target,'opened',names[0])));assert.equal(reference.schema,2);
 assert.equal(reference.preOpen.fingerprint,reference.base);assert.equal(reference.preOpen.checkoutId,first.nativeCheckout.checkoutId);
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'released');checks.cleanFirstOpenReleased=true;
 // No private analysis was requested; first-import already produced the shared base before this worker opened it.
 await cli(['ghidra','open',...select(a)]);await cli(['ghidra','comments','set',...select(a),'--address','1000','--kind','eol','--text','SAVED_PRIVATE_WORK']);
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'retained');const dirty=context(a),oldRefs=await references(a.target);
 const restored={...dirty,state:'stopped',workingSnapshot:dirty.baseSnapshot,scalars:[],complexChanges:[],generation:dirty.generation+1};
 const db=new DatabaseSync(join(ws,'workspace.sqlite'));try{db.prepare('UPDATE contexts SET generation=?,data=? WHERE id=?').run(restored.generation,JSON.stringify(restored),dirty.id);}finally{db.close();}
 for(const receipt of [join(dirty.nativeCheckout.root,'process.json'),join(dirname(dirty.nativeCheckout.root),'current.json')])await rename(await owned(receipt),receipt+'.fixture-original');
 await cli(['ghidra','open',...select(a)]);assert.deepEqual(await references(a.target),oldRefs);
 assert.equal((await cli(['ghidra','comments','get',...select(a),'--address','1000','--kind','eol'])).text,'SAVED_PRIVATE_WORK');
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'retained');assert.equal(context(a).nativeCheckout.root,dirty.nativeCheckout.root);
 await cli(['ghidra','gc','--dry-run']);await cli(['ghidra','gc']);assert.ok((await readdir(dirty.nativeCheckout.root)).includes('view.rep'));
 await cli(['ghidra','open',...select(a)]);assert.equal((await cli(['ghidra','comments','get',...select(a),'--address','1000','--kind','eol'])).text,'SAVED_PRIVATE_WORK');
 checks.staleControlPreservesPrivateWork=true;
 const discarded=await cli(['ghidra','changes','discard',...select(a)]);assert.ok(discarded.retainedKeepFile);
 const empty=await cli(['ghidra','merge',...select(a)]);assert.ok(['empty','merged'].includes(empty.state));assert.equal(context(a).nativeCheckout.state,'dropped');
 await cli(['ghidra','open',...select(a)]);assert.equal((await cli(['ghidra','comments','get',...select(a),'--address','1000','--kind','eol'])).text,null);
 assert.equal((await cli(['ghidra','close',...select(a)])).checkout,'released');checks.discardEmptyMergeAndReopen=true;
 await app.dispose();app=f.createApplication(runtime=>createInsightCli({runtime}));binding=await server.ensure();workspace=new Workspace(ws,'default');
 classes=await nativeHelpers(ws,inputs,c);compileRoot=join(f.root,'fixture-classes');await mkdir(compileRoot);
 const source=fileURLToPath(new URL('../skills/ghidra-coordinator/tests/fixtures/native-merge/NativeDisposalFixture.java',import.meta.url));
 const javac=join(dirname(inputs.java),'javac'+(process.platform==='win32'?'.exe':''));
 const compileCall=join(f.root,'fixture-compile'),receiptCall=join(f.root,'fixture-receipts');await mkdir(compileCall);await mkdir(receiptCall);
 await exec(javac,await javaClasspathArguments(compileCall,'ghidra',javac,['-proc:none','-cp',classes+delimiter+inputs.classpath,'-d',compileRoot,source]),{windowsHide:true,timeout:60000,maxBuffer:1024*1024});
 const receiptArgs=['-cp',compileRoot+delimiter+classes+delimiter+inputs.classpath,'NativeDisposalFixture','receipts'];
 assert.match((await exec(inputs.java,await javaClasspathArguments(receiptCall,'ghidra',inputs.java,receiptArgs),{windowsHide:true})).stdout,/RELEASE_RECEIPTS_VERIFIED/);
 checks.exactAndLegacyReleaseReceipts=true;
 // Dirty Update creates its .keep through saveAs, so its actual buffers have a new DB ID, not the original fingerprint.
 const left=await cli(['ghidra','open','--target',a.target,'--session','new']),right=await cli(['ghidra','open','--target',a.target,'--session','new']);
 await cli(['ghidra','comments','set',...select(left),'--address','1000','--kind','eol','--text','SHARED_DIRTY_UPDATE']);
 await cli(['ghidra','comments','set',...select(right),'--address','1001','--kind','eol','--text','PRIVATE_DIRTY_UPDATE']);
 const beforeUpdate=context(right).nativeCheckout;await cli(['ghidra','merge',...select(left)]);
 const refreshed=await cli(['ghidra','refresh',...select(right),'--request-id','dirty-backup-update']);assert.equal(refreshed.nativeMergeInvocations,1);
 assert.equal(context(right).nativeCheckout.checkoutId,beforeUpdate.checkoutId);
 const read=new DatabaseSync(join(ws,'workspace.sqlite'),{readOnly:true});let updateRequest;
 try{updateRequest=read.prepare('SELECT id FROM requests WHERE caller_id=?').get('dirty-backup-update').id;}finally{read.close();}
 const update=JSON.parse(await readFile(join(beforeUpdate.root,'operations',updateRequest+'-update.json'))),keepName=right.target+'.bin.keep',backup=update.result.disposableBackups[keepName];
 assert.equal(update.backupAbsent,true);assert.equal(update.backupExpected,true);assert.equal(backup.schema,1);assert.equal(typeof backup.fileId,'string');
 assert.match(backup.fingerprint,/^[a-f0-9]{64}$/);assert.notEqual(backup.fingerprint,update.before.fingerprint,'Pinned saveAs must generate distinct DB-ID buffers');
 assert.equal((await cli(['ghidra','comments','get',...select(right),'--address','1000','--kind','eol'])).text,'SHARED_DIRTY_UPDATE');
 assert.equal((await cli(['ghidra','comments','get',...select(right),'--address','1001','--kind','eol'])).text,'PRIVATE_DIRTY_UPDATE');
 await cli(['ghidra','merge',...select(right)]);assert.equal(context(right).nativeCheckout.state,'dropped');assert.ok(!(await readdir(beforeUpdate.root)).includes('view.rep'));
 await cli(['ghidra','open',...select(right)]);assert.equal((await cli(['ghidra','comments','get',...select(right),'--address','1001','--kind','eol'])).text,'PRIVATE_DIRTY_UPDATE');
 assert.equal((await cli(['ghidra','close',...select(right)])).checkout,'released');checks.dirtyUpdateBackupPublishedReleasedAndReopened=true;
 for(const mutation of ['base-fallback','edit','nested','backup']){
  const checkout=await directCheckout(a.target),status=await native(checkout,'status');assert.equal(status.modified,false);
  const baseView=JSON.parse(await readFile(await workspace.artifacts.verify(workspace.contextById(checkout.context).baseSnapshot)));assert.equal(status.saved.fingerprint,baseView.fingerprint);
  const proof={verifiedVersion:checkout.baseVersion,fingerprint:status.saved.fingerprint};
  if(mutation==='base-fallback')Object.assign(proof,{opened:reference.opened===proof.fingerprint?reference.base:reference.opened,openedVerified:true});else await mutate(checkout,mutation);
  const refusal=await native(checkout,'release',proof);assert.equal(refusal.state,'unknown',mutation);
  const after=await native(checkout,'status');assert.equal(after.checkedOut,true);assert.equal(after.checkoutId,checkout.checkoutId);
  assert.ok((await readdir(checkout.root)).includes('view.rep'));checks[mutation]=true;
 }
 // A valid native-created .keep remains disposable only while its actual saved bytes match that operation's receipt.
 const keepCheckout=await directCheckout(a.target);await mutate(keepCheckout,'edit');
 const discard=await native(keepCheckout,'discard',{request:'q_'+randomUUID()});assert.equal(discard.state,'discarded');assert.ok(discard.disposableBackups);
 const kept={...keepCheckout,checkoutId:discard.checkoutId,baseVersion:discard.baseVersion};await mutate(kept,'edit-backup');
 assert.equal((await native(kept,'release',{verifiedVersion:kept.baseVersion,fingerprint:discard.saved.fingerprint})).state,'unknown');
 assert.equal((await native(kept,'status')).checkedOut,true);checks.changedNativeBackupRetained=true;
 // Stop at the real server-termination/local-deletion boundary, retaining the native file as hijacked.
 for(const fault of ['none','edit','nested','legacy-intent']){
  const checkout=await directCheckout(a.target),before=await native(checkout,'status'),proof={verifiedVersion:checkout.baseVersion,fingerprint:before.saved.fingerprint};
  await mutate(checkout,'interrupt-release',proof);
  const interrupted=await native(checkout,'status');assert.equal(interrupted.checkedOut,false);assert.ok(interrupted.projectFiles.includes(checkout.path.slice(1)));
  assert.equal(interrupted.saved.fingerprint,before.saved.fingerprint);assert.equal(interrupted.fileId,checkout.fileId);
  if(fault==='legacy-intent'){
   const path=join(checkout.root,'released.json'),intent=JSON.parse(await readFile(path));delete intent.fileId;delete intent.savedFingerprint;await writeFile(path,JSON.stringify(intent));
  }else if(fault!=='none')await mutate(checkout,fault);
  const result=await native(checkout,'release',proof);
  if(fault==='none'){
   assert.equal(result.state,'released');assert.equal((await native(checkout,'drop',proof)).state,'dropped');assert.ok(!(await readdir(checkout.root)).includes('view.rep'));
  }else{
   assert.equal(result.state,'unknown');assert.ok((await readdir(checkout.root)).includes('view.rep'));
   assert.equal(JSON.parse(await readFile(join(checkout.root,'released.json'))).state,'release_intent');
  }
  checks['interruptedUndo-'+fault]=true;
 }
 // Both completed legacy release and interrupted legacy intent recover without undoing an unrelated checkout.
 for(const legacy of ['released','release_intent']){
  const checkout=await directCheckout(a.target),status=await native(checkout,'status'),proof={verifiedVersion:checkout.baseVersion,fingerprint:status.saved.fingerprint};
  assert.equal((await native(checkout,'release',proof)).state,'released');const path=join(checkout.root,'released.json');
  await writeFile(path,JSON.stringify({state:legacy,checkoutId:checkout.checkoutId,version:checkout.baseVersion,fingerprint:proof.fingerprint}));
  assert.equal((await native(checkout,'release',proof)).state,'released');
  if(legacy==='released')await writeFile(join(checkout.root,'view.gpr'),'partially deleted project');
  assert.equal((await native(checkout,'drop',proof)).state,'dropped');
 }
 checks.legacyInterruptedDisposalRecovered=true;
 const checkout=await directCheckout(a.target),status=await native(checkout,'status'),proof={verifiedVersion:checkout.baseVersion,fingerprint:status.saved.fingerprint};
 assert.equal((await native(checkout,'release',proof)).state,'released');
 assert.equal((await native(checkout,'drop',{...proof,opened:reference.opened===proof.fingerprint?reference.base:reference.opened,openedVerified:true})).state,'unknown');
 assert.ok((await readdir(checkout.root)).includes('view.rep'));assert.equal((await native(checkout,'drop',proof)).state,'dropped');checks.changedReleaseProofRefused=true;
}finally{
 workspace?.close();await app.dispose();await server.stop();
 const receipt={schema:1,scope:'focused disposable native first-open and release safety',root:f.root,checks,events,
  sourceSha256:createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/references/native/InsightNativeCheckout.java',import.meta.url))).digest('hex'),
  limits:['Default backend CLI first-open/recovery and direct native final-release faults; no concurrent race scheduling or installed-package proof']};
 await writeFile(join(f.root,'native-disposal-results.json'),JSON.stringify(receipt,null,2));
 await writeFile(join(options['output-base'],'native-disposal-results.json'),JSON.stringify(receipt,null,2));
 console.log(JSON.stringify({root:f.root,checks,results:join(f.root,'native-disposal-results.json')}));
}
