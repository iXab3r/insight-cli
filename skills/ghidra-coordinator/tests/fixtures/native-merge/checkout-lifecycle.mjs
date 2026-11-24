import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';

// A fixture scenario, not another public CLI or coordinator implementation.
export async function proveCheckoutLifecycle({root,id,port,java,classpath,directories,command,privateEnv,publisher,reader}) {
 const results=[];
 async function call(operation,actor,role,extra={},failure=false) {
  const invocation=join(root,'calls',operation+'-'+actor+'-'+randomUUID());await mkdir(invocation,{recursive:true});
  const request=join(invocation,'request.json');
  await writeFile(request,JSON.stringify({root,id,port,operation,actor,role,...extra}),{flag:'wx',mode:0o600});
  const environment={...privateEnv,...(role==='worker'?{}:{PROOF_ROLE_PASSWORD:role==='publisher'?publisher:reader})};
  let result,error;
  try {result=await command(java,[...directories(invocation),'-Xmx768m','-cp',classpath,'NativeCheckoutLifecycle',request],invocation,120000,environment);}
  catch(caught){result=caught;error=caught;}
  const stdout=result.stdout??'',stderr=String(result.stderr??error?.stack??'');
  for(const secret of [publisher,reader])assert.ok(!stdout.includes(secret)&&!stderr.includes(secret),'Fixture exposed a role credential');
  await writeFile(join(invocation,'stdout.json'),stdout);await writeFile(join(invocation,'stderr.log'),stderr);
  if(error&&!failure)throw error;
  if(failure)assert.equal(error?.code,1,'Expected native rejection, not success or timeout');
  const value=JSON.parse(stdout.trim());results.push(value);
  console.log(JSON.stringify({event:'native_lifecycle_step',operation,actor,role,state:value.state??'ok',nativeMergeInvocations:value.nativeMergeInvocations}));
  return value;
 }
 function sameIdentity(a,b) {assert.equal(a.project,b.project);assert.equal(a.fileId,b.fileId);}
 function sameSaved(a,b) {sameIdentity(a,b);assert.deepEqual(a.program,b.program);assert.deepEqual(a.changes,b.changes);}
 function offline(value) {assert.equal(value.repositoryConnected,false);assert.equal(value.credentialVariablesAbsent,true);assert.ok(value.authenticationRefusals>0);assert.equal(value.checkedOut,true);}
 const keys=['functionPath','locals','tags','instruction','comment','createdFunction','definedData','record','enumValue','union','typedef','typeBindings','deletedFunctionAbsent','deletedTypeAbsent','renamedType','label','references','bookmark','equate','property','option','block','register','external','externalPath','patchedByte'];
 function actorSurvives(actual,expected,index) {
  assert.deepEqual(actual['function'+index],expected['function'+index]);assert.deepEqual(actual['type'+index],expected['type'+index]);
  for(const key of keys)assert.deepEqual(actual.extended['actor'+index][key],expected.extended['actor'+index][key],'Lost actor '+index+' '+key);
 }
 const baseline=await call('baseline','baseline','publisher');assert.equal(baseline.versions.length,1);
 const denied=await call('checkout','denied','reader',{},true);
 assert.equal(denied.serverReadOnly,true);assert.match(denied.message,/checkout rejected|read.only|permission|access/i);
 const clients=await Promise.all(['agenta','agentb'].map(actor=>call('checkout',actor,'publisher')));
 assert.ok(clients.every(c=>c.baseVersion===1));assert.notEqual(clients[0].checkoutId,clients[1].checkoutId);
 assert.equal(clients[0].fileId,clients[1].fileId);
 const edited=await Promise.all(['agenta','agentb'].map((actor,index)=>call('edit',actor,'worker',{index})));
 for(let i=0;i<2;i++) {
  offline(edited[i]);sameIdentity(clients[i],edited[i]);assert.equal(edited[i].localVersion,1);
  assert.ok(edited[i].changes.dataTypeAdditions.length>0);assert.ok(edited[i].changes.symbolAdditions.length>0);
 }
 const restarted=await call('local','agentb','worker');offline(restarted);sameSaved(edited[1],restarted);
 assert.notEqual(restarted.pid,edited[1].pid,'Restart must use a separate worker JVM');
 const forbidden=await call('checkin','agentb','worker',{},true);assert.match(forbidden.error,/NotConnectedException/);
 const unchanged=await call('read','readbefore','reader');assert.equal(unchanged.versions.length,1);assert.equal(unchanged.checkouts.length,2);
 assert.deepEqual(unchanged.program,baseline.program);
 const serviceReopen=await call('local','agentb','publisher');sameSaved(restarted,serviceReopen);
 assert.equal(serviceReopen.checkoutId,clients[1].checkoutId);assert.equal(serviceReopen.baseVersion,1);
 const aPublished=await call('checkin','agenta','publisher');assert.equal(aPublished.versions.length,2);assert.equal(aPublished.nativeMergeInvocations,0);
 const beforeUpdate=await call('local','agentb','worker');offline(beforeUpdate);sameSaved(restarted,beforeUpdate);
 // Dirty native Update: advance B's existing checkout to R2, leave the server at R2.
 const updated=await call('update','agentb','publisher');
 assert.equal(updated.nativeMergeInvocations,1);assert.equal(updated.checkoutBefore,clients[1].checkoutId);
 assert.equal(updated.checkoutId,clients[1].checkoutId);assert.equal(updated.baseBefore,1);assert.equal(updated.baseVersion,2);
 assert.equal(updated.versions.length,2);assert.equal(updated.checkouts.length,1);sameIdentity(restarted,updated);
 assert.ok(updated.projectFiles.includes('fixture.keep'),'Native dirty Update must account for its keep file');
 actorSurvives(updated.program,edited[0].program,0);actorSurvives(updated.program,edited[1].program,1);
 const updatedRestart=await call('local','agentb','worker');offline(updatedRestart);sameSaved(updated,updatedRestart);assert.equal(updatedRestart.localVersion,2);
 const postUpdate=await call('edit','agentb','worker',{index:2});offline(postUpdate);
 actorSurvives(postUpdate.program,edited[0].program,0);actorSurvives(postUpdate.program,edited[1].program,1);
 const bPublished=await call('checkin','agentb','publisher');assert.equal(bPublished.versions.length,3);assert.equal(bPublished.nativeMergeInvocations,0);
 const shared=await call('read','readfinal','reader');assert.equal(shared.serverReadOnly,true);assert.equal(shared.versions.length,3);assert.equal(shared.checkouts.length,0);
 for(let i=0;i<3;i++)actorSurvives(shared.program,postUpdate.program,i);
 for(const actor of ['agenta','agentb'])assert.equal((await call('drop',actor,'publisher')).copyDropped,true);
 // Clean Update follows the native fast path; it retains the original checkout too.
 const clean=await call('checkout','clean','publisher');
 const conflicts=await Promise.all(['conflicta','conflictb'].map(actor=>call('checkout',actor,'publisher')));
 const proposals=await Promise.all(['conflicta','conflictb'].map((actor,index)=>call('edit',actor,'worker',{index,conflict:true})));
 await call('checkin','conflicta','publisher');
 const cleanUpdated=await call('update','clean','publisher');assert.equal(cleanUpdated.nativeMergeInvocations,0);
 assert.equal(cleanUpdated.checkoutId,clean.checkoutId);assert.equal(cleanUpdated.baseBefore,3);assert.equal(cleanUpdated.baseVersion,4);
 assert.equal(cleanUpdated.versions.length,4);assert.ok(!cleanUpdated.projectFiles.includes('fixture.keep'));
 const cleanRestart=await call('local','clean','worker');offline(cleanRestart);sameSaved(cleanUpdated,cleanRestart);
 // Release the clean checkout through Ghidra without making a spurious version.
 const released=await call('releaseclean','clean','publisher');assert.equal(released.versions.length,4);assert.equal(released.checkedOut,false);
 assert.equal((await call('drop','clean','publisher')).copyDropped,true);
 const failed=await call('update','conflictb','publisher',{},true);assert.match(failed.error,/UnresolvedNativeConflict/);
 const retained=await call('local','conflictb','worker');offline(retained);sameSaved(proposals[1],retained);assert.equal(retained.localVersion,3);
 const authoritative=await call('read','readafterconflict','reader');assert.equal(authoritative.versions.length,4);
 actorSurvives(authoritative.program,proposals[0].program,0);
 assert.ok(authoritative.checkouts.some(c=>c.id===conflicts[1].checkoutId&&c.version===3));
 assert.equal((await call('drop','conflictb','publisher',{},true)).state,'failed');
 assert.equal((await call('drop','conflicta','publisher')).copyDropped,true);
 for(const actor of ['denied','readbefore','readfinal','readafterconflict'])assert.equal((await call('drop',actor,'reader')).copyDropped,true);
 assert.equal((await call('drop','baseline','publisher')).copyDropped,true);
 // Every saved native project is checked for leaked plaintext role credentials.
 let scannedFiles=0;
 async function scan(directory) {for(const entry of await readdir(directory,{withFileTypes:true})) {
  const path=join(directory,entry.name);if(entry.isDirectory())await scan(path);
  else if(entry.isFile()){const data=await readFile(path);for(const secret of [publisher,reader])assert.ok(!data.includes(Buffer.from(secret)),'Credential persisted in native project');scannedFiles++;}
 }}
 await scan(join(root,'projects'));
 assert.ok(results.every(r=>r.guiWindows===0||r.state==='failed'));
 await writeFile(join(root,'results.json'),JSON.stringify(results,null,2));
 return {schema:1,scope:'native checkout lifecycle and authority proof',ghidra:'12.1.2',
  serverAccounts:{publisher:'admin',reader:'read-only',worker:'no credentials; native authentication refused'},
  sameNativeProjectsReopened:true,checkoutIdsPreserved:true,nativeChangeSetsPreservedAcrossRestart:true,
  offlineWorkerCheckinRefused:true,readerCheckoutRefused:true,dirtyNativeUpdate:{from:1,to:2,serverVersionUnchanged:true,keepFileObserved:true,nativeMergeInvocations:1},
  cleanNativeUpdate:{from:3,to:4,nativeMergeInvocations:0},
  editsAfterUpdatePublished:true,independentReadback:true,confirmedPublishedCopiesDropped:3,cleanCheckoutReleasedAndDropped:true,evidenceProjectsDropped:5,
  conflictingUpdate:{refused:true,localProjectionAndChangeSetsPreserved:true,checkoutAndBasePreserved:true,dropRefused:true},
  plaintextRoleCredentialsAbsentFromRetainedProjects:true,projectFilesScanned:scannedFiles,guiWindows:0,
  retained:['conflictb: unresolved private work, original checkout/base; server and call evidence retained'],
  limitations:['Disposable fixture only; no product CLI migration or GC','Cooperative worker process credential isolation, not an OS security boundary against hostile same-user code','Bounded function/type and extended object projections, not full database equivalence','No process kill, unknown check-in recovery or concurrent service writers tested','Pinned headless adapter and documented native memory-comment compatibility fix required']};
}
