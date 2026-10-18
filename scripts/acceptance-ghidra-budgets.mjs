// Installed public CLI; isolated Factory storage/owner, disposable native input only.
// Arguments: package-root diagnostics-directory input ghidra-home java import|save|abandon [analyzer-module]
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
const [packageRoot,directory,input,ghidra,java,scenario,module]=process.argv.slice(2);
assert.ok(['import','save','abandon','recover-import'].includes(scenario));
assert.equal(process.platform,'win32','This fixture gate records Windows headless behavior');
const f=await createPublicFixture(packageRoot,directory),call=f.call,inputHash=digest(await readFile(input));
let scope,complete=false;
const selected=()=>['--session',scope.session,'--target',scope.target];
const option=async(group,name)=>{
 const inventory=await call(['ghidra','program','get-program-options',...selected()]);assert.ok(Array.isArray(inventory.value.groups));if(!inventory.value.groups.some(g=>g===group||g.name===group))return undefined;
 const r=await call(['ghidra','program','get-program-options',...selected(),'--group',group]);
 const row=r.value.options.find(o=>o.name===name);return row?.value;
};
try{
 await call(['permissions','grant','Destructive']);
 await call(['profile','set',f.profile,'--java',resolve(java),'--ghidra-home',resolve(ghidra),'--max-contexts','1',
  '--initial-import-seconds',scenario==='recover-import'?'1':'3600','--save-seconds',scenario==='abandon'?'1':'120']);
 if(scenario==='import'){
  assert.ok(module,'Supply the compiled LongBudget module');
  const m=await call(['ghidra','extensions','inspect','--directory',resolve(module)]);
  await call(['ghidra','extensions','install','--directory',resolve(module),'--sha256',m.sha256]);
  await call(['ipc-server','stop']);
 }
 const open=['ghidra','open',resolve(input),'--session','new','--request-id','budget-open',...(scenario==='import'?[]:['--no-analysis'])];
 if(scenario==='recover-import'){
  const interrupted=await call(open,{allowFailure:true,timeout:150000});assert.notEqual(interrupted.code,0);
  assert.equal(interrupted.value.detail.phase,'initial-import');assert.equal(interrupted.value.detail.timeoutMilliseconds,1000);
  await call(['ghidra','budgets','set','--initial-import-seconds','3600']);
  scope=await call(open,{timeout:150000});assert.equal(scope.session,interrupted.value.session);assert.equal(scope.target,interrupted.value.target);
  assert.deepEqual(await call(open),scope);
 }else scope=await call(open,{timeout:900000});
 assert.equal(scope.sharedRevision,'R1');
 if(scenario==='import'){
  assert.equal(await option('LongBudgetFixture','completed'),'true');
  assert.deepEqual(await call(open),scope);
 }else if(scenario!=='recover-import'){
  const code=await readFile(new URL('../tests/acceptance/fixtures/ghidra-budgets/SlowSaveFixture.java',import.meta.url),'utf8');
  const run=['ghidra','scripts','run-inline',...selected(),'--code',code,'--request-id','budget-script'];
  const result=await call(run,{allowFailure:true,timeout:150000});
  if(scenario==='save'){
   assert.equal(result.code,0);assert.equal(result.value.state,'applied');
   assert.deepEqual(await call(run),result.value);
   assert.equal(await option('SlowSaveFixture','marker'),'saved-once');
   assert.equal(await option('SlowSaveFixture','executions'),'1');
  }else{
   assert.notEqual(result.code,0);assert.equal(result.value.phase,'save');assert.equal(result.value.timeoutMilliseconds,1000);
   const status=await call(['sessions','status',scope.session,'--target',scope.target]);
   assert.equal(status.ghidra.unresolvedRequests.length,1);assert.equal(status.ghidra.unresolvedRequests[0].detail.phase,'save');
   assert.equal(status.ghidra.unresolvedRequests[0].detail.savedSnapshot,undefined);
   const abandon=['ghidra','abandon',...selected(),'--request-id','budget-script','--acknowledge-unknown-effects'];
   assert.notEqual((await call(abandon,{allowFailure:true})).code,0,'A live worker must block abandonment');
   const processes=await call(['tools','processes','--tool','ghidra']);
   const worker=processes.items.find(p=>p.role==='context'&&p.session===scope.session&&p.target===scope.target);assert.ok(worker);
   await call(['tools','processes','kill',worker.id]);
   const abandoned=await call(abandon);assert.equal(abandoned.state,'abandoned');assert.equal(abandoned.outcome,'unknown');
   assert.deepEqual(await call(abandon),abandoned);
   assert.notEqual((await call(run,{allowFailure:true})).code,0);
   await call(['ghidra','open',...selected()]);
   assert.equal(await option('SlowSaveFixture','marker'),undefined,'Unproved native DB must not be adopted');
  }
 }
 await call(['ghidra','close',...selected()]);await call(['ghidra','open',...selected()]);
 if(scenario==='save'){
  assert.equal(await option('SlowSaveFixture','executions'),'1');
  await call(['ghidra','merge',...selected(),'--request-id','budget-merge']);
  await call(['ghidra','close',...selected()]);
  scope=await call(['ghidra','open',resolve(input),'--session','new']);assert.equal(scope.sharedRevision,'R2');
  assert.equal(await option('SlowSaveFixture','marker'),'saved-once');assert.equal(await option('SlowSaveFixture','executions'),'1');
 }
 await call(['ghidra','close',...selected()]);await call(['ghidra','server','stop']);
 assert.equal((await call(['ghidra','status'])).processes.length,0);assert.equal(digest(await readFile(input)),inputHash);
 complete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,scenario,state:'passed',scope:'Windows installed public CLI with controlled native delays',
  checks:{originalInputUnchanged:true,ownedNativeStopped:true,verifiedSavedView:true,requestNotReplayed:true},
  build:JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8'))},null,2)+'\n');
 console.log('Ghidra budget native gate PASS:',scenario);
}finally{if(!complete)console.error('Retain owned native diagnostics for recovery:',directory);await f.cleanup();}
