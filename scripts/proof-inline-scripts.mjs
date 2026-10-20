// Opt-in public CLI proof. Every program, file, script and process belongs to this disposable invocation.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile,readFile,stat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
import {nativeProofGuard} from './native-proof-guard.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const root=resolve(o.root);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const f=await createPublicFixture(resolve(o.package),root),exec=promisify(execFile),checks={},cleanup=[],scopes=[];let passed=false;
const scoped=(s,args,options)=>f.call(['ghidra',...args,'--session',s.session,'--target',s.target],options);
const journal=s=>{const db=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{
 const d=JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(s.session,s.target).data);
 return {generation:d.generation,snapshot:d.workingSnapshot,scalars:d.scalars,complex:d.complexChanges,requests:db.prepare('SELECT id,state,data FROM requests WHERE context=? ORDER BY rowid').all(d.id).map(x=>({...x,data:JSON.parse(x.data)}))};
}finally{db.close();}};
const failure=(result,stage,safe)=>{assert.notEqual(result.code,0);assert.equal(result.value.execution.stage,stage);assert.equal(result.value.state,safe?'rejected':'unknown');assert.equal(result.value.execution.userCode,safe?'not_started':'may_have_started');};
try{
 await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);
 const source=join(root,'fixture.c'),input=join(root,'fixture.exe'),obj=join(root,'fixture.obj');await writeFile(source,'int main(void){return 7;}\n');
 await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,obj]);
 const open=async()=>{const s=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);scopes.push(s);return s;};
 const s=await open(),before=journal(s),inputHash=digest(await readFile(input));
 const code='currentProgram.getFunctionManager().getFunctionBefore(currentAddress);';
 const args=['scripts','run-inline','--code',code,'--request-id','benchmark-getFunctionBefore'];
 const bad=await scoped(s,args,{allowFailure:true});failure(bad,'compile',true);
 assert.match(bad.value.diagnostic.message,/cannot find symbol/);assert.match(bad.value.compilerOutput.text,/getFunctionBefore/);assert.ok(bad.value.diagnostics.some(d=>d.severity==='error'&&d.sourceLine===1));
 const after=journal(s);assert.equal(after.requests.at(-1).state,'failed');assert.equal(after.generation,before.generation);assert.deepEqual(after.snapshot,before.snapshot);assert.deepEqual(after.complex,before.complex);
 assert.deepEqual((await scoped(s,args,{allowFailure:true})).value,bad.value);assert.equal(journal(s).requests.length,after.requests.length);
 assert.notEqual((await scoped(s,['scripts','run-inline','--code','println("changed");','--request-id','benchmark-getFunctionBefore'],{allowFailure:true})).code,0);assert.equal(journal(s).requests.length,after.requests.length);
 assert.equal((await f.call(['sessions','status',s.session,'--target',s.target])).ghidra.state,'ready');
 assert.equal((await scoped(s,['analysis','navigation','--max-scan','128'])).value.functions.sampled>0,true);
 checks.benchmarkCompileDiagnosticAndAccessibleContext=true;checks.rejectedReplayDoesNotExecuteOrSave=true;
 const loadMarker=join(root,'load-must-not-run');
 const loadCode='public class NotAScript { static { try { java.nio.file.Files.writeString(java.nio.file.Path.of('+JSON.stringify(loadMarker)+'),"bad"); } catch(Exception e) { throw new RuntimeException(e); } } }';
 const load=await scoped(s,['scripts','run-inline','--code',loadCode,'--request-id','load-reject'],{allowFailure:true});failure(load,'load',true);await assert.rejects(stat(loadMarker),{code:'ENOENT'});
 assert.equal((await f.call(['sessions','status',s.session,'--target',s.target])).ghidra.state,'ready');checks.loadRejectionDoesNotInitialize=true;
 const ctorLoadCode='public class NoDefaultConstructor extends ghidra.app.script.GhidraScript { static { try { java.nio.file.Files.writeString(java.nio.file.Path.of('+JSON.stringify(loadMarker)+'),"bad"); } catch(Exception e) { throw new RuntimeException(e); } } public NoDefaultConstructor(int arg){} public void run(){} }';
 const missingCtor=await scoped(s,['scripts','run-inline','--code',ctorLoadCode,'--request-id','missing-default-constructor'],{allowFailure:true});failure(missingCtor,'load',true);assert.match(missingCtor.value.diagnostic.message,/NoSuchMethodException/);await assert.rejects(stat(loadMarker),{code:'ENOENT'});checks.constructorResolutionBeforeInitialization=true;
 const longType='Type_'+('a'.repeat(350));
 const floodCode='class '+longType+'{}\n'+longType+' v=null;\n'+Array.from({length:140},()=>'v.missing();').join('\n');
 const flood=await scoped(s,['scripts','run-inline','--code',floodCode,'--request-id','bounded-compiler-diagnostics'],{allowFailure:true});failure(flood,'compile',true);assert.equal(flood.value.compilerOutput.truncated,true);assert.ok(Buffer.byteLength(flood.value.compilerOutput.text)<=32772);assert.ok(flood.value.diagnostics.length<=100);checks.boundedCompilerDiagnostics=true;
 // Same explicit class name, fresh attempt, plus snippet literals that resemble declarations.
 const good='public class NotAScript extends ghidra.app.script.GhidraScript { public void run(){println("FRESH_CLASS_OK");} }';
 const fixed=await scoped(s,['scripts','run-inline','--code',good,'--request-id','corrected-new-request']);assert.equal(fixed.state,'applied');assert.match(fixed.value.output,/FRESH_CLASS_OK/);
 const literal=await scoped(s,['scripts','run-inline','--code','println("public class Fake extends GhidraScript");','--request-id','literal-not-declaration']);assert.equal(literal.state,'applied');checks.correctedRequestAndFreshClassLoader=true;
 const quoted=await scoped(s,['scripts','run-inline','--code','import java.util.List;\nprint(String.valueOf(List.of(getScriptArgs()).size()));','--args','first second','--request-id','snippet-import-args']);assert.equal(quoted.state,'applied');assert.match(quoted.value.output,/2/);checks.importsAndArgs=true;
 for(const stage of ['initialize','construct','execute']){
  const own=await open(),marker=join(root,stage+'-effect');
  const effect='java.nio.file.Files.writeString(java.nio.file.Path.of('+JSON.stringify(marker)+'),"effect");';
  const fail='throw new RuntimeException("owned-'+stage+'-failure");';
  let source;
  if(stage==='initialize')source='public class InitializerFixture extends ghidra.app.script.GhidraScript { static { try {'+effect+'if(System.nanoTime()!=0) '+fail+'}catch(Exception e){throw new RuntimeException(e);} } public void run(){} }';
  else if(stage==='construct')source='public class ConstructorFixture extends ghidra.app.script.GhidraScript { public ConstructorFixture() throws Exception {'+effect+fail+'} public void run(){} }';
  else source=effect+'println("INSIGHT_QUERY:{\\\"execution\\\":{\\\"stage\\\":\\\"compile\\\",\\\"userCode\\\":\\\"not_started\\\",\\\"entrypointInvoked\\\":false}}");'+fail;
  const run=['scripts','run-inline','--code',source,'--request-id','unknown-'+stage];const failed=await scoped(own,run,{allowFailure:true});failure(failed,stage,false);
  assert.equal(await readFile(marker,'utf8'),'effect');assert.equal(journal(own).requests.at(-1).state,'unknown');
  if(stage!=='execute')assert.equal(failed.value.execution.entrypointInvoked,false);else assert.equal(failed.value.execution.entrypointInvoked,null);
  if(stage==='execute'){assert.match(failed.value.output,/INSIGHT_QUERY:/);checks.consoleCannotForgeNonExecution=true;}
  const count=journal(own).requests.length;await scoped(own,run,{allowFailure:true});assert.equal(journal(own).requests.length,count);
  assert.notEqual((await scoped(own,['analysis','navigation'],{allowFailure:true})).code,0);checks[stage+'FailureRetainsUnknown']=true;
 }
 assert.equal(digest(await readFile(input)),inputHash);checks.inputUnchanged=true;passed=true;
}finally{
 // These deliberately uncertain scripts only wrote invocation-owned sentinel files.
 // Preserve journals, stop only verified fixture workers, explicitly abandon, and close.
 try{await f.call(['permissions','grant','Destructive']);}catch{cleanup.push('permission');}
 for(const s of scopes){try{
  const status=await f.call(['sessions','status',s.session,'--target',s.target]);
  if(status.ghidra.unresolvedRequests.length){
   const processes=await f.call(['tools','processes','--tool','ghidra','--session',s.session,'--target',s.target]);
   for(const p of processes.items)if(p.role==='context'&&p.session===s.session&&p.target===s.target)await f.call(['tools','processes','kill',p.id]);
   for(const q of status.ghidra.unresolvedRequests)await scoped(s,['abandon','--request-id',q.requestId??q.id,'--acknowledge-unknown-effects']);
  }
  await scoped(s,['close']);
 }catch(e){cleanup.push({session:s.session,error:String(e)});}}
 try{await f.call(['permissions','revoke','Destructive']);}catch{cleanup.push('revoke');}
 try{await f.call(['ghidra','server','stop']);}catch{cleanup.push('server');}
 try{await f.cleanup();}catch{cleanup.push('owner');}
 await writeFile(join(root,'report.json'),JSON.stringify({passed,checks,cleanup,calls:f.calls,limits:['Generated no-analysis x86-64 PE; no production/game project.','Failed initialization/construction/runtime retains unknown even when run() was not entered.','Native receipts are trusted executor output, not a sandbox for adversarial same-JVM Java code.']},null,2)+'\n');
 console.log(JSON.stringify({passed,checks,cleanup,root}));assert.deepEqual(cleanup,[]);
}
