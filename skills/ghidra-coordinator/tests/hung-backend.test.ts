import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import type {CommandContext} from '@eyeauras/cli-factory';
import {GhidraContexts} from '../src/contexts.js';
import type {Workspace} from '../src/workspace.js';
import type {NativeInputs} from '../src/native-inputs.js';
import {processIdentity} from '../src/tool-runtime/identity.js';
import {nativeProcessProof} from '../src/tool-runtime/native-process-proof.js';
import {verifyGhidraProcess} from '../src/ghidra-processes.js';
import {processStatus} from '../src/tool-runtime/supervisor.js';
import {digest} from '../src/model.js';

async function fixture(t:test.TestContext){
 const directory=await realpath(await mkdtemp('/private/tmp/insight-hung-backend-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const scope={session:'session',target:'target'},context={id:'context',generation:0,baseRevision:1,workingSnapshot:{id:'acknowledged'}};
 const root=join(directory,'workspace/ghidra-native/context',context.id,'stage');await mkdir(root,{recursive:true});
 const token=randomUUID()+randomUUID(),child=spawn(process.execPath,['-e','process.stdout.write("ready");setInterval(()=>{},1000)'],{cwd:root,env:{GHIDRA_MCP_AUTH_TOKEN:token,GHIDRA_MCP_FILE_ROOT:root},stdio:['ignore','pipe','ignore']});
 t.after(async()=>{if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await once(child,'exit');}});
 await once(child.stdout!,'data');
 const id=randomUUID(),identity=await processIdentity(child.pid!);assert.ok(identity);
 const binding={toolProcessId:id,pid:child.pid!,endpoint:'http://127.0.0.1:12345',root,target:scope.target,session:scope.session,context:context.id,mode:'headless',program:'/target.bin',tokenSecret:'context-'+randomUUID(),runtimeFingerprint:'fixture',kind:'context',baseRevision:1};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));await writeFile(join(root,'../current.json'),JSON.stringify(binding));
 const runRoot=join(directory,'runtime/runs',id);await mkdir(runRoot,{recursive:true});await mkdir(join(directory,'runtime/processes'),{recursive:true});
 const receipt={schema:1,id,tool:'ghidra',role:'context',installation:'fixture',root:runRoot,profileBinding:digest(resolve(directory)),ownerPid:process.pid,gated:false,state:'running',pid:child.pid!,identity:identity.birth,strongIdentity:false,executable:process.execPath,createdAt:new Date().toISOString(),session:scope.session,target:scope.target,metadata:{contextRoot:root}};
 await writeFile(join(directory,'runtime/processes',id+'.json'),JSON.stringify(receipt));
 let publication:unknown;
 let unresolved:{id:string;operation:string}[]=[{id:'lost-open',operation:'ghidra.open'}],restores=0,verifiedSnapshots=0;
 const snapshotPath=join(directory,'acknowledged.snapshot');await writeFile(snapshotPath,'saved private annotation');
 const workspace={directory:join(directory,'workspace'),context:()=>context,target:()=>({id:scope.target}),unresolved:()=>unresolved,activePublication:()=>publication,model:()=>({sharedRevision:1}),
  artifacts:{verify:async(snapshot:unknown)=>{assert.equal(snapshot,context.workingSnapshot);verifiedSnapshots++;return snapshotPath;}},saveContext:()=>context} as unknown as Workspace;
 const c={appArguments:{AppDataDirectory:directory},profile:{name:'default',values:{analysisDirectory:null}},secrets:{require:async()=>token,delete:async()=>{}},fetch:async()=>{throw Error('Synthetic unavailable JVM endpoint');}} as unknown as CommandContext;
 const backend=new GhidraContexts(workspace,{fingerprint:'fixture'} as NativeInputs,c);
 (backend as any).privateCopy=async()=>{restores++;}; // Only JVM import is substituted; process ownership/termination and retained bytes are real.
 return {directory,root,scope,context,child,id,binding,receipt,c,backend,token,snapshotPath,setPublication:(value:unknown)=>{publication=value;},setUnresolved:(value:typeof unresolved)=>{unresolved=value;},counts:()=>({restores,verifiedSnapshots})};
}

test('reconnected headless context recovers an unavailable endpoint and retains acknowledged private work',async t=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'){t.skip('Packaged macOS ARM64 kernel helper');return;}
 const f=await fixture(t);
 assert.equal(await nativeProcessProof(f.child.pid!,process.execPath,f.root,f.token),true);
 assert.equal(await verifyGhidraProcess(f.receipt as any,f.c),true,'Authentication does not enter the hung backend');
 assert.equal((await processStatus(f.directory,f.id,r=>verifyGhidraProcess(r,f.c))).state,'running');
 await f.backend.open(f.scope,'continuation-open');
 assert.equal(f.counts().restores,1);assert.ok(f.counts().verifiedSnapshots>0);
 assert.equal(await readFile(f.snapshotPath,'utf8'),'saved private annotation');
 const stopped=JSON.parse(await readFile(join(f.root,'stopped.json'),'utf8'));assert.equal(stopped.reason,'backend_unresponsive');
 const record=JSON.parse(await readFile(join(f.directory,'runtime/processes',f.id+'.json'),'utf8'));assert.equal(record.outcome,'killed');
 assert.equal(await readFile(join(f.root,'process.json'),'utf8'),JSON.stringify(f.binding),'Original receipt retained');
});

test('foreign token, executable, root or a changed PID birth cannot authorize cleanup',async t=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'){t.skip('Packaged macOS ARM64 kernel helper');return;}
 const f=await fixture(t);
 assert.equal(await nativeProcessProof(f.child.pid!,process.execPath,f.root,'foreign-token'),false);
 assert.equal(await nativeProcessProof(f.child.pid!,'/bin/sleep',f.root,f.token),false);
 assert.equal(await nativeProcessProof(f.child.pid!,process.execPath,f.directory,f.token),false);
 await writeFile(join(f.directory,'runtime/processes',f.id+'.json'),JSON.stringify({...f.receipt,identity:'different-birth'}));
 await assert.rejects(f.backend.open(f.scope,'continuation-open'));
 assert.equal(f.child.exitCode,null);assert.equal(f.child.signalCode,null);assert.equal(f.counts().restores,0);
});

test('unknown mutation and publication are not replayed or discarded by hang recovery',async t=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'){t.skip('Packaged macOS ARM64 kernel helper');return;}
 const f=await fixture(t);
 for(const operation of ['ghidra.scripts.run-inline','ghidra.merge','ghidra.close']){
  f.setUnresolved([{id:'uncertain',operation}]);await assert.rejects(f.backend.open(f.scope,'continuation-open'));
  assert.equal(f.child.exitCode,null);assert.equal(f.child.signalCode,null);
 }
 assert.deepEqual(f.counts(),{restores:0,verifiedSnapshots:0});
});

test('missing acknowledged snapshot, active publication and connected debugger prevent automatic retirement',async t=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'){t.skip('Packaged macOS ARM64 kernel helper');return;}
 const f=await fixture(t),context=f.context as any,snapshot=context.workingSnapshot;
 delete context.workingSnapshot;await assert.rejects(f.backend.open(f.scope,'continuation-open'));context.workingSnapshot=snapshot;
 f.setPublication({state:'unknown'});await assert.rejects(f.backend.open(f.scope,'continuation-open'));f.setPublication(undefined);
 context.debugger={connected:true};await assert.rejects(f.backend.open(f.scope,'continuation-open'));delete context.debugger;
 assert.equal(f.child.exitCode,null);assert.equal(f.child.signalCode,null);assert.deepEqual(f.counts(),{restores:0,verifiedSnapshots:0});
});
