import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import type {CommandContext} from '@eyeauras/cli-factory';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {Workspace} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import type {NativeInputs} from '../src/native-inputs.js';
import {randomUUID} from 'node:crypto';
import {digest} from '../src/model.js';
import {processIdentity} from '../src/tool-runtime/identity.js';

test('inventory ignores a proven reused worker PID before resolving a removed target, retaining its journal',async t=>{
 const identity=await processIdentity(process.pid);if(!identity?.strong){t.skip('Requires strong OS process birth identity');return;}
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),directory=join(f.root,'workspace');
 const root=join(f.root,'previous-installation','missing-stage'),context='old-context',id=randomUUID();
 const receiptDirectory=join(directory,'ghidra-native/context',context);await mkdir(receiptDirectory,{recursive:true});
 const binding={root,context,kind:'context',mode:'headless',target:'removed-target',session:'old-session',pid:process.pid,
  toolProcessId:id,runtimeFingerprint:'old-runtime',tokenSecret:'old-token-reference'};
 const path=join(receiptDirectory,'current.json'),bytes=JSON.stringify(binding);await writeFile(path,bytes);
 await mkdir(join(f.root,'runtime/processes'),{recursive:true});
 const processRoot=join(f.root,'runtime/runs',id);await mkdir(processRoot,{recursive:true});
 const record={schema:1,id,tool:'ghidra',role:'context',installation:binding.runtimeFingerprint,root:processRoot,
  profileBinding:digest(resolve(f.root)),state:'running',pid:process.pid,target:binding.target,session:binding.session,
  identity:'different-original-worker-birth',strongIdentity:true,metadata:{contextRoot:root}};
 const recordPath=join(f.root,'runtime/processes',id+'.json');
 const workspace={directory,target:()=>{throw Error('Removed target lookup');}} as unknown as Workspace;
 const backend=new GhidraContexts(workspace,{} as NativeInputs,{appArguments:{AppDataDirectory:f.root}} as CommandContext);
 for(const changed of [{target:'foreign'},{session:'foreign'},{role:'gui'},{installation:'foreign'},
  {strongIdentity:false},{identity:identity.birth},{metadata:{contextRoot:directory}}]){
  await writeFile(recordPath,JSON.stringify({...record,...changed}));
  await assert.rejects((backend as any).inventory(),/Removed target lookup/);
 }
 await writeFile(recordPath,JSON.stringify(record));await (backend as any).inventory();
 await writeFile(recordPath,JSON.stringify({...record,state:'exited'}));
 await assert.rejects((backend as any).inventory(),/Removed target lookup/,'Terminal state without completion evidence is ambiguous');
 await writeFile(recordPath,JSON.stringify({...record,state:'exited',endedAt:new Date().toISOString()}));
 await (backend as any).inventory();
 assert.equal(await readFile(path,'utf8'),bytes,'Inventory must preserve recovery journals');
 process.kill(process.pid,0);
});

test('a terminal supervised worker releases its credential after its PID is reused without stopping the new process',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),directory=join(f.root,'workspace');
 const scope={session:'session',target:'target'},context={id:'context-id',generation:0,workingSnapshot:{fixture:true}};
 const root=join(directory,'ghidra-native','context',context.id,'stage');await mkdir(root,{recursive:true});
 const id=randomUUID(),processRoot=join(f.root,'runtime','runs',id);await mkdir(processRoot,{recursive:true});
 await mkdir(join(f.root,'runtime','processes'),{recursive:true});
 const binding={root,kind:'context',context:context.id,target:scope.target,session:scope.session,pid:process.pid,mode:'headless',
  tokenSecret:'context-'+randomUUID(),runtimeFingerprint:'previous-runtime',toolProcessId:id};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
 await writeFile(join(root,'..','current.json'),JSON.stringify(binding));
 const receipt={schema:1,id,tool:'ghidra',role:'context',installation:binding.runtimeFingerprint,root:processRoot,
  profileBinding:digest(resolve(f.root)),state:'exited',pid:binding.pid,target:scope.target,session:scope.session,
  identity:'retired-original-birth',strongIdentity:true,endedAt:new Date().toISOString(),metadata:{contextRoot:root}};
 const recordPath=join(f.root,'runtime','processes',id+'.json');await writeFile(recordPath,JSON.stringify(receipt));
 let copied=0,released=0;
 const workspace={directory,context:()=>context,target:()=>({id:'target'}),unresolved:()=>[],
  model:()=>({sharedRevision:1}),saveContext:()=>context} as unknown as Workspace;
 const backend=new GhidraContexts(workspace,{fingerprint:'new-runtime'} as NativeInputs,
  {appArguments:{AppDataDirectory:f.root},secrets:{delete:async(name:string)=>{assert.equal(name,binding.tokenSecret);released++;}}} as unknown as CommandContext);
 (backend as any).privateCopy=async()=>{copied++;};
 for(const changed of [{target:'foreign'},{role:'gui'},{installation:'foreign'},{session:'foreign'},
   {pid:process.pid+1},{strongIdentity:false},{endedAt:undefined},{metadata:{contextRoot:directory}},{state:'unverified'}]){
  await writeFile(recordPath,JSON.stringify({...receipt,...changed}));
  assert.equal(await (backend as any).retiredWorker(binding),false);
 }
 await writeFile(recordPath,JSON.stringify(receipt));
 await backend.open(scope);assert.equal(copied,1);assert.equal(released,1);
 process.kill(process.pid,0); // The unrelated current process was never terminated.
});

test('stopped launch-failure workers release their own credentials before a current binding exists',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),directory=join(f.root,'workspace');
 const secrets=new Map([['server-permanent','fixture-server-secret']]);
 const backend=new GhidraContexts({directory} as Workspace,{} as NativeInputs,
  {secrets:{delete:async(name:string)=>{secrets.delete(name);}}} as unknown as CommandContext);
 for(let n=0;n<3;n++){
  const root=join(directory,'ghidra-native','shared','target','stage'+n);await mkdir(root,{recursive:true});
  const child=spawn(process.execPath,['-e','process.exit(0)'],{stdio:'ignore'});
  await new Promise<void>((resolve,reject)=>{child.once('exit',()=>resolve());child.once('error',reject);});
  const tokenSecret='context-'+randomUUID();secrets.set(tokenSecret,'fixture-ephemeral-secret');
  const binding={pid:child.pid!,endpoint:'http://127.0.0.1:1',root,target:'target',mode:'headless',
   program:'/program',kind:'shared',tokenSecret,runtimeFingerprint:'fixture'};
  await writeFile(join(root,'process.json'),JSON.stringify(binding));
  await (backend as any).stopRecord({binding,child},false,true,'startup_failed');
  assert.deepEqual([...secrets.keys()],['server-permanent']);
  const stopped=JSON.parse(await readFile(join(root,'stopped.json'),'utf8'));
  assert.equal(stopped.reason,'startup_failed');assert.equal(stopped.tokenSecret,tokenSecret);
 }
});

test('a retired previous-runtime binding does not prevent restoring its saved context',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli'}),directory=join(f.root,'workspace');
 const scope={session:'session',target:'target'},context={id:'context-id',generation:0,workingSnapshot:{fixture:true}};
 const root=join(directory,'ghidra-native','context',context.id,'stage');await mkdir(root,{recursive:true});
 const binding={root,kind:'context',context:context.id,target:scope.target,pid:123456789,mode:'headless',
  tokenSecret:'context-'+randomUUID(),runtimeFingerprint:'previous-runtime'};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
 await writeFile(join(root,'..','current.json'),JSON.stringify(binding));
 let copied=0,released=0;
 const workspace={directory,context:()=>context,target:()=>({id:'target'}),unresolved:()=>[],
  model:()=>({sharedRevision:1}),saveContext:()=>context} as unknown as Workspace;
 const backend=new GhidraContexts(workspace,{fingerprint:'new-runtime'} as NativeInputs,
  {secrets:{delete:async(name:string)=>{assert.equal(name,binding.tokenSecret);released++;}}} as unknown as CommandContext);
 (backend as any).privateCopy=async()=>{copied++;};
 await backend.open(scope);assert.equal(copied,1);assert.equal(released,1);
});

test('a replacement context owner authenticates and releases an unread owned child during disposal',async t=>{
  let workspace:Workspace;const f=await createCliFixture({after:action=>t.after(async()=>{workspace?.close();await (action as ()=>Promise<void>)();})},{applicationId:'insight-cli'}),directory=join(f.root,'workspace');
  workspace=new Workspace(directory,'default');
  const input=join(f.root,'fixture.exe');await writeFile(input,'synthetic owner receipt input');
  const target=await workspace.importTarget(input),scope=workspace.reserveOpen(target.id,'new',{autoAnalyze:false}).context;
  const root=join(directory,'ghidra-native/context',scope.id,'owned');await mkdir(root,{recursive:true});
  const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  assert.ok(child.pid);
  const binding={pid:child.pid,endpoint:'http://127.0.0.1:19091',root,target:target.id,context:scope.id,mode:'headless',
    program:'/program',kind:'context',tokenSecret:'context-11111111-1111-4111-8111-111111111111',runtimeFingerprint:'a'.repeat(64)};
  await writeFile(join(root,'process.json'),JSON.stringify(binding));
  await writeFile(join(directory,'ghidra-native/context',scope.id,'current.json'),JSON.stringify(binding));
  let authenticated=0,released=0;
  const invocation=new AbortController();invocation.abort();
  const context={profile:{name:'default',values:{}},signal:invocation.signal,environment:{},
    secrets:{require:async()=> 'fixture-private-token',delete:async(name:string)=>{assert.equal(name,binding.tokenSecret);released++;}},fetch:async(_input:unknown,init?:RequestInit)=>{
      assert.equal((init!.headers as Record<string,string>).Authorization,'Bearer fixture-private-token');authenticated++;
      assert.equal(init!.signal!.aborted,false,'Cleanup cannot reuse the cancelled invocation signal');
      return Response.json({pid:child.pid,tcp_port:19091,project_path:join(root,'view')});
    }} as unknown as CommandContext;
  const inputs={fingerprint:binding.runtimeFingerprint} as NativeInputs;
  const replacement=new GhidraContexts(workspace,inputs,context);
  await replacement.dispose();assert.ok(authenticated>=2,'Inventory and cleanup must each verify the owned endpoint');
  const stopped=JSON.parse(await readFile(join(root,'stopped.json'),'utf8'));assert.equal(stopped.pid,child.pid);
  assert.throws(()=>process.kill(child.pid!,0),/ESRCH/);
  assert.equal(released,1,'The verified stopped worker releases only its own ephemeral credential');
});

test('a GUI replacement ignores an earlier stop as proof and independently verifies the current owned process',async t=>{
  let workspace:Workspace;const f=await createCliFixture({after:action=>t.after(async()=>{workspace?.close();await (action as ()=>Promise<void>)();})},{applicationId:'insight-cli'}),directory=join(f.root,'workspace');workspace=new Workspace(directory,'default');
  const input=join(f.root,'fixture.exe');await writeFile(input,'synthetic mode transition input');const target=await workspace.importTarget(input),scope=workspace.reserveOpen(target.id,'new',{autoAnalyze:false}).context;
  const root=join(directory,'ghidra-native/context',scope.id,'owned');await mkdir(root,{recursive:true});
  const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});assert.ok(child.pid);
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  const binding={pid:child.pid,endpoint:'http://127.0.0.1:19092',root,target:target.id,context:scope.id,mode:'gui',program:'/program',kind:'context',tokenSecret:'current-fixture-token',runtimeFingerprint:'b'.repeat(64)};
  await writeFile(join(root,'process.json'),JSON.stringify(binding));await writeFile(join(directory,'ghidra-native/context',scope.id,'current.json'),JSON.stringify(binding));
  await writeFile(join(root,'stopped.json'),JSON.stringify({pid:child.pid+1,tokenSecret:'previous-headless-token'}));
  let wrong=false,authentications=0;
  const context={profile:{name:'default',values:{}},signal:new AbortController().signal,environment:{},secrets:{require:async()=> 'fixture-private-token'},
    fetch:async(input:URL,init:RequestInit)=>{assert.equal((init.headers as Record<string,string>).Authorization,'Bearer fixture-private-token');authentications++;
      const path=new URL(input).pathname;
      if(path==='/mcp/instance_info')return Response.json({pid:wrong?child.pid!+1:child.pid,tcp_port:19092,project_path:join(root,'view')});
      if(path==='/mcp/schema')return Response.json({tools:[{path:'/get_program_options',method:'GET',params:[{name:'program',source:'query'},{name:'group',source:'query'}]},{path:'/get_metadata',method:'GET',params:[{name:'program',source:'query'}]}]});
      if(path==='/get_program_options')return Response.json({options:[{name:'Executable SHA256',value:target.binarySha256}]});
      if(path==='/get_metadata')return Response.json({program_name:'fixture'});throw Error('Unexpected protocol request');
    }} as unknown as CommandContext;
  const backend=new GhidraContexts(workspace,{fingerprint:binding.runtimeFingerprint} as NativeInputs,context);
  assert.equal(await backend.closed(scope),false);assert.ok(authentications>=4);
  wrong=true;await assert.rejects(backend.closed(scope),/no longer matches its receipt/);process.kill(child.pid,0);
  const exited=new Promise<void>(resolve=>child.once('exit',()=>resolve()));child.kill('SIGTERM');await exited;
  assert.equal(await backend.closed(scope),true,'The recorded current PID actually exited; no stale stop receipt is used as proof');
});

test('native process authentication accepts a profile projection and rejects foreign ownership or PID',async t=>{
 const {mkdtemp,mkdir,symlink,rm}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{verifyGhidraProcess}=await import('../src/ghidra-processes.js');
 const directory=await mkdtemp(join(tmpdir(),'insight-auth-alias-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const profile=join(directory,'profile'),alias=join(directory,'projection'),other=join(directory,'other');await mkdir(profile);await mkdir(other);await symlink(profile,alias,process.platform==='win32'?'junction':'dir');
 const root=join(alias,'workspace/ghidra-native/context/id/stage');await mkdir(root,{recursive:true});
 const binding={pid:process.pid,endpoint:'http://127.0.0.1:19091',root,target:'fixture',runtimeFingerprint:'fixture-runtime',program:'/program',tokenSecret:'fixture-token'};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));let pid=process.pid,requests=0;
 const context={appArguments:{AppDataDirectory:profile},profile:{name:'default',values:{analysisDirectory:null}},secrets:{require:async()=> 'synthetic-private-token'},fetch:async(_input:unknown,init:RequestInit)=>{assert.equal((init.headers as Record<string,string>).Authorization,'Bearer synthetic-private-token');requests++;return Response.json({pid,tcp_port:19091,project_path:join(root,'view')});}} as any;
 const record={pid:process.pid,target:'fixture',installation:'fixture-runtime',metadata:{contextRoot:root}} as any;
 assert.equal(await verifyGhidraProcess(record,context),true);assert.equal(requests,1);
 pid++;assert.equal(await verifyGhidraProcess(record,context),false);
 const foreign={...context,appArguments:{AppDataDirectory:other}};assert.equal(await verifyGhidraProcess(record,foreign),false);
});
