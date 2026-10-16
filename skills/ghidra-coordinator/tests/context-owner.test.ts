import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import type {CommandContext} from '@eyeauras/cli-factory';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {Workspace} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import type {NativeInputs} from '../src/native-inputs.js';

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
    program:'/program',kind:'context',tokenSecret:'owned-fixture-token',runtimeFingerprint:'a'.repeat(64)};
  await writeFile(join(root,'process.json'),JSON.stringify(binding));
  await writeFile(join(directory,'ghidra-native/context',scope.id,'current.json'),JSON.stringify(binding));
  let authenticated=0;
  const invocation=new AbortController();invocation.abort();
  const context={profile:{name:'default',values:{}},signal:invocation.signal,environment:{},
    secrets:{require:async()=> 'fixture-private-token'},fetch:async(_input:unknown,init?:RequestInit)=>{
      assert.equal((init!.headers as Record<string,string>).Authorization,'Bearer fixture-private-token');authenticated++;
      assert.equal(init!.signal!.aborted,false,'Cleanup cannot reuse the cancelled invocation signal');
      return Response.json({pid:child.pid,tcp_port:19091,project_path:join(root,'view')});
    }} as unknown as CommandContext;
  const inputs={fingerprint:binding.runtimeFingerprint} as NativeInputs;
  const replacement=new GhidraContexts(workspace,inputs,context);
  await replacement.dispose();assert.ok(authenticated>=2,'Inventory and cleanup must each verify the owned endpoint');
  const stopped=JSON.parse(await readFile(join(root,'stopped.json'),'utf8'));assert.equal(stopped.pid,child.pid);
  assert.throws(()=>process.kill(child.pid!,0),/ESRCH/);
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
