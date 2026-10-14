import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,realpath,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import type {CommandContext} from '@eyeauras/cli-factory';
import {GhidraRuntime} from '../src/ghidra.js';
import type {Target,Binding} from '../src/model.js';
import {HttpBridge} from '../src/transport.js';

test('dead reader cleanup validates its receipt without contacting a dead endpoint',async t=>{
  const root=await realpath(await mkdtemp(join(tmpdir(),'insight-lifecycle-')));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const directory=join(root,'processes','reader-synthetic');await mkdir(directory,{recursive:true});
  const child=spawn(process.execPath,['-e','process.exit(0)']);
  await new Promise<void>((ok,bad)=>{child.once('error',bad);child.once('exit',()=>ok());});
  const target:Target={id:'synthetic',lane:'synthetic',profile:'default',server:'ghidra://127.0.0.1:14100',repository:'alpha',programPath:'/fixture.exe',binarySha256:'a'.repeat(64),language:'x86:LE:64:default',compilerSpec:'windows',imageBase:'140000000'};
  const binding:Binding={pid:child.pid!,endpoint:'http://127.0.0.1:19000',projectDirectory:directory,identity:target,version:1,role:'reader'};
  await writeFile(join(directory,'process.json'),JSON.stringify(binding));
  const context={fetch:async()=>{throw Error('No dead endpoint request may execute');}} as unknown as CommandContext;
  await new GhidraRuntime(root,context).stop(target,binding);
  await assert.rejects(new GhidraRuntime(root,context).stop(target,{...binding,pid:process.pid}),/receipt/);
  await assert.rejects(new GhidraRuntime(join(root,'other-profile'),context).stop(target,binding),/selected profile/);
});

test('post-launch binding failure stops the owned child and retains diagnostic stage',async t=>{
  const root=await realpath(await mkdtemp(join(tmpdir(),'insight-launch-')));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const directory=join(root,'processes','reader-synthetic');await mkdir(directory,{recursive:true});
  const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)']);
  const exit=new Promise<void>((ok,bad)=>{child.once('error',bad);child.once('exit',()=>ok());});
  t.after(()=>{if(child.exitCode===null && child.signalCode===null)child.kill('SIGTERM');});
  const target:Target={id:'synthetic',lane:'synthetic',profile:'default',server:'ghidra://127.0.0.1:14100',repository:'alpha',programPath:'/fixture.exe',binarySha256:'a'.repeat(64),language:'x86:LE:64:default',compilerSpec:'windows',imageBase:'140000000'};
  const binding:Binding={pid:child.pid!,endpoint:'http://127.0.0.1:19000',projectDirectory:directory,identity:target,version:1,role:'reader'};
  await writeFile(join(directory,'process.json'),JSON.stringify(binding));
  const fetch=async(input:URL|string|Request)=>{
    if(String(input).endsWith('/mcp/instance_info'))return new Response(JSON.stringify({pid:child.pid,tcp_port:19000,project_path:directory+'/fixture.gpr'}));
    if(String(input).endsWith('/mcp/schema'))return new Response(JSON.stringify({tools:[{path:'/get_project_info',method:'GET',params:[]}]}));
    return new Response(JSON.stringify({project_server_bound:false}));
  };
  const context={profile:{values:{python:process.execPath,bridgeDirectory:root}},fetch,signal:new AbortController().signal} as unknown as CommandContext;
  const processes=new Map([[directory,{binding,http:new HttpBridge(binding.endpoint,fetch),child}]]);
  const runtime=new GhidraRuntime(root,context,processes);
  // Substitute the external launch boundary; cleanup and receipt/process handling remain real.
  (runtime as unknown as {launch:()=>Promise<Binding>}).launch=async()=>binding;
  await assert.rejects(runtime.startReader(target,'synthetic'),/Actual server\/repository/);
  await exit;assert.equal(child.signalCode,'SIGTERM');assert.equal(processes.size,0);
});
