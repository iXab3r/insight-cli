import test from 'node:test';
import assert from 'node:assert/strict';
import {createCli} from '@eyeauras/cli-factory';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {defineTool,lifecycleCommands,type ToolDefinition} from '../src/tool-runtime/definition.js';

test('Ghidra and one-shot definitions share Factory lifecycle, permission gates and JSON',async t=>{
 const f=await createCliFixture(t,{applicationId:'tool-fixture'});let writes=0;
 const tool=(id:string,components:ToolDefinition['components'])=>defineTool({id,description:'Fixture',components,lifecycle:{
  async status(){return {tool:id,state:'not_ready'};},async download(){writes++;return {state:'downloaded'};},
  async install(){writes++;return {state:'installed'};},async uninstall(){writes++;return {state:'uninstalled'};},async doctor(){return {state:'verified'};},
 }});
 const ghidra=tool('ghidra',[{id:'jdk',version:'fixture',artifacts:[]},{id:'ghidra',version:'fixture',dependencies:['jdk'],artifacts:[]}]);
 const ilspy=tool('ilspy',[{id:'ilspy',version:'fixture',artifacts:[]}]);
 for(const item of [ghidra,ilspy]){
  const app=f.createApplication(runtime=>createCli({name:'tool-fixture',description:'Tool contract fixture',runtime,permissions:{categories:[{name:'Destructive',description:'Remove owned files',enabledByDefault:false}]},commands:lifecycleCommands(item)}));
  assert.equal((await f.json(app,['status']) as any).tool,item.id);
  const denied=await f.run(app,['install','--json']);assert.notEqual(denied.exitCode,0);assert.equal(writes,0);
 }
 assert.throws(()=>tool('bad',[{id:'a',version:'1',artifacts:[],dependencies:['a']}]),/Cyclic/);
 assert.throws(()=>tool('bad',[{id:'a',version:'1',artifacts:[],dependencies:['missing']}]),/Unknown/);
});
test('shared cache validates cancellation and declared size without activating partial bytes',async t=>{
 const {mkdtemp,rm,stat}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const {cacheArtifact}=await import('../src/tool-runtime/archives.js');
 const root=await mkdtemp(join(tmpdir(),'tool-cache-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const a={name:'fixture',url:'https://example.invalid/tool',sha256:'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',size:5,format:'zip' as const,root:'.',license:'Fixture'};
 const aborted=new AbortController();aborted.abort();let calls=0;
 const fetcher=(async()=>{calls++;return new Response('hello');}) as typeof fetch;
 await assert.rejects(cacheArtifact(a,root,fetcher,aborted.signal));assert.equal(calls,0);
 await assert.rejects(cacheArtifact({...a,size:6},root,fetcher,new AbortController().signal),/size/);
 await assert.rejects(stat(join(root,a.sha256+'.zip')));
 const results=await Promise.all([cacheArtifact(a,root,fetcher,new AbortController().signal),cacheArtifact(a,root,fetcher,new AbortController().signal)]);
 assert.equal(results[0],results[1]);
});

test('installation fingerprints survive staging relocation and an aliased parent without admitting escaping links',async t=>{
 if(process.platform==='win32'){t.skip('Symbolic-link privileges are not a Windows unit prerequisite');return;}
 const {mkdtemp,rm,mkdir,writeFile,symlink,rename}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const {treeFingerprint}=await import('../src/tool-runtime/store.js');
 const root=await mkdtemp(join(tmpdir(),'linked-installation-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const actual=join(root,'actual'),alias=join(root,'alias');await mkdir(actual);await symlink(actual,alias,'dir');
 const stage=join(alias,'stage');await mkdir(join(stage,'Framework/Versions/A'),{recursive:true});await writeFile(join(stage,'Framework/Versions/A/runtime'),'original');await symlink('A',join(stage,'Framework/Versions/Current'),'dir');await symlink('Versions/Current/runtime',join(stage,'Framework/runtime'));
 const expected=await treeFingerprint(stage);const installed=join(alias,'installed');await rename(stage,installed);
 assert.equal(await treeFingerprint(installed),expected);assert.equal(await treeFingerprint(join(actual,'installed')),expected);
 await writeFile(join(installed,'Framework/Versions/A/runtime'),'modified');assert.notEqual(await treeFingerprint(installed),expected);
 await symlink(root,join(installed,'escape'),'dir');await assert.rejects(treeFingerprint(installed),/escapes/);
});

test('native preflight failure retains a readable terminal record without freezing tool removal',async t=>{
 const {mkdtemp,rm}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const {runTool}=await import('../src/tool-runtime/run.js'),{listProcesses}=await import('../src/tool-runtime/supervisor.js'),{assertUnused}=await import('../src/tool-runtime/store.js');
 const root=await mkdtemp(join(tmpdir(),'tool-native-preflight-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await assert.rejects(runTool({appArguments:{AppDataDirectory:root},environment:{PATH:process.env.PATH},signal:new AbortController().signal},{tool:'fixture',role:'invalid-native-deadline',executable:process.execPath,nativeDeadline:true,timeoutMs:0}));
 const records=await listProcesses(root);assert.equal(records.length,1);assert.equal(records[0]!.state,'failed');await assertUnused(root,'fixture');
});
