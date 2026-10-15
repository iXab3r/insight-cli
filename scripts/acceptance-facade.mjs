import {p3Inputs} from './native-p3-inputs.mjs';
import {runNpm} from './npm-command.mjs';
// Owned installed-package CLI/IPC acceptance; all native data and keyring accounts are disposable.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,mkdir,readFile,writeFile,cp,rm,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {AppArguments,ProfileStore,KeyringSecretStore,ProfileSecrets} from '@eyeauras/cli-factory';
const source=fileURLToPath(new URL('../',import.meta.url)),exec=promisify(execFile),options={};
for(let i=2;i<process.argv.length;i++) {
  const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;else if(arg==='--faults')options.faults=true;else if(arg==='--automatic-faults')options.automaticFaults=true;
  else if(arg.startsWith('--')&&process.argv[i+1])options[arg.slice(2)]=process.argv[++i];else throw Error('Invalid acceptance argument');
}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
for(const key of ['java','ghidra-home','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const scratch=await realpath(await mkdtemp('/tmp/insight-facade-')),applicationId='insight-proof-'+randomUUID(),
  entry=join(scratch,'fixture-bin.mjs');
const argumentOptions={AppName:applicationId,Profile:'default',Environment:{AppDomainDirectory:scratch,
  ApplicationExecutablePath:entry,EnvironmentAppData:scratch,EnvironmentLocalAppData:scratch,ProcessId:1}};
const appArguments=new AppArguments(argumentOptions),directory=appArguments.AppDataDirectory;
await mkdir(directory,{recursive:true,mode:0o700});await mkdir(join(scratch,'artifacts'));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar'],maxContexts:4};
const profiles=new ProfileStore({applicationId,appArguments});await profiles.set('default',values);
await profiles.setPermissions('default',['ReadOnly','Update','Destructive']);
const packed=JSON.parse((await runNpm(['pack','--offline','--ignore-scripts','--json','--workspace','@ixab3r/insight-cli',
  '--pack-destination',join(scratch,'artifacts')],{cwd:source})).stdout)[0];
const rootManifest=JSON.parse(await readFile(join(source,'package.json'),'utf8')),
  lock=JSON.parse(await readFile(join(source,'package-lock.json'),'utf8')),
  cliManifest=JSON.parse(await readFile(join(source,'skills/ghidra-coordinator/package.json'),'utf8'));
const manifest={name:'owned-insight-facade-proof',version:'0.1.0',private:true,type:'module',
  files:['fixture-bin.mjs','fixture-config.json','.cli-package-build.json'],
  dependencies:{...rootManifest.dependencies,'@ixab3r/insight-cli':'file:artifacts/'+packed.filename},devDependencies:rootManifest.devDependencies};
lock.name=manifest.name;lock.version=manifest.version;lock.packages['']=manifest;
for(const [path,item]of Object.entries(lock.packages))if(item.link||path.startsWith('skills/'))delete lock.packages[path];
const artifact=await readFile(join(scratch,'artifacts',packed.filename));
lock.packages['node_modules/@ixab3r/insight-cli']={version:cliManifest.version,resolved:manifest.dependencies['@ixab3r/insight-cli'],
  integrity:'sha512-'+createHash('sha512').update(artifact).digest('base64'),dependencies:cliManifest.dependencies,
  engines:cliManifest.engines,bin:cliManifest.bin,license:cliManifest.license};
await cp(join(source,'vendor'),join(scratch,'vendor'),{recursive:true});
await writeFile(join(scratch,'package.json'),JSON.stringify(manifest));await writeFile(join(scratch,'package-lock.json'),JSON.stringify(lock));
await runNpm(['ci','--offline','--ignore-scripts','--no-audit','--no-fund'],{cwd:scratch,timeout:60000,maxBuffer:262144});
await cp(join(source,'scripts/fixtures/facade-owner.mjs'),entry);
await writeFile(join(scratch,'fixture-config.json'),JSON.stringify({applicationId,appArguments:argumentOptions}),{mode:0o600});
const {writePackageBuildManifest}=await import('@eyeauras/cli-factory-ipc/build');await writePackageBuildManifest(scratch);
const invoke=async(argv,ok=true)=>{
  let result;try{const output=await exec(process.execPath,[entry,...argv,'--json'],{cwd:scratch,timeout:240000,maxBuffer:2*1024*1024});result={exitCode:0,...output};}
  catch(error){result={exitCode:error.code??1,stdout:error.stdout??'',stderr:error.stderr??''};}
  if(!ok)return result;
  assert.equal(result.exitCode,0,'Installed command failed: '+argv.slice(0,3).join(' ')+'; '+result.stderr.slice(0,800));
  return JSON.parse(result.stdout);
};
const select=scope=>['--session',scope.session,'--target',scope.target],at='0x140001000';
const comment=(scope,text,requestId)=>invoke(['ghidra','comments','set',...select(scope),'--address',at,'--kind','eol','--text',text,
  ...(requestId?['--request-id',requestId]:[])]);
const read=async(scope)=>(await invoke(['ghidra','comments','get',...select(scope),'--address',at,'--kind','eol'])).text;
async function input(label,increment){const dir=join(scratch,label);await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
  await writeFile(c,`__declspec(noinline) int first(int x){return x+${increment};}\nint main(void){return first(2);}\n`);
  await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
  await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);return exe;}
async function killed(pid){process.kill(pid,'SIGKILL');for(let i=0;i<100;i++){try{process.kill(pid,0);}catch(error){if(error.code==='ESRCH')return;throw error;}await delay(50);}throw Error('Owned fixture owner remained live');}
async function barrier(){for(let i=0;i<1200;i++){try{return JSON.parse(await readFile(join(directory,'barrier.json'),'utf8'));}catch{}await delay(100);}throw Error('Owned fault barrier did not arrive');}
const sourceHashes=options.automaticFaults?await p3Inputs():undefined,harnessHashes=Object.fromEntries(await Promise.all(['scripts/acceptance-facade.mjs','scripts/fixtures/facade-owner.mjs','scripts/npm-command.mjs'].map(async path=>[path,createHash('sha256').update(await readFile(join(source,path))).digest('hex')])));
let receipt,activeFaultOwner;
try {
  const exe=await input('client',17),helper=await input('helper',23);
  const a=await invoke(['ghidra','open',exe,'--session','new','--request-id','open-A']),
    b=await invoke(['ghidra','open',exe,'--session','new']),
    ah=await invoke(['ghidra','open',helper,'--session',a.session]),
    bh=await invoke(['ghidra','open',helper,'--session',b.session]);
  assert.equal(a.target,b.target);assert.notEqual(a.session,b.session);assert.notEqual(a.target,ah.target);assert.equal(ah.target,bh.target);
  assert.deepEqual(await invoke(['ghidra','open',exe,'--session','new','--request-id','open-A']),a);
  const inventory=await invoke(['ghidra','types','get-valid-data-types',...select(a),'--limit','5']);assert.ok(inventory.value.types.length);assert.equal(inventory.value.read_only.modification_unchanged,true);
  const constants=await invoke(['ghidra','analysis','detect-crypto-constants',...select(a),'--max-bytes','1']);assert.equal(constants.value.complete,false);assert.ok(constants.value.next_address);
  const partialGlobals=await invoke(['ghidra','listing','list-globals',...select(a),'--max-scan','1']);assert.equal(partialGlobals.value.truncated,true);
  await Promise.all([comment(a,'A client'),comment(ah,'A helper')]);
  assert.equal(await read(b),null);assert.equal(await read(bh),null);
  await Promise.all([invoke(['ghidra','merge',...select(a),'--request-id','merge-A']),invoke(['ghidra','merge',...select(ah)])]);
  assert.equal(await read(b),null);await invoke(['ghidra','refresh',...select(b)]);assert.equal(await read(b),'A client');
  await comment(a,'A overlap');await comment(b,'B overlap');await invoke(['ghidra','merge',...select(a)]);
  assert.notEqual((await invoke(['ghidra','merge',...select(b)],false)).exitCode,0);
  await invoke(['ghidra','refresh',...select(b)]);assert.equal(await read(b),'B overlap');
  const owner=await invoke(['ipc-server','status']);assert.equal(owner.running,true);
  await killed(owner.pid);
  const resumed=await invoke(['ghidra','open',...select(b)]);assert.equal(resumed.pendingChanges,1);
  assert.equal(await read(b),'B overlap');assert.equal(await read(ah),'A helper');
  const conflicted=await invoke(['sessions','status',b.session,'--target',b.target]);assert.equal(conflicted.ghidra.conflicts[0].local,'B overlap');
  await invoke(['ipc-server','stop']);
  const nativeSecrets=new KeyringSecretStore(),secrets=new ProfileSecrets(nativeSecrets,applicationId,'default');
  const {GhidraServer}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/server.js'));
  const {nativeInputs}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/native-inputs.js'));
  const context={profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,fetch,secrets};
  await new GhidraServer(join(directory,'workspace'),await nativeInputs(values),context).stop();
  await invoke(['ghidra','open',...select(b)]);assert.equal(await read(b),'B overlap');assert.equal(await read(ah),'A helper');
  await invoke(['ipc-server','stop']);
  const savedBlock=await invoke(['ghidra','memory','create-block',...select(a),'--name','InstalledOwnedBlock','--address','0x180000000','--bytes-hex','616263','--request-id','installed-block']);assert.equal(savedBlock.value.sha256,createHash('sha256').update('abc').digest('hex'));
  assert.deepEqual(await invoke(['ghidra','memory','create-block',...select(a),'--name','InstalledOwnedBlock','--address','0x180000000','--bytes-hex','616263','--request-id','installed-block']),savedBlock);
  const patched=await invoke(['ghidra','memory','patch-bytes',...select(a),'--address','0x180000000','--expect-hex','616263','--bytes-hex','646566','--request-id','installed-sdk-patch']);assert.equal(patched.value.bytes_hex,'646566');
  const preview=await invoke(['ghidra','assembly','preview',...select(a),'--address',at,'--instructions','["NOP"]']);assert.equal(preview.value.bytes_hex,'90');
  await invoke(['ghidra','namespaces','create',...select(a),'--name','InstalledNamespace']);
  assert.ok((await invoke(['ghidra','namespaces','list',...select(a)])).value.items.some(row=>row.name==='InstalledNamespace'));
  const exported=await invoke(['ghidra','formats','export',...select(a),'--exporter','Raw Bytes','--ranges','[{"start":"0x180000000","end":"0x180000002"}]','--output-directory',join(scratch,'installed-sdk-export')]);assert.equal(exported.value.selected,true);assert.equal((await readFile(join(scratch,'installed-sdk-export','program.out'))).toString(),'def');
  await invoke(['ipc-server','stop']);
  const automaticFaultPhases=options.automaticFaults?['local_ack','verified']:[];
  if(automaticFaultPhases.length){
    const auto=await invoke(['ghidra','open',exe,'--session','new']);
    await invoke(['ghidra','sync-policy','set',...select(auto),'--publish','after-edit','--refresh','manual']);
    for(const phase of automaticFaultPhases){
      const baseline=await invoke(['sessions','status',auto.session,'--target',auto.target]),expected='R'+(Number(baseline.ghidra.sharedRevision.slice(1))+1),requestId='automatic-fault-'+phase;
      const earlier=(await readFile(join(directory,'effect-calls.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),before=earlier.filter(e=>e.operation==='publish').length,beforeSetters=earlier.filter(e=>e.operation==='set_comment').length;
      await rm(join(directory,'barrier.json'),{force:true});const owner=await invoke(['ipc-server','status']);activeFaultOwner=owner.pid;
      await writeFile(join(directory,'fault.json'),JSON.stringify({phase,requestIdPrefix:phase==='verified'?'auto-merge-':'auto-local-'}),{mode:0o600});
      const args=['ghidra','comments','set',...select(auto),'--address',at,'--kind','eol','--text','Automatic retained '+phase,'--request-id',requestId];
      const pending=invoke(args,false),held=await barrier();assert.equal(held.ownerPid,owner.pid);assert.equal(held.session,auto.session);assert.equal(held.target,auto.target);
      assert.ok(held.requestId.startsWith(phase==='verified'?'auto-merge-':'auto-local-'));
      await killed(held.ownerPid);activeFaultOwner=undefined;await pending;await rm(join(directory,'fault.json'));
      await invoke(['ghidra','open',...select(auto)]);const replay=await invoke(args);assert.equal(replay.state,'applied');assert.equal(replay.pendingChanges,0);assert.equal(replay.automatic.publication.sharedRevision,expected);
      assert.deepEqual(await invoke(args),replay);assert.equal(await read(auto),'Automatic retained '+phase);
      const effects=(await readFile(join(directory,'effect-calls.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);assert.equal(effects.filter(e=>e.operation==='set_comment').length,beforeSetters+1);assert.equal(effects.filter(e=>e.operation==='publish').length,before+1);
      const fresh=await invoke(['ghidra','open',exe,'--session','new']);assert.equal(await read(fresh),'Automatic retained '+phase);await invoke(['ghidra','close',...select(fresh)]);
      await invoke(['ipc-server','stop']);console.log('Owned automatic owner crash verified:',phase);
    }
    assert.deepEqual(await p3Inputs(),sourceHashes,'Runtime source changed during automatic owner-crash acceptance');
    for(const [path,sha]of Object.entries(harnessHashes))assert.equal(createHash('sha256').update(await readFile(join(source,path))).digest('hex'),sha);
  }
  const phases=options.faults?['accepted','local_effect','local_save','local_ack','published','verified','publication_intent']:[];
  for(let i=0;i<phases.length;i++) {
    const phase=phases[i],binary=await input('fault-'+phase,100+i),a=await invoke(['ghidra','open',binary,'--session','new']);
    const requestId='fault-'+phase,merge=['published','verified','publication_intent'].includes(phase);
    if(merge)await comment(a,'Saved before publication crash');
    await rm(join(directory,'barrier.json'),{force:true});
    const owner=await invoke(['ipc-server','status']);
    activeFaultOwner=owner.pid;
    await writeFile(join(directory,'fault.json'),JSON.stringify({phase,requestId}),{mode:0o600});
    const args=merge?['ghidra','merge',...select(a),'--request-id',requestId]:
      ['ghidra','comments','set',...select(a),'--address',at,'--kind','eol','--text','Retained '+phase,'--request-id',requestId];
    const pending=invoke(args,false);const held=await barrier();
    assert.equal(held.ownerPid,owner.pid);assert.equal(held.session,a.session);assert.equal(held.target,a.target);assert.equal(held.requestId,requestId);
    await killed(held.ownerPid);activeFaultOwner=undefined;await pending;await rm(join(directory,'fault.json'));
    if(phase==='publication_intent') {
      const status=await invoke(['sessions','status',a.session,'--target',a.target]);assert.equal(status.ghidra.mergeState,'unknown');
      assert.notEqual((await invoke(args,false)).exitCode,0,'Unproved publication must not be re-executed');
    } else {
      await invoke(['ghidra','open',...select(a)]);
      const replay=await invoke(args);assert.equal(replay.state,merge?'merged':'applied');
      assert.equal(await read(a),merge?'Saved before publication crash':'Retained '+phase);
      if(merge)assert.equal(replay.sharedRevision,'R2','Reconciliation must not create a second version');
      const effects=(await readFile(join(directory,'effect-calls.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
      assert.equal(effects.filter(e=>e.requestId===requestId).length,1,'Retry must not dispatch the effect again');
    }
    await invoke(['ipc-server','stop']);console.log('Owned installed owner crash verified:',phase);
  }
  receipt={schema:1,scope:'installed native Factory facade IPC/OS secrets',sourceRevision:options['source-revision']??'working tree',
    artifactSha256:createHash('sha256').update(artifact).digest('hex'),sessions:2,targets:2,contexts:4,
    packagedNativeQueryKernels:true,packagedSavedMemoryDigest:true,packagedSdkSavedEdits:true,packagedNativeRestrictedExport:true,
    equalBasenames:true,equalAddresses:true,parallelCliProcesses:true,independentPrivateViews:true,explicitMergeRefresh:true,
    conflictRetainedAfterOwnerRestart:true,managedServerRestartRetainsWork:true,requestIdRetryRetainsSession:true,
    faultPhases:phases,automaticFaultPhases,...(sourceHashes?{sourceHashes,harnessHashes}:{}),ghidra:'12.1.2',java:'21',node:process.versions.node,
    limitations:['tiny owned static PE inputs','test-only barriers and isolated application identity','debugger/archive/full catalog final gate remains']};
} catch(error) {
  console.error('Owned installed fixture failure:',error.message);console.error('Owned installed fixture diagnostics:',scratch);
  if(activeFaultOwner){await killed(activeFaultOwner);activeFaultOwner=undefined;}throw error;
}
finally {
  await rm(join(directory,'fault.json'),{force:true});
  await invoke(['ipc-server','stop'],false);
  const {GhidraServer}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/server.js')),
    {GhidraContexts}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/contexts.js')),
    {Workspace}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/workspace.js')),
    {nativeInputs}=await import(join(scratch,'node_modules/@ixab3r/insight-cli/dist/src/native-inputs.js'));
  const secrets=new ProfileSecrets(new KeyringSecretStore(),applicationId,'default');
  const context={profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,fetch,secrets};
  const inputs=await nativeInputs(values),workspace=new Workspace(join(directory,'workspace'),'default'),native=new GhidraContexts(workspace,inputs,context);
  try {
    // Stop leftover owned bindings even when an unknown request prevents ordinary continuation.
    for(const session of workspace.sessions())for(const scoped of workspace.contexts(session.id)) {
      let binding;try{binding=JSON.parse(await readFile(join(workspace.directory,'ghidra-native/context',scoped.id,'current.json'),'utf8'));}catch{continue;}
      try{process.kill(binding.pid,0);}catch(error){if(error.code==='ESRCH')continue;throw error;}
      await native.stopRecord(await native.verified(binding,workspace.target(scoped.target),false));
    }
    await new GhidraServer(workspace.directory,inputs,context).stop();
  } finally {workspace.close();}
  let keys=[];try{keys=(await readFile(join(directory,'secret-keys.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(error){if(error.code!=='ENOENT')throw error;}
  const keyring=new KeyringSecretStore();for(const key of keys)await keyring.delete(key.service,key.account);
}
if(receipt){await writeFile(join(scratch,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
