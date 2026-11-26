import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdir,readFile,writeFile,readdir,unlink,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {recoveryFixture} from './scoped-recovery-fixture.js';
import {runtimeProcesses} from '../src/runtime-manager.js';

async function endedPid(){
  const child=spawn(process.execPath,['-e','process.exit(0)'],{stdio:'ignore'});
  await new Promise<void>((ok,bad)=>{child.once('exit',()=>ok());child.once('error',bad);});return child.pid!;
}

for(const stopReceipt of [false,true])test(`a live first start blocks launch, close and release without a current receipt (stop receipt: ${stopReceipt})`,async t=>{
  const f=await recoveryFixture(t),binding=f.processBinding(process.pid),path=join(f.checkout.root,'process.json');
  await writeFile(path,JSON.stringify(binding));if(stopReceipt)await writeFile(join(f.checkout.root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
  const original=await readFile(path,'utf8'),context=f.workspace.context(f.scope),backend=f.backend();let launches=0;
  Object.assign(backend,{launch:async()=>{launches++;throw Error('Replacement launch reached');}});
  if(!stopReceipt)assert.equal((await runtimeProcesses(f.root)).some(p=>p.pid===process.pid),true);
  await assert.rejects(backend.open(f.scope),/not finished starting/);
  assert.equal(await backend.closed(f.scope),false);assert.equal(await (backend as any).neverStartedOrClosed(context),false);
  await (backend as any).inventory();assert.equal((backend as any).capacity.slots.has(context.id),true);
  // Remove diagnostic work so only process/ownership admission prevents no-work disposal.
  f.workspace.saveContext(f.scope,context.generation,{complexChanges:[],workingSnapshot:f.shared});
  assert.equal(await backend.releaseUnchanged(f.scope),false);
  const gc=await backend.collect(true);assert.ok(gc);assert.equal(launches,0);assert.deepEqual(f.deleted,[]);assert.deepEqual(f.calls,[]);
  assert.equal(await readFile(path,'utf8'),original);assert.equal(await readFile(f.bytes,'utf8'),'synthetic saved local program bytes');process.kill(process.pid,0);
});

for(const stopped of [false,true])test(`a proved ended first start continues the original checkout and archives its launch receipt (stopped receipt: ${stopped})`,async t=>{
  const f=await recoveryFixture(t),binding=f.processBinding(await endedPid()),path=join(f.checkout.root,'process.json');await writeFile(path,JSON.stringify(binding));
  if(stopped)await writeFile(join(f.checkout.root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
  const original=await readFile(path,'utf8'),before=f.workspace.context(f.scope),backend=f.backend();let copies=0;
  Object.assign(backend,{privateCopy:async(c:unknown,snapshot:unknown)=>{copies++;assert.deepEqual(c,before);assert.deepEqual(snapshot,before.workingSnapshot);}});
  assert.equal(await backend.closed(f.scope),true);await backend.open(f.scope);assert.equal(copies,1);
  assert.deepEqual(f.workspace.context(f.scope).nativeCheckout,before.nativeCheckout);assert.deepEqual(f.workspace.context(f.scope).workingSnapshot,before.workingSnapshot);
  assert.equal(await readFile(path,'utf8'),original);
  const history=await readdir(join(f.checkout.root,'worker-history'));assert.equal(history.length,1);
  assert.equal(JSON.parse(await readFile(join(f.checkout.root,'worker-history',history[0]!),'utf8')).process,original);
  assert.deepEqual(f.deleted,stopped?[binding.tokenSecret]:[]);assert.equal(f.calls.length,0);
});

test('first-start absence is proved from all owned roots, not from the ready pointer',async t=>{
  const f=await recoveryFixture(t),backend=f.backend();assert.equal(await (backend as any).neverStartedOrClosed(f.workspace.context(f.scope)),true);
  const path=join(f.checkout.root,'process.json'),valid=f.processBinding(await endedPid());
  for(const value of ['{',JSON.stringify({}),...[{pid:0},{context:'foreign'},{target:'foreign'},{session:'foreign'},{kind:'shared'},
    {program:'/foreign.bin'},{root:f.root},{endpoint:'http://remote.invalid:1'},{tokenSecret:'foreign'}].map(p=>JSON.stringify({...valid,...p}))]){
    await writeFile(path,value);const retained=await readFile(path,'utf8');
    await assert.rejects(backend.open(f.scope));await assert.rejects(backend.closed(f.scope));await assert.rejects((backend as any).neverStartedOrClosed(f.workspace.context(f.scope)));
    assert.equal(await readFile(path,'utf8'),retained);assert.equal(f.calls.length,0);
  }
  await unlink(path);
  const other=join(f.checkout.root,'..','w-historical');await mkdir(other);const live=f.processBinding(process.pid,other);
  await writeFile(join(other,'process.json'),JSON.stringify(live));await assert.rejects(backend.open(f.scope),/not proved stopped/);
  await assert.rejects(backend.closed(f.scope),/not proved stopped/);assert.deepEqual(f.deleted,[]);
  await writeFile(join(other,'process.json'),JSON.stringify({...live,pid:valid.pid}));assert.equal(await backend.closed(f.scope),true);
  await writeFile(path,JSON.stringify(valid));assert.equal(await backend.closed(f.scope),true);
});

test('a root link or malformed ready receipt cannot hide a first-start worker',async t=>{
  const f=await recoveryFixture(t),backend=f.backend(),path=join(f.checkout.root,'process.json'),binding=f.processBinding(process.pid);
  await writeFile(path,JSON.stringify(binding));const ready=join(f.checkout.root,'..','current.json');
  for(const bytes of ['{','{}']){await writeFile(ready,bytes);await assert.rejects(backend.open(f.scope));assert.equal(await readFile(path,'utf8'),JSON.stringify(binding));}
  await unlink(ready);const foreign=join(f.root,'foreign');await mkdir(foreign);
  await symlink(foreign,join(f.checkout.root,'..','linked'),process.platform==='win32'?'junction':'dir');
  await assert.rejects(backend.closed(f.scope),/root moved/);assert.equal(f.calls.length,0);assert.deepEqual(f.deleted,[]);
});

test('a ready pointer delegates to full closed validation; nested missing evidence never means no worker',async t=>{
  const f=await recoveryFixture(t),backend=f.backend(),binding=f.processBinding(process.pid),path=join(f.checkout.root,'process.json'),ready=join(f.checkout.root,'..','current.json');
  await writeFile(ready,JSON.stringify(binding));await writeFile(path,JSON.stringify(binding));
  // Readiness is established, but its referenced launch receipt has disappeared.
  await unlink(path);
  await assert.rejects((backend as any).neverStartedOrClosed(f.workspace.context(f.scope)),{code:'ENOENT'});
  await assert.rejects(backend.open(f.scope),{code:'ENOENT'});await assert.rejects((backend as any).inventory(),{code:'ENOENT'});
  assert.equal(await readFile(ready,'utf8'),JSON.stringify(binding));
  await unlink(ready);await writeFile(path,JSON.stringify({...binding,root:join(f.root,'missing')}));
  await assert.rejects((backend as any).inventory(),{code:'ENOENT'});
  await assert.rejects((backend as any).neverStartedOrClosed(f.workspace.context(f.scope)),{code:'ENOENT'});
  assert.deepEqual(f.deleted,[]);assert.equal(f.calls.length,0);
});

for(const change of [
  {name:'foreign program',patch:{program:'/foreign.bin'}},
  {name:'legacy program in a native checkout',patch:{program:'/program'}},
  {name:'remote endpoint',patch:{endpoint:'http://remote.invalid:19091'}},
  {name:'missing mode',patch:{mode:undefined}},
  {name:'missing runtime',patch:{runtimeFingerprint:undefined}},
])test('an ended ready worker with '+change.name+' cannot authorize continuation',async t=>{
  const f=await recoveryFixture(t),binding={...f.processBinding(await endedPid()),...change.patch},backend=f.backend();
  const path=join(f.checkout.root,'process.json'),ready=join(f.checkout.root,'..','current.json'),bytes=JSON.stringify(binding);
  await writeFile(path,bytes);await writeFile(ready,bytes);
  await writeFile(join(f.checkout.root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
  let launches=0;Object.assign(backend,{privateCopy:async()=>{launches++;throw Error('Unproved replacement reached');}});
  await assert.rejects(backend.open(f.scope),/receipt changed/);await assert.rejects(backend.closed(f.scope),/receipt changed/);
  await assert.rejects((backend as any).neverStartedOrClosed(f.workspace.context(f.scope)),/receipt changed/);
  await assert.rejects((backend as any).inventory(),/receipt changed/);
  assert.equal(launches,0);assert.deepEqual(f.deleted,[]);assert.deepEqual(f.calls,[]);
  assert.equal(await readFile(path,'utf8'),bytes);assert.equal(await readFile(ready,'utf8'),bytes);
});

for(const ready of [false,true])for(const changed of ['target','session'] as const)
test(`inventory rejects a foreign context ${changed} before credential access (ready: ${ready})`,async t=>{
  const f=await recoveryFixture(t),binding=f.processBinding(process.pid),backend=f.backend();
  if(changed==='target'){
    const input=join(f.root,'other.bin');await writeFile(input,'another immutable input');
    binding.target=(await f.workspace.importTarget(input)).id;
  }else binding.session='s_foreign';
  const bytes=JSON.stringify(binding),path=join(f.checkout.root,'process.json');await writeFile(path,bytes);
  if(ready)await writeFile(join(f.checkout.root,'..','current.json'),bytes);
  let credentials=0,bridge=0;
  (backend as any).c.secrets.require=async()=>{credentials++;return 'synthetic-private-token';};
  (backend as any).c.fetch=async()=>{bridge++;return Response.json({pid:binding.pid,tcp_port:19091,project_path:join(binding.root,'view')});};
  await assert.rejects((backend as any).inventory(),{code:'coordinator.binding'});
  assert.equal(credentials,0);assert.equal(bridge,0);assert.equal((backend as any).running.size,0);
  assert.equal((backend as any).capacity.slots.has(f.scope.id),false);
  assert.deepEqual(f.deleted,[]);assert.deepEqual(f.calls,[]);assert.equal(await readFile(path,'utf8'),bytes);
  assert.equal(await readFile(f.bytes,'utf8'),'synthetic saved local program bytes');process.kill(process.pid,0);
});
