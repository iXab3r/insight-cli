import test from 'node:test';
import assert from 'node:assert/strict';
import {access,link,lstat,mkdir,mkdtemp,readFile,readdir,rm,symlink,unlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {Workspace,type GhidraContext} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import {Research} from '../src/research.js';
import {transferCategories} from '../src/cross-results.js';
import type {Artifact} from '../src/artifacts.js';
import {collectStorage,type CollectionPort} from '../src/storage-gc.js';
import type {NativeInputs} from '../src/native-inputs.js';
import type {CommandContext} from '@eyeauras/cli-factory';

const exists=(path:string)=>access(path).then(()=>true,()=>false);
async function fixture(t:test.TestContext,dropped=true){
  const directory=await mkdtemp(join(tmpdir(),'cross-peer-')),workspace=new Workspace(join(directory,'workspace'),'default');
  t.after(async()=>{workspace.close();await rm(directory,{recursive:true,force:true});});
  const input=join(directory,'input.bin');await writeFile(input,'owned synthetic input');const target=await workspace.importTarget(input);
  const snapshot=async(text:string)=>{const path=join(directory,randomUUID());await writeFile(path,text);return workspace.captureSnapshot(path);};
  const saved=await snapshot('saved private research');
  const open=()=>{
    const {context,request}=workspace.reserveOpen(target.id,'new',{autoAnalyze:false});workspace.recordRequest(request.id,'failed',{state:'not_opened'});
    return workspace.saveContext(context,context.generation,{state:'stopped',workingSnapshot:saved,baseSnapshot:saved,baseRevision:1});
  };
  const initial=open(),root=join(workspace.directory,'ghidra-native','context',initial.id,'w-owned');await mkdir(root,{recursive:true});
  const context=workspace.saveContext(initial,initial.generation,{complexChanges:dropped?[]:['saved-private-edit'],nativeCheckout:{schema:1,context:initial.id,root,
    origin:'ghidra://127.0.0.1:1',repository:'owned',path:'/'+target.id+'.bin',fileId:'file',checkoutId:1,baseVersion:1,runtimeFingerprint:'a'.repeat(64),state:dropped?'dropped':'active'}});
  if(!dropped){await writeFile(join(root,'native-owner.json'),JSON.stringify({context:context.id,target:target.id}));await mkdir(join(root,'view.rep'));await writeFile(join(root,'view.rep','db.gbf'),'private database');}
  await writeFile(join(root,'process.json'),JSON.stringify({kind:'context',context:context.id,target:target.id,root,pid:999999,tokenSecret:'owned',mode:'headless'}));
  await writeFile(join(root,'stopped.json'),JSON.stringify({pid:999999,tokenSecret:'owned',reason:'explicit_close'}));
  await writeFile(join(root,'runtime.log'),'retained log');await mkdir(join(root,'operations'));await writeFile(join(root,'operations','journal.json'),'retained journal');
  const stage=async(packed= saved,state='closed')=>{
    const name='__insight_peer_'+randomUUID().replaceAll('-',''),folder=join(root,'cross-peer',name);await mkdir(folder,{recursive:true});
    const input=join(folder,'input.gzf'),receipt=join(folder,'receipt.json');await link(await workspace.artifacts.verify(packed),input);
    await writeFile(receipt,JSON.stringify({path:'/'+name,context:context.id,target:target.id,state}));return {folder,input,receipt,name};
  };
  const port:CollectionPort={closed:async()=>true,release:async()=>false};
  return {directory,workspace,target,context,root,saved,snapshot,open,stage,port};
}
type Fixture=Awaited<ReturnType<typeof fixture>>;
async function backend(f:Fixture,action?:(operation:string,parameters:Record<string,unknown>)=>Promise<unknown>){
  const calls:{operation:string;parameters:Record<string,unknown>}[]=[],inputs:string[]=[];
  const record={binding:{root:f.root,target:f.target.id,context:f.context.id,program:'/selected'},http:{call:async(operation:string,parameters:Record<string,unknown>)=>{
    calls.push({operation,parameters});
    if(operation==='/import_program')inputs.push(String(parameters.gzf_path));
    const value=await action?.(operation,parameters);if(value!==undefined)return value;
    return operation==='/open_program'?{path:parameters.path}:{success:true};
  }}};
  const contexts=new GhidraContexts(f.workspace,{} as NativeInputs,{signal:new AbortController().signal} as CommandContext);
  Object.assign(contexts,{selected:async()=>record,fork:()=>({verified:async()=>record})});
  const compare=()=>contexts.pair(f.context,f.context,f.saved,'/diff_functions',{});
  return {contexts,compare,calls,inputs};
}

test('successful comparison unlinks only its staged input after verified native close and removal',async t=>{
  const f=await fixture(t),b=await backend(f,async operation=>{
    if(operation==='/diff_functions')assert.equal((await lstat(await f.workspace.artifacts.verify(f.saved))).nlink,2);
    return undefined;
  });
  await b.compare();const input=b.inputs[0]!,receipt=join(input,'..','receipt.json');
  assert.deepEqual(b.calls.map(c=>c.operation),['/import_program','/open_program','/diff_functions','/close_program','/delete_file']);
  assert.equal(await exists(input),false);assert.equal(JSON.parse(await readFile(receipt,'utf8')).state,'closed');
  assert.equal((await lstat(await f.workspace.artifacts.verify(f.saved))).nlink,1);
});

test('native saved receipts use the existing export capture and leave no cross-peer packed program after compare and gc',async t=>{
  const f=await fixture(t,false),path=join(f.directory,'native.json');
  await writeFile(path,JSON.stringify({source:'checkout',checkout:f.context.nativeCheckout,fingerprint:'a'.repeat(64)}));
  const native=await f.workspace.captureNative(path),b=await backend(f,async(operation,p)=>{
    if(operation==='/export_program')await writeFile(join(String(p.output_dir),String(p.output_name)),'native full export');
  });
  f.workspace.saveContext(f.context,f.context.generation,{workingSnapshot:native});
  Object.assign(b.contexts,{closed:async()=>false,nativeView:async()=>({fingerprint:'a'.repeat(64)})});
  await b.contexts.pair(f.context,f.context,native,'/diff_functions',{});
  const packed=f.workspace.allArtifacts().find(a=>a.kind==='snapshot'&&a.id!==f.saved.id)!;
  assert.equal(packed.size,'native full export'.length);assert.equal(await exists(b.inputs[0]!),false);
  assert.equal((await lstat(await f.workspace.artifacts.verify(packed))).nlink,1);
  const planned=await collectStorage(f.workspace,f.port,true),done=await collectStorage(f.workspace,f.port,false);
  assert.equal(done.bytes,planned.bytes);assert.equal(done.bytes,packed.size);assert.equal(await exists(f.workspace.artifacts.path(packed)),false);
  assert.equal(JSON.parse(await readFile(join(b.inputs[0]!,'..','receipt.json'),'utf8')).state,'closed');
});

for(const failed of ['/import_program','/open_program','/diff_functions'])test('a failed '+failed+' keeps saved research and removes only a verified closed temporary input',async t=>{
  const f=await fixture(t),b=await backend(f,async operation=>{if(operation===failed)throw Error('injected action failure');});
  await assert.rejects(b.compare(),/injected action failure/);
  assert.equal(await exists(b.inputs[0]!),false);await f.workspace.artifacts.verify(f.saved);
  assert.deepEqual(b.calls.slice(-2).map(c=>c.operation),['/close_program','/delete_file']);
});

for(const failed of ['/close_program','/delete_file'])test('uncertain '+failed+' keeps preparing input until native reconciliation succeeds',async t=>{
  const f=await fixture(t);let refuse=true;
  const b=await backend(f,async operation=>{if(refuse&&operation===failed)throw Error('injected cleanup failure');});
  await assert.rejects(b.compare(),/injected cleanup failure/);const old=b.inputs[0]!,receipt=join(old,'..','receipt.json');
  assert.ok(await exists(old));assert.equal(JSON.parse(await readFile(receipt,'utf8')).state,'preparing');
  for(const dry of [true,false]){
    const gc=await collectStorage(f.workspace,f.port,dry);assert.ok(gc.retained.some(r=>r.path===join(old,'..')&&/incomplete/.test(r.reason)));assert.ok(await exists(old));
  }
  refuse=false;const start=b.calls.length;await b.compare();
  assert.deepEqual(b.calls.slice(start,start+3).map(c=>c.operation),['/close_program','/delete_file','/import_program']);
  assert.equal(await exists(old),false);assert.equal(JSON.parse(await readFile(receipt,'utf8')).state,'closed');
  for(const input of b.inputs)assert.equal(await exists(input),false);
});

test('reconciliation reclaims historical closed inputs without calling native cleanup again',async t=>{
  const f=await fixture(t),old=await f.stage(),before=await readFile(old.receipt,'utf8'),b=await backend(f);
  await b.compare();assert.equal(await exists(old.input),false);assert.equal(await readFile(old.receipt,'utf8'),before);
  assert.equal(b.calls.filter(c=>c.operation==='/close_program').length,1);
});

test('an unlink failure preserves its closed receipt and input for reconciliation without replaying native removal',async t=>{
  const f=await fixture(t),b=await backend(f),original=fs.promises.unlink;let refuse=true;
  const mock=t.mock.method(fs.promises,'unlink',async(path:Parameters<typeof unlink>[0])=>{
    if(refuse&&String(path)===b.inputs[0])throw Object.assign(Error('injected unlink failure'),{code:'EACCES'});
    return original(path);
  });syncBuiltinESMExports();
  try{
    await assert.rejects(b.compare(),/injected unlink failure/);const old=b.inputs[0]!,receipt=join(old,'..','receipt.json'),closed=await readFile(receipt,'utf8');
    assert.ok(await exists(old));assert.equal(JSON.parse(closed).state,'closed');refuse=false;
    await b.compare();assert.equal(await exists(old),false);assert.equal(await readFile(receipt,'utf8'),closed);
    assert.equal(b.calls.filter(c=>c.operation==='/close_program').length,2);
  }finally{mock.mock.restore();syncBuiltinESMExports();}
});

test('cleanup does not overwrite a foreign ownership receipt or remove its input',async t=>{
  const f=await fixture(t);let input='';
  const b=await backend(f,async(operation,p)=>{
    if(operation==='/import_program')input=String(p.gzf_path);
    if(operation==='/diff_functions'){
      const receipt=join(input,'..','receipt.json'),r=JSON.parse(await readFile(receipt,'utf8'));
      await writeFile(receipt,JSON.stringify({...r,context:'c_foreign'}));
    }
  });
  await assert.rejects(b.compare(),/another context/);assert.ok(await exists(input));
  assert.equal(JSON.parse(await readFile(join(input,'..','receipt.json'),'utf8')).context,'c_foreign');
});

test('an unexpected file appearing during compare keeps the stage and blocks subsequent reconciliation',async t=>{
  const f=await fixture(t);let input='';
  const b=await backend(f,async(operation,p)=>{
    if(operation==='/import_program')input=String(p.gzf_path);
    if(operation==='/diff_functions')await writeFile(join(input,'..','research.txt'),'saved research');
  });
  await assert.rejects(b.compare(),/unrecognized files/);assert.ok(await exists(input));await assert.rejects(b.compare(),/unrecognized files/);
  const result=await collectStorage(f.workspace,f.port,false);assert.ok(result.retained.some(r=>r.path===join(input,'..')&&/unrecognized files/.test(r.reason)));
  assert.equal(await readFile(join(input,'..','research.txt'),'utf8'),'saved research');
});

for(const dropped of [false,true])test('gc reclaims historical completed input after '+(dropped?'native disposal':'worker close')+' and counts its last hardlink',async t=>{
  const f=await fixture(t,dropped),packed=await f.snapshot('historical full packed export'),s=await f.stage(packed);
  f.workspace.forgetArtifact(packed.id);await unlink(f.workspace.artifacts.path(packed));assert.equal((await lstat(s.input)).nlink,1);
  const receipt=await readFile(s.receipt,'utf8'),before=await readdir(s.folder),planned=await collectStorage(f.workspace,f.port,true);
  assert.deepEqual(await readdir(s.folder),before);assert.deepEqual(planned.categories['duplicate-exports'],{items:1,bytes:packed.size});
  const done=await collectStorage(f.workspace,f.port,false);assert.deepEqual(done.categories,planned.categories);
  assert.equal(await exists(s.input),false);assert.equal(await readFile(s.receipt,'utf8'),receipt);
  assert.equal(await readFile(join(f.root,'runtime.log'),'utf8'),'retained log');assert.equal(await readFile(join(f.root,'operations','journal.json'),'utf8'),'retained journal');
  if(!dropped)assert.equal(await readFile(join(f.root,'view.rep','db.gbf'),'utf8'),'private database');
  const again=await collectStorage(f.workspace,f.port,false);assert.equal(again.bytes,0);assert.equal(again.categories['duplicate-exports'],undefined);
});

test('gc counts all removed hardlink names once and keeps links rooted by saved research',async t=>{
  const f=await fixture(t),packed=await f.snapshot('unreferenced export'),a=await f.stage(packed),b=await f.stage(packed),kept=await f.stage(f.saved);
  const foreign=join(f.directory,'saved-research.gzf');await link(await f.workspace.artifacts.verify(f.saved),foreign);
  const planned=await collectStorage(f.workspace,f.port,true),done=await collectStorage(f.workspace,f.port,false);
  assert.deepEqual(done.categories,planned.categories);assert.equal(done.bytes,packed.size);assert.equal(done.categories['duplicate-exports']!.items,3);
  for(const s of [a,b,kept])assert.equal(await exists(s.input),false);
  assert.equal(await exists(f.workspace.artifacts.path(packed)),false);assert.equal((await lstat(foreign)).nlink,2);
  await f.workspace.artifacts.verify(f.saved);assert.equal(await readFile(foreign,'utf8'),'saved private research');
});

test('a retained foreign hardlink prevents any claimed physical saving',async t=>{
  const f=await fixture(t),packed=await f.snapshot('export with a foreign name'),s=await f.stage(packed),foreign=join(f.directory,'foreign.gzf');
  await link(s.input,foreign);
  for(const dry of [true,false])assert.equal((await collectStorage(f.workspace,f.port,dry)).bytes,0);
  assert.equal(await exists(s.input),false);assert.equal((await lstat(foreign)).nlink,1);assert.equal(await readFile(foreign,'utf8'),'export with a foreign name');
});

test('gc reports failed input removal without counting its bytes when the other hardlink is collected',async t=>{
  const f=await fixture(t),packed=await f.snapshot('export with failed removal'),s=await f.stage(packed);await f.stage(f.saved);
  const planned=await collectStorage(f.workspace,f.port,true);assert.equal(planned.bytes,packed.size);
  const original=fs.promises.unlink,mock=t.mock.method(fs.promises,'unlink',async(path:Parameters<typeof unlink>[0])=>{
    if(String(path)===s.input)throw Object.assign(Error('injected unlink failure'),{code:'EACCES'});
    return original(path);
  });syncBuiltinESMExports();
  try{
    const result=await collectStorage(f.workspace,f.port,false);assert.equal(result.bytes,0);assert.equal(result.categories['duplicate-exports']!.items,1);
    assert.ok(result.retained.some(r=>r.path===s.input&&/Removal failed: EACCES/.test(r.reason)));
    assert.equal((await lstat(s.input)).nlink,1);assert.equal(await exists(f.workspace.artifacts.path(packed)),false);
    const receipt=JSON.parse(await readFile(join(f.workspace.directory,'gc',result.id!+'.json'),'utf8'));
    assert.equal(receipt.bytes,0);assert.deepEqual(receipt.retained,result.retained);
  }finally{mock.mock.restore();syncBuiltinESMExports();}
  assert.equal((await collectStorage(f.workspace,f.port,false)).bytes,packed.size);
});

const invalid:Record<string,{prepare:(f:Fixture,s:Awaited<ReturnType<Fixture['stage']>>)=>Promise<unknown>;reason:RegExp}>={
  preparing:{prepare:async(_f,s)=>{const r=JSON.parse(await readFile(s.receipt,'utf8'));await writeFile(s.receipt,JSON.stringify({...r,state:'preparing'}));},reason:/incomplete/},
  'unknown state':{prepare:async(_f,s)=>{const r=JSON.parse(await readFile(s.receipt,'utf8'));await writeFile(s.receipt,JSON.stringify({...r,state:'unknown'}));},reason:/Unknown/},
  'foreign context':{prepare:async(_f,s)=>{const r=JSON.parse(await readFile(s.receipt,'utf8'));await writeFile(s.receipt,JSON.stringify({...r,context:'c_foreign'}));},reason:/another context/},
  'foreign target':{prepare:async(_f,s)=>{const r=JSON.parse(await readFile(s.receipt,'utf8'));await writeFile(s.receipt,JSON.stringify({...r,target:'t_foreign'}));},reason:/another context/},
  'foreign path':{prepare:async(_f,s)=>{const r=JSON.parse(await readFile(s.receipt,'utf8'));await writeFile(s.receipt,JSON.stringify({...r,path:'/foreign'}));},reason:/another context/},
  'missing receipt':{prepare:async(_f,s)=>unlink(s.receipt),reason:/missing or malformed/},
  'malformed receipt':{prepare:async(_f,s)=>writeFile(s.receipt,'{'),reason:/missing or malformed/},
  'extra file':{prepare:async(_f,s)=>writeFile(join(s.folder,'research.txt'),'saved research'),reason:/unrecognized files/},
  'extra directory':{prepare:async(_f,s)=>mkdir(join(s.folder,'journal')),reason:/unrecognized files/},
  'changed worker target':{prepare:async(f)=>writeFile(join(f.root,'process.json'),JSON.stringify({kind:'context',context:f.context.id,target:'t_foreign',pid:999999,tokenSecret:'owned'})),reason:/different owner/},
  'changed native owner':{prepare:async(f)=>writeFile(join(f.root,'native-owner.json'),JSON.stringify({context:'c_foreign',target:f.target.id})),reason:/different owner/},
  'linked native owner':{prepare:async(f,s)=>symlink(s.folder,join(f.root,'native-owner.json'),'junction'),reason:/ownership receipt is a link/},
};
for(const [name,{prepare,reason}] of Object.entries(invalid))test('gc retains and explains a completed cross-peer input with '+name,async t=>{
  const f=await fixture(t),s=await f.stage();await prepare(f,s);
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);assert.ok(result.retained.some(r=>r.path===s.folder&&reason.test(r.reason)),JSON.stringify(result.retained));
    assert.equal(result.categories['duplicate-exports'],undefined);assert.ok(await exists(s.input));
  }
});

test('an unreadable stage receipt is retained and explained without deleting its input',async t=>{
  const f=await fixture(t),s=await f.stage(),original=fs.promises.readFile;
  const mock=t.mock.method(fs.promises,'readFile',((path:Parameters<typeof readFile>[0],...options:unknown[])=>{
    if(String(path)===s.receipt)return Promise.reject(Object.assign(Error('injected read failure'),{code:'EACCES'}));
    return Reflect.apply(original,fs.promises,[path,...options]);
  }) as typeof readFile);syncBuiltinESMExports();
  try{
    for(const dry of [true,false]){
      const result=await collectStorage(f.workspace,f.port,dry);
      assert.ok(result.retained.some(r=>r.path===s.folder&&/could not be verified: EACCES/.test(r.reason)));assert.ok(await exists(s.input));
    }
  }finally{mock.mock.restore();syncBuiltinESMExports();}
});

for(const name of ['cross-peer','stage','input.gzf','receipt.json'])test('gc never follows a linked '+name+' in cross-peer storage',async t=>{
  const f=await fixture(t),s=await f.stage(),foreign=join(f.directory,'foreign');await mkdir(foreign);
  await writeFile(join(foreign,'input.gzf'),'foreign bytes');await writeFile(join(foreign,'receipt.json'),'foreign receipt');
  const path=name==='cross-peer'?join(f.root,name):name==='stage'?s.folder:join(s.folder,name);
  const moved=path+'-original';const {rename}=await import('node:fs/promises');await rename(path,moved);await symlink(foreign,path,'junction');
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);assert.ok(result.retained.some(r=>/link|unrecognized/.test(r.reason)));assert.equal(result.bytes,0);
  }
  assert.equal(await readFile(join(foreign,'input.gzf'),'utf8'),'foreign bytes');assert.equal(await readFile(join(foreign,'receipt.json'),'utf8'),'foreign receipt');
});

for(const outcome of ['running','unknown','failed'] as const)test('a '+outcome+' operation retains its completed input and saved evidence',async t=>{
  const f=await fixture(t),s=await f.stage(),r=f.workspace.reserveRequest(f.context,'/merge_program_documentation',{}).request;
  f.workspace.startRequest(r.id,{sourceSnapshot:f.saved});if(outcome!=='running')f.workspace.recordRequest(r.id,outcome,{outcome:'unknown'});
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);assert.ok(result.retained.some(r=>/unresolved or uncertain/.test(r.reason)));assert.ok(await exists(s.input));
  }
  await f.workspace.artifacts.verify(f.saved);
});

test('another context referencing the checkout keeps even its completed stage',async t=>{
  const f=await fixture(t),s=await f.stage(),other=f.open(),path=join(f.directory,'source.json');
  await writeFile(path,JSON.stringify({source:'checkout',checkout:f.context.nativeCheckout}));const source=await f.workspace.captureNative(path);
  const r=f.workspace.reserveRequest(other,'/merge_program_documentation',{}).request;f.workspace.startRequest(r.id,{sourceSnapshot:source});f.workspace.recordRequest(r.id,'unknown',{});
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);assert.ok(result.retained.some(r=>r.path===s.folder&&/another context references/.test(r.reason)));assert.ok(await exists(s.input));
  }
  f.workspace.recordRequest(r.id,'failed',{});await collectStorage(f.workspace,f.port,false);assert.equal(await exists(s.input),false);
});

for(const cleanupFailure of [false,true])test('Research retains immutable native transfer bytes through lost acknowledgement, gc and reconciliation'+(cleanupFailure?' with interrupted cleanup':''),async t=>{
  const f=await fixture(t,false),source=f.open(),sourceRoot=join(f.workspace.directory,'ghidra-native','context',source.id,'w-source');
  await mkdir(sourceRoot,{recursive:true});
  const sourceContext=f.workspace.saveContext(source,source.generation,{nativeCheckout:{...f.context.nativeCheckout!,context:source.id,root:sourceRoot},complexChanges:['source-private-edit']});
  const receipt=async(context:GhidraContext,fingerprint:string)=>{
    const path=join(f.directory,randomUUID()+'.json');await writeFile(path,JSON.stringify({source:'checkout',checkout:context.nativeCheckout,fingerprint}));return f.workspace.captureNative(path);
  };
  let sourceView=await receipt(sourceContext,'a'.repeat(64)),destinationView=await receipt(f.context,'b'.repeat(64));
  f.workspace.saveContext(sourceContext,sourceContext.generation,{workingSnapshot:sourceView});
  f.workspace.saveContext(f.context,f.context.generation,{workingSnapshot:destinationView});
  const originalSourceView=sourceView,inputs:string[]=[],programs=new Map<string,string>(),checks:string[]=[];
  let sourceBytes='immutable source documentation',destinationBytes='old receiver documentation',writes=0,sourceExports=0,match=false,refuseCleanup=cleanupFailure;
  const contexts=new GhidraContexts(f.workspace,{} as NativeInputs,{signal:new AbortController().signal} as CommandContext);
  const record=(context:GhidraContext,program:string)=>({binding:{root:context.nativeCheckout!.root,context:context.id,target:context.target,program},http:{call:async(operation:string,p:Record<string,unknown>)=>{
    if(operation==='/export_program'){
      if(program==='/source')sourceExports++;
      await writeFile(join(String(p.output_dir),String(p.output_name)),program==='/source'?sourceBytes:destinationBytes);
    }
    if(operation==='/import_program'){inputs.push(String(p.gzf_path));programs.set('/'+p.target_name,await readFile(String(p.gzf_path),'utf8'));}
    if(operation==='/open_program')return {path:p.path};
    if(operation==='/delete_file'){
      if(refuseCleanup)throw Error('lost cleanup acknowledgement');programs.delete(String(p.filePath));
    }
    if(operation==='/merge_program_documentation'){
      const bytes=programs.get(String(p.source));assert.ok(bytes);
      if(p.dry_run===false){
        writes++;destinationBytes=bytes;destinationView=await receipt(f.context,'c'.repeat(64));throw Error('lost native transfer acknowledgement');
      }
      checks.push(bytes);assert.equal(programs.get(String(p.target)),destinationBytes);
      const remaining=match&&bytes===programs.get(String(p.target))?0:1;
      return {dry_run:true,errors:0,...Object.fromEntries(transferCategories.map(key=>[key,{planned:key==='instruction_comments'?remaining:0,applied:key==='instruction_comments'?remaining:0}]))};
    }
    return {success:true};
  }}});
  const sourceRecord=record(sourceContext,'/source'),destinationRecord=record(f.context,'/selected');
  Object.assign(contexts,{open:async(scope:GhidraContext)=>f.workspace.context(scope),closed:async()=>false,
    saved:async(scope:GhidraContext)=>scope.session===source.session?sourceView:destinationView,
    selected:async(scope:GhidraContext)=>scope.session===source.session?sourceRecord:destinationRecord,
    nativeView:async()=>({}),fork:()=>({verified:async()=>destinationRecord})});
  const research=new Research(f.workspace,async()=>contexts);
  await assert.rejects(research.transfer(f.context,source,false,'lost-native-transfer'),/lost .*acknowledgement/);
  const request=f.workspace.scopedRequest(f.context,'lost-native-transfer')!,execution=request.execution as {sourceSnapshot:Artifact;sourceView:Artifact};
  assert.equal(request.state,'unknown');assert.equal(execution.sourceSnapshot.kind,'snapshot');assert.equal(execution.sourceView.id,originalSourceView.id);
  assert.equal(await readFile(await f.workspace.artifacts.verify(execution.sourceSnapshot),'utf8'),'immutable source documentation');
  const originalInput=inputs[0]!,stageReceipt=join(originalInput,'..','receipt.json');assert.ok(await exists(originalInput));
  for(const dry of [true,false]){
    const gc=await collectStorage(f.workspace,f.port,dry);assert.ok(gc.retained.some(r=>/unresolved or uncertain/.test(r.reason)));
    assert.ok(await exists(originalInput));await f.workspace.artifacts.verify(execution.sourceSnapshot);
  }
  // The source's mutable native checkout no longer has the revision used by the unknown transfer.
  sourceBytes='later source documentation';sourceView=await receipt(sourceContext,'d'.repeat(64));
  const currentSource=f.workspace.context(source);f.workspace.saveContext(source,currentSource.generation,{workingSnapshot:sourceView});
  refuseCleanup=false;
  await research.reconcileRequests(f.context,contexts);assert.equal(f.workspace.request(request.id).state,'unknown');
  assert.equal(JSON.parse(await readFile(stageReceipt,'utf8')).state,'closed');assert.ok(await exists(originalInput));
  await collectStorage(f.workspace,f.port,false);await f.workspace.artifacts.verify(execution.sourceSnapshot);
  match=true;await research.reconcileRequests(f.context,contexts);
  const settled=f.workspace.request(request.id);assert.equal(settled.state,'applied');assert.equal((settled.result as {reconciled:boolean}).reconciled,true);
  assert.equal(writes,1);assert.equal(sourceExports,1);assert.deepEqual(checks,['immutable source documentation','immutable source documentation']);
  assert.equal(destinationBytes,'immutable source documentation');assert.equal(sourceBytes,'later source documentation');
  await collectStorage(f.workspace,f.port,false);
  for(const input of inputs)assert.equal(await exists(input),false);
  assert.equal(await exists(f.workspace.artifacts.path(execution.sourceSnapshot)),false);
  assert.equal(await readFile(join(f.root,'operations','journal.json'),'utf8'),'retained journal');
});

for(const state of ['closed','preparing'])test('reconciliation preserves the last packed input of an older native-only unknown transfer with '+state+' cleanup',async t=>{
  const f=await fixture(t),packed=await f.snapshot('only surviving original source bytes'),s=await f.stage(packed,state),path=join(f.directory,'native-source.json');
  await writeFile(path,JSON.stringify({source:'checkout',checkout:f.context.nativeCheckout}));const native=await f.workspace.captureNative(path);
  const r=f.workspace.reserveRequest(f.context,'/merge_program_documentation',{}).request;f.workspace.startRequest(r.id,{kind:'transfer',sourceSnapshot:native});f.workspace.recordRequest(r.id,'unknown',{});
  f.workspace.forgetArtifact(packed.id);await unlink(f.workspace.artifacts.path(packed));const b=await backend(f);
  await b.compare();assert.equal(JSON.parse(await readFile(s.receipt,'utf8')).state,'closed');
  assert.equal(await readFile(s.input,'utf8'),'only surviving original source bytes');assert.equal((await lstat(s.input)).nlink,1);
  assert.ok(b.calls.every(call=>call.operation!=='/merge_program_documentation'));
  for(const dry of [true,false]){await collectStorage(f.workspace,f.port,dry);assert.ok(await exists(s.input));}
  f.workspace.recordRequest(r.id,'failed',{});await b.compare();assert.equal(await exists(s.input),false);
});

for(const [abandoned,alias] of [[false,false],[true,false],[false,true]])test('gc checks the scanned historical root after checkout replacement'+(abandoned?' for an abandoned unknown effect':alias?' through its retained alias':''),async t=>{
  const f=await fixture(t),packed=await f.snapshot('x'.repeat(55)),s=await f.stage(packed),other=f.open(),path=join(f.directory,'old-source.json');
  const sourceRoot=alias?join(f.directory,'old-root-alias'):f.root;if(alias)await symlink(f.root,sourceRoot,'junction');
  await writeFile(path,JSON.stringify({source:'checkout',checkout:{...f.context.nativeCheckout,root:sourceRoot}}));const source=await f.workspace.captureNative(path);
  const replacement=join(f.root,'..','w-replacement');await mkdir(replacement);
  await writeFile(join(replacement,'process.json'),await readFile(join(f.root,'process.json')));await writeFile(join(replacement,'stopped.json'),await readFile(join(f.root,'stopped.json')));
  f.workspace.saveContext(f.context,f.context.generation,{nativeCheckout:{...f.context.nativeCheckout!,root:replacement}});
  f.workspace.forgetArtifact(packed.id);await unlink(f.workspace.artifacts.path(packed));assert.equal((await lstat(s.input)).nlink,1);
  const r=f.workspace.reserveRequest(other,'/merge_program_documentation',{}).request;f.workspace.startRequest(r.id,{sourceSnapshot:source});
  f.workspace.recordRequest(r.id,abandoned?'failed':'unknown',abandoned?{outcome:'unknown'}:{});
  const current=f.workspace.context(f.context);assert.equal(f.workspace.checkoutReferenced(current),false);assert.equal(f.workspace.checkoutReferenced(current,f.root),true);
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);assert.equal(result.bytes,0);assert.equal(result.categories['duplicate-exports'],undefined);
    assert.ok(result.retained.some(row=>row.path===s.folder&&/another context references/.test(row.reason)));assert.ok(await exists(s.input));
  }
  if(!abandoned){
    f.workspace.recordRequest(r.id,'failed',{});const result=await collectStorage(f.workspace,f.port,false);
    assert.equal(await exists(s.input),false);assert.equal(result.categories['duplicate-exports']!.bytes,55);
  }
});

test('gc retains and reports an unreadable native-owner receipt in dry-run and execution',async t=>{
  const f=await fixture(t,false),s=await f.stage(),owner=join(f.root,'native-owner.json'),before=await readFile(owner,'utf8'),original=fs.promises.readFile;
  const mock=t.mock.method(fs.promises,'readFile',((path:Parameters<typeof readFile>[0],...options:unknown[])=>{
    if(String(path)===owner)return Promise.reject(Object.assign(Error('injected native owner read failure'),{code:'EACCES'}));
    return Reflect.apply(original,fs.promises,[path,...options]);
  }) as typeof readFile);syncBuiltinESMExports();
  try{
    for(const dry of [true,false]){
      const result=await collectStorage(f.workspace,f.port,dry);assert.equal(result.state,dry?'planned':'complete');assert.equal(result.bytes,0);
      assert.ok(result.retained.some(r=>r.path===s.folder&&/ownership receipt could not be verified: EACCES/.test(r.reason)));assert.ok(await exists(s.input));
      if(!dry){const receipt=JSON.parse(await readFile(join(f.workspace.directory,'gc',result.id!+'.json'),'utf8'));assert.deepEqual(receipt.retained,result.retained);}
    }
  }finally{mock.mock.restore();syncBuiltinESMExports();}
  assert.equal(await readFile(owner,'utf8'),before);await collectStorage(f.workspace,f.port,false);assert.equal(await exists(s.input),false);
});

for(const proof of ['missing process','unreadable process','unreadable stop'] as const)test('gc retains a historical peer input with '+proof+' proof despite a stopped replacement checkout',async t=>{
  const f=await fixture(t,false),packed=await f.snapshot('last historical source bytes'),s=await f.stage(packed);
  const replacement=join(f.root,'..','w-replacement');await mkdir(replacement);
  for(const name of ['process.json','stopped.json','native-owner.json'])await writeFile(join(replacement,name),await readFile(join(f.root,name)));
  f.workspace.saveContext(f.context,f.context.generation,{nativeCheckout:{...f.context.nativeCheckout!,root:replacement}});
  f.workspace.forgetArtifact(packed.id);await unlink(f.workspace.artifacts.path(packed));assert.equal((await lstat(s.input)).nlink,1);
  const process=join(f.root,'process.json'),stop=join(f.root,'stopped.json');
  if(proof==='missing process')await unlink(process);
  const original=fs.promises.readFile,mock=proof==='missing process'?undefined:t.mock.method(fs.promises,'readFile',((path:Parameters<typeof readFile>[0],...options:unknown[])=>{
    if(String(path)===(proof==='unreadable process'?process:stop))return Promise.reject(Object.assign(Error('injected historical worker proof read failure'),{code:'EACCES'}));
    return Reflect.apply(original,fs.promises,[path,...options]);
  }) as typeof readFile);syncBuiltinESMExports();
  try{
    for(const dry of [true,false]){
      const result=await collectStorage(f.workspace,f.port,dry);assert.equal(result.state,dry?'planned':'complete');assert.equal(result.bytes,0);
      const reason=proof==='missing process'?/no worker receipt that proves it stopped/:/worker proof could not be verified: EACCES/;
      assert.ok(result.retained.some(row=>[f.root,s.folder].includes(row.path)&&reason.test(row.reason)));
      assert.equal(await readFile(s.input,'utf8'),'last historical source bytes');
      if(!dry){const receipt=JSON.parse(await readFile(join(f.workspace.directory,'gc',result.id!+'.json'),'utf8'));assert.deepEqual(receipt.retained,result.retained);}
    }
  }finally{mock?.mock.restore();syncBuiltinESMExports();}
  if(proof==='missing process')await writeFile(process,await readFile(join(replacement,'process.json')));
  await collectStorage(f.workspace,f.port,false);assert.equal(await exists(s.input),false);
});

for(const binding of ['missing','replacement','alias'] as const)test('historical peer worker root binding is '+binding,async t=>{
  const f=await fixture(t,false),packed=await f.snapshot('historical input binding'),s=await f.stage(packed);
  f.workspace.forgetArtifact(packed.id);await unlink(f.workspace.artifacts.path(packed));assert.equal((await lstat(s.input)).nlink,1);
  const replacement=join(f.root,'..','w-replacement'),processReceipt=join(f.root,'process.json'),worker=JSON.parse(await readFile(processReceipt,'utf8'));
  await mkdir(replacement);await writeFile(join(replacement,'process.json'),JSON.stringify({...worker,root:replacement}));
  for(const name of ['stopped.json','native-owner.json'])await writeFile(join(replacement,name),await readFile(join(f.root,name)));
  f.workspace.saveContext(f.context,f.context.generation,{nativeCheckout:{...f.context.nativeCheckout!,root:replacement}});
  const historical={...worker};
  if(binding==='missing')delete historical.root;
  else if(binding==='replacement')historical.root=replacement;
  else{historical.root=join(f.directory,'historical-alias');await symlink(f.root,historical.root,'junction');}
  await writeFile(processReceipt,JSON.stringify(historical));
  for(const dry of [true,false]){
    const result=await collectStorage(f.workspace,f.port,dry);
    if(binding==='alias'){
      assert.equal(result.categories['duplicate-exports']!.bytes,packed.size);assert.equal(await exists(s.input),dry);
    }else{
      assert.equal(result.bytes,0);assert.ok(await exists(s.input));
      assert.ok(result.retained.some(row=>row.path===s.folder&&/does not identify this working root/.test(row.reason)));
    }
  }
  if(binding!=='alias'){await writeFile(processReceipt,JSON.stringify(worker));await collectStorage(f.workspace,f.port,false);assert.equal(await exists(s.input),false);}
});
