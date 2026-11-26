import type {TestContext} from 'node:test';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import type {CommandContext} from '@eyeauras/cli-factory';
import {Workspace,type NativeCheckout} from '../src/workspace.js';
import {GhidraContexts} from '../src/contexts.js';
import type {NativeInputs} from '../src/native-inputs.js';
import type {GhidraServer} from '../src/server.js';

/** Real workspace/artifact journals; all Ghidra/DB/server execution is replaced at the native boundary. */
export async function recoveryFixture(t:TestContext){
  const root=await mkdtemp(join(tmpdir(),'insight-scoped-recovery-'));let workspace=new Workspace(join(root,'workspace'),'default');
  t.after(async()=>{workspace.close();await rm(root,{recursive:true,force:true});});
  const input=join(root,'input.bin');await writeFile(input,'offline recovery fixture; no executable or native database');
  const target=await workspace.importTarget(input),reservation=workspace.reserveOpen(target.id,'new',{autoAnalyze:false}),scope=reservation.context;
  workspace.recordRequest(reservation.request.id,'failed',{});
  const checkout:NativeCheckout={schema:1,context:scope.id,root:join(workspace.directory,'ghidra-native','context',scope.id,'w-owned'),
    fileId:'owned-file',checkoutId:3,baseVersion:1,origin:'ghidra://127.0.0.1:12345',repository:'owned',path:'/'+target.id+'.bin',runtimeFingerprint:'d'.repeat(64),state:'active'};
  const owner={schema:1,protocol:'native-checkout-v1',context:scope.id,target:target.id,sourceSha:target.binarySha256,
    origin:checkout.origin,repository:checkout.repository,path:checkout.path,runtimeFingerprint:checkout.runtimeFingerprint};
  await mkdir(join(checkout.root,'operations'),{recursive:true});await writeFile(join(checkout.root,'native-owner.json'),JSON.stringify(owner));
  const bytes=join(checkout.root,'saved-bytes.bin');await writeFile(bytes,'synthetic saved local program bytes');
  const receipt=async(value:unknown)=>{const path=join(root,randomUUID()+'.json');await writeFile(path,JSON.stringify(value));return workspace.captureNative(path);};
  const saved={fileId:checkout.fileId,version:1,fingerprint:'b'.repeat(64),language:'x86:LE:64:default',compiler:'default',imageBase:'1000'};
  const sharedValue={state:'verified',version:1,fileId:checkout.fileId,fingerprint:'a'.repeat(64)};
  const sharedReceipt=async(version:number,fingerprint:string)=>receipt({schema:1,engine:'native-checkout-v1',source:'server',target:target.id,
    origin:checkout.origin,repository:checkout.repository,path:checkout.path,sourceSha:target.binarySha256,runtimeFingerprint:checkout.runtimeFingerprint,
    version,fileId:checkout.fileId,fingerprint});
  const shared=await sharedReceipt(1,sharedValue.fingerprint);workspace.establishModel(target.id,1,shared);
  const localReceipt=(fingerprint=saved.fingerprint,debuggerMetadata?:string)=>receipt({schema:1,engine:'native-checkout-v1',source:'checkout',checkout,
    ...saved,fingerprint,...(debuggerMetadata===undefined?{}:{debuggerMetadata})});
  const local=await localReceipt();
  workspace.saveContext(scope,workspace.context(scope).generation,{state:'stopped',nativeCheckout:checkout,baseRevision:1,baseSnapshot:shared,workingSnapshot:local,complexChanges:['private-edit']});
  const deleted:string[]=[],calls:Record<string,unknown>[]=[],binding={origin:checkout.origin,repository:checkout.repository};
  const c={appArguments:{AppDataDirectory:root},profile:{name:'default',values:{}},signal:new AbortController().signal,environment:{},
    secrets:{delete:async(name:string)=>{deleted.push(name);},require:async()=> 'synthetic-private-token'}} as unknown as CommandContext;
  const state={status:{state:'ready',checkedOut:true,recoverable:false,checkinActive:false,fileId:checkout.fileId,checkoutId:3,baseVersion:1,modified:true,saved,
      projectFiles:[target.id+'.bin'],checkouts:[{id:3,version:1}],versions:[{version:1,comment:'insight target '+target.id},{version:2,comment:'another writer'}]} as Record<string,unknown>,
    history:{repository:checkout.repository,path:checkout.path,version:2,checkinActive:false,checkouts:[3],versions:[{version:1,comment:'insight target '+target.id},{version:2,comment:'another writer'}]} as Record<string,unknown>,
    verify:{state:'unknown'} as Record<string,unknown>,shared:{...sharedValue,version:2,fingerprint:'c'.repeat(64)} as Record<string,unknown>};
  const server={ensure:async()=>binding,programStatus:async()=>{calls.push({operation:'history'});return state.history;},
    nativeCheckout:async(_b:unknown,q:Record<string,unknown>)=>{calls.push(q);if(q.operation!=='status')throw Error('Forbidden native mutation in recovery fixture');return state.status;},
    nativeRead:async(_b:unknown,q:Record<string,unknown>)=>{calls.push(q);return q.operation==='verify'?state.verify:state.shared;}} as unknown as GhidraServer;
  const backend=()=>new GhidraContexts(workspace,{fingerprint:checkout.runtimeFingerprint} as NativeInputs,c,new Map(),new Map(),server);
  const processBinding=(pid:number,processRoot=checkout.root)=>({pid,endpoint:'http://127.0.0.1:19091',root:processRoot,target:scope.target,context:scope.id,session:scope.session,
    mode:'headless',program:checkout.path,tokenSecret:'context-'+randomUUID(),runtimeFingerprint:checkout.runtimeFingerprint,kind:'context'});
  return {root,get workspace(){return workspace;},restart:()=>{workspace.close();workspace=new Workspace(join(root,'workspace'),'default');},
    scope,target,checkout,owner,saved,shared,local,bytes,receipt,localReceipt,sharedReceipt,deleted,calls,state,server,backend,processBinding};
}
