import {mkdir,realpath,readFile,open,link,unlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {stable,object,fail} from './model.js';
import type {Workspace,ResearchTarget} from './workspace.js';
import type {GhidraServer,ServerBinding} from './server.js';

export const initialRoot=(workspace:Workspace,target:string)=>join(workspace.directory,'ghidra-native','initial',target);
export async function initialIntent(workspace:Workspace,target:string){
  try{return object(JSON.parse(await readFile(join(initialRoot(workspace,target),'intent.json'),'utf8')));}
  catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
}
/** Immutable input/authority binding; private attempts and conditional first creation share it. */
export async function initializeModel(workspace:Workspace,target:ResearchTarget,binding:ServerBinding,server:Pick<GhidraServer,'initialImport'|'initialPublication'>,fingerprint:string){
  const root=initialRoot(workspace,target.id);await mkdir(root,{recursive:true,mode:0o700});
  if(await realpath(root)!==resolve(root))fail('binding','Initial model storage moved outside its owned root.');
  const expected={schema:1,target:target.id,sha256:target.binarySha256,input:await workspace.artifacts.verify(target.input),
    origin:binding.origin,repository:binding.repository,readerUser:binding.readerUser,publisherUser:binding.publisherUser,
    settings:workspace.model(target.id).settings,runtimeFingerprint:fingerprint};
  let intent=await initialIntent(workspace,target.id);
  if(!intent){
    const temporary=join(root,'intent.new-'+randomUUID()),handle=await open(temporary,'wx',0o600);
    try{await handle.writeFile(stable({...expected,id:randomUUID()}));await handle.sync();}finally{await handle.close();}
    try{await link(temporary,join(root,'intent.json'));}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
    finally{await unlink(temporary);}
    if(process.platform!=='win32'){const directory=await open(root,'r');try{await directory.sync();}finally{await directory.close();}}
    intent=await initialIntent(workspace,target.id);
  }
  if(!intent||typeof intent.id!=='string'||!/^[a-f0-9-]{36}$/.test(intent.id)||
    Object.entries(expected).some(([key,value])=>stable(intent![key])!==stable(value)))fail('binding','Retained initial model differs from its input, load settings, runtime or repository authority.');
  if(workspace.model(target.id).state==='opening')workspace.beginModelInitialization(target.id);
  const prepared=await server.initialImport(root);
  if(prepared.state==='busy')fail('busy','The original initial-import worker is still active; retain the context and continue after it completes.');
  if(prepared.state!=='prepared')fail('unknown','Initial import did not establish a complete private snapshot.');
  const receipt=object(JSON.parse(await readFile(join(root,'import.json'),'utf8'))),name=receipt.snapshot;
  if(typeof name!=='string'||!/^attempt-[a-f0-9-]{36}\.gzf$/.test(name))fail('binding','Initial model snapshot receipt is malformed.');
  const snapshot=await workspace.captureSnapshot(join(root,name));
  if(snapshot.sha256!==receipt.snapshotSha256)fail('binding','Initial saved snapshot changed before publication.');
  let result=await server.initialPublication(binding,root,'stage');
  if(result.state==='staged'){
    const proof=await server.initialPublication(binding,root,'verify-stage');
    if(proof.state!=='stage_verified'||proof.version!==1||proof.snapshotBuffersVerified!==true)fail('unknown','Independent initial staging readback did not establish the complete snapshot.');
    result=await server.initialPublication(binding,root,'promote');
  }
  if(result.state!=='published'||result.version!==1||result.snapshotBuffersVerified!==true)fail('unknown','Initial publication requires reconciliation against its saved snapshot.');
  const verified=await server.initialPublication(binding,root,'verify');
  if(verified.state!=='verified'||verified.version!==1||verified.snapshotBuffersVerified!==true)fail('unknown','Independent initial-model readback did not establish the complete saved buffers.');
  workspace.establishModel(target.id,1,snapshot);
}
