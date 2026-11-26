import {lstat,mkdir,open,readdir,readFile,realpath,rename,rm,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {Workspace,type GhidraContext} from './workspace.js';
import type {Artifact} from './artifacts.js';
import {stable} from './model.js';
import {peerStages} from './cross-peer.js';
import {sameDirectory} from './directory-identity.js';

/** Deletes only bytes reproducible from retained state. Anything unproved is reported and kept. */
export interface CollectionPort {
  closed(context:GhidraContext):Promise<boolean>;
  /** Verify natively that a stopped checkout has no work, then release and drop its project. */
  release(context:GhidraContext):Promise<boolean>;
}
export interface Category {items:number;bytes:number}
const missing=(error:unknown)=>(error as NodeJS.ErrnoException).code==='ENOENT';
const uuid='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
const artifactName=/^([a-f0-9]{64})\.(gzf|json)$/,pendingName=new RegExp('^pending-'+uuid+'$');
const exportName=new RegExp('^(?:saved-'+uuid+'|shared|recovered)\\.gzf$');

async function linked(path:string){try{return (await lstat(path)).isSymbolicLink();}catch(error){if(missing(error))return false;throw error;}}
async function directories(path:string):Promise<string[]>{
  if(await linked(path))return [];
  try{return (await readdir(path,{withFileTypes:true})).filter(e=>e.isDirectory()).map(e=>e.name);}
  catch(error){if(missing(error))return [];throw error;}
}
async function files(path:string):Promise<string[]>{
  if(await linked(path))return [];
  try{return (await readdir(path,{withFileTypes:true})).filter(e=>e.isFile()).map(e=>e.name);}
  catch(error){if(missing(error))return [];throw error;}
}
async function present(path:string){try{return await lstat(path);}catch(error){if(missing(error))return;throw error;}}
async function json(path:string):Promise<Record<string,unknown>|undefined>{
  try{const value=JSON.parse(await readFile(path,'utf8'));return value&&typeof value==='object'&&!Array.isArray(value)?value:undefined;}
  catch(error){if(missing(error)||error instanceof SyntaxError)return;throw error;}
}
function alive(pid:number){try{process.kill(pid,0);return true;}catch(error){return (error as NodeJS.ErrnoException).code!=='ESRCH';}}
async function older(path:string,ms:number){const st=await present(path);return st!==undefined&&Date.now()-st.mtimeMs>ms;}
/** A hard link frees its bytes only when every name of that file is removed. */
class Reclaimed {
  private readonly seen=new Map<string,{links:number;names:number;size:number;category:string}>();
  async add(path:string,category:string):Promise<void>{
    const st=await lstat(path,{bigint:true});
    if(st.isDirectory()){for(const name of await readdir(path))await this.add(join(path,name),category);return;}
    if(!st.isFile())return;
    const key=st.dev+':'+st.ino,row=this.seen.get(key);
    // A real run removes names as it goes, so keep the first observed link count.
    if(row)row.names++;else this.seen.set(key,{links:Number(st.nlink),names:1,size:Number(st.size),category});
  }
  include(other:Reclaimed){
    for(const [key,value] of other.seen){const row=this.seen.get(key);if(row)row.names+=value.names;else this.seen.set(key,value);}
  }
  bytes(){const out:Record<string,number>={};for(const f of this.seen.values())if(f.names>=f.links)out[f.category]=(out[f.category]??0)+f.size;return out;}
}
async function stopReceipt(root:string,worker:Record<string,unknown>){
  const stop=await json(join(root,'stopped.json'));
  return stop&&stop.pid===worker.pid&&stop.tokenSecret===worker.tokenSecret?stop:undefined;
}
async function stopped(root:string,worker:Record<string,unknown>):Promise<boolean>{
  if(!Number.isSafeInteger(worker.pid)||Number(worker.pid)<1)return false;
  return Boolean(await stopReceipt(root,worker))||!alive(Number(worker.pid));
}
/** A detached private project is redundant only while it holds just its one imported program. */
async function soleProgram(root:string):Promise<boolean>{
  let count=0;
  async function walk(path:string):Promise<void>{
    let entries;try{entries=await readdir(path,{withFileTypes:true});}catch(error){if(missing(error))return;throw error;}
    for(const e of entries){if(e.isDirectory())await walk(join(path,e.name));else if(e.name.endsWith('.prp')&&e.name!=='project.prp')count++;}
  }
  for(const tree of ['idata','versioned','user'])await walk(join(root,'view.rep',tree));
  return count<=1;
}
/** A native receipt describes bytes elsewhere; only a verified full packed program proves detached capture. */
async function detachedCapture(workspace:Workspace,root:string,candidates:Artifact[]):Promise<boolean>{
  try{
    const path=join(root,'saved.gzf'),st=await present(path);
    if(!st?.isFile()||st.isSymbolicLink())return false;
    const possible=candidates.filter(a=>a.kind==='snapshot'&&a.size===st.size);if(!possible.length)return false;
    const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);
    const sha=hash.digest('hex');
    for(const artifact of possible)if(artifact.sha256===sha)try{await workspace.artifacts.verify(artifact);return true;}catch{/* Try another retained full copy. */}
  }catch{/* Unreadable or changing capture bytes never authorize project removal. */}
  return false;
}
async function durable(path:string,value:unknown){
  const temporary=path+'.new-'+randomUUID(),file=await open(temporary,'wx',0o600);
  try{await file.writeFile(stable(value));await file.sync();}finally{await file.close();}
  await rename(temporary,path);
}
export async function collectStorage(workspace:Workspace,port:CollectionPort,dryRun:boolean,progress:(message:string)=>void=()=>{}){
  const native=join(workspace.directory,'ghidra-native'),retained:{path:string;reason:string}[]=[];
  const reclaimed=new Reclaimed(),categories:Record<string,Category>={};
  const id=randomUUID(),receipt=join(workspace.directory,'gc',id+'.json'),startedAt=new Date().toISOString();
  if(!dryRun){await mkdir(join(workspace.directory,'gc'),{recursive:true,mode:0o700});await durable(receipt,{schema:1,id,state:'started',startedAt});}
  const keep=(path:string,reason:string)=>{retained.push({path,reason});};
  async function remove(path:string,category:string):Promise<boolean>{
    const st=await present(path);if(!st)return true;
    if(st.isSymbolicLink()||!st.isFile()&&!st.isDirectory()){keep(path,'Links and special entries are never removed.');return false;}
    const sizes=new Reclaimed();await sizes.add(path,category);
    if(!dryRun)try{if(st.isDirectory())await rm(path,{recursive:true,maxRetries:3});else await unlink(path);}
      catch(error){keep(path,'Removal failed: '+String((error as NodeJS.ErrnoException).code));return false;}
    reclaimed.include(sizes);
    (categories[category]??={items:0,bytes:0}).items++;
    return true;
  }

  // A context participates only when nothing about its private state is uncertain.
  const contexts=workspace.allContexts(),safe=new Set<string>(),blockedTargets=new Set<string>(),unsettled=new Set<string>();
  const nativeRoots=new Set(contexts.flatMap(c=>c.nativeCheckout?[c.nativeCheckout.root]:[])),artifacts=workspace.allArtifacts(),nativeEvidence=new Set<string>(),nativeProjects=new Map<string,string>();
  let unverifiedNativeReceipt=false;
  for(const artifact of artifacts)if(artifact.kind==='native')try{
    const view=await json(await workspace.artifacts.verify(artifact));
    if(!view){unverifiedNativeReceipt=true;nativeEvidence.add(artifact.id);}
    else if(view.source==='checkout'){
      const checkout=view.checkout as {root?:unknown}|undefined;
      if(typeof checkout?.root==='string'){
        nativeRoots.add(checkout.root);nativeProjects.set(artifact.id,checkout.root);
      }else{unverifiedNativeReceipt=true;nativeEvidence.add(artifact.id);}
    }
  }catch{unverifiedNativeReceipt=true;nativeEvidence.add(artifact.id);}
  for(const context of contexts){
    const active=workspace.activePublication(context.target);let reason:string|undefined;
    if(active)blockedTargets.add(context.target);
    if(['opening','needs_recovery'].includes(context.state))reason='Context is still opening or requires recovery.';
    else if(workspace.unresolved(context).length||workspace.uncertainOutcome(context))reason='Context has an unresolved or uncertain operation.';
    else if(active?.session===context.session)reason='Context has an unresolved publication.';
    else if(context.debugger?.traces.length||context.debugger?.connected)reason='Context retains debugger state.';
    else{
      try{if(!await port.closed(context))reason='Context worker is not proved stopped.';}
      catch{reason='Context worker receipt could not be verified.';}
      if(!reason&&context.workingSnapshot)
        try{await workspace.artifacts.verify(context.workingSnapshot);}catch{reason='Saved private view could not be verified.';}
    }
    if(reason){keep(join(native,'context',context.id),reason);unsettled.add(context.target);}else safe.add(context.id);
  }

  // Ghidra releases clean checkouts itself; their projects are never deleted behind its back.
  for(const context of contexts){
    const checkout=context.nativeCheckout,category='native-checkouts';
    if(!checkout||checkout.state==='dropped'||!safe.has(context.id)||checkout.conflict||context.scalars.length||context.complexChanges.length)continue;
    if(checkout.state==='active'&&!await present(checkout.root)){keep(checkout.root,'Native checkout project is missing; its server checkout is retained.');continue;}
    try{
      const owner=join(checkout.root,'native-owner.json');
      if(await linked(owner)||!await json(owner)){keep(checkout.root,'Native ownership receipt is missing or unverifiable; its checkout is retained.');continue;}
    }catch{keep(checkout.root,'Native ownership receipt could not be verified; its checkout is retained.');continue;}
    if(workspace.checkoutReferenced(context)){keep(checkout.root,'An unresolved operation in another context references this checkout.');continue;}
    const project=join(checkout.root,'view.rep');
    if(dryRun){
      if(workspace.unchangedNative(context))await remove(project,category);
      else keep(checkout.root,'Saved receipt differs from its shared base and from every recorded pristine open of that version; the checkout may hold private work.');
      continue;
    }
    const sizes=new Reclaimed();if(await present(project))await sizes.add(project,category);
    try{
      progress('Verifying native checkout '+context.session+' / '+context.target);
      if(await port.release(context)){const row=categories[category]??={items:0,bytes:0};row.items++;row.bytes+=sizes.bytes()[category]??0;}
      else keep(checkout.root,'Native checkout is not proved unchanged.');
    }catch(error){keep(checkout.root,'Native release was refused: '+String((error as Error).message).slice(0,300));}
  }

  const known=new Set(contexts.map(c=>c.id)),captured=new Map<string,Artifact[]>(),targetCaptures=new Map<string,Artifact[]>(),discarded=new Set<string>(),disposedDetachedRoots=new Set<string>();
  for(const context of contexts){
    const snapshots:Artifact[]=[];
    if(context.workingSnapshot?.kind==='snapshot')snapshots.push(context.workingSnapshot);
    try{
      const migration=await json(join(workspace.directory,'legacy-migrations',context.target,context.id+'-detached.json'));
      const original=migration?.original as GhidraContext|undefined;
      if(migration?.schema===1&&original?.id===context.id&&original.target===context.target&&!original.nativeCheckout&&original.workingSnapshot?.kind==='snapshot')snapshots.push(original.workingSnapshot);
    }catch{/* A damaged migration receipt does not prove a detached capture. */}
    captured.set(context.id,snapshots);targetCaptures.set(context.target,[...(targetCaptures.get(context.target)??[]),...snapshots]);
  }
  // Only detached roots are reached by the project rule, and a discarded context holds no others.
  for(const context of contexts)if(workspace.legacyDiscarded(context))discarded.add(context.id);
  for(const kind of ['context','shared','candidate'] as const){
    const parent=join(native,kind);
    for(const owner of await directories(parent)){
      if(kind==='context'&&!safe.has(owner)){if(!known.has(owner))keep(join(parent,owner),'Directory has no matching context.');continue;}
      if(kind!=='context'&&blockedTargets.has(owner)){keep(join(parent,owner),'Target has an unresolved publication.');continue;}
      // A merge or refresh interrupted before its publication row still owns candidate evidence.
      if(kind==='candidate'&&unsettled.has(owner)){keep(join(parent,owner),'Target has an unsettled context.');continue;}
      for(const name of await directories(join(parent,owner))){
        const root=join(parent,owner,name);
        if(await realpath(root)!==join(await realpath(parent),owner,name)){keep(root,'Working root moved outside owned storage.');continue;}
        let worker:Record<string,unknown>|undefined,nativeRoot=false,projectOwnershipReason:string|undefined;
        try{
          const ownerPresent=Boolean(await present(join(root,'native-owner.json')));
          const creationPath=join(parent,owner,'checkout.json');
          if(kind==='context'&&await linked(creationPath)){keep(root,'Native creation receipt is linked; project ownership is unproved.');continue;}
          const creation=kind==='context'?await json(creationPath):undefined;
          const creationPresent=kind==='context'&&Boolean(await present(creationPath));
          const creationRoot=creation?.root;
          let locatorUnverified=false;
          const locators=[...nativeRoots,...(typeof creationRoot==='string'?[creationRoot]:[])];
          const recordedNative=!ownerPresent&&locators.some(named=>{
            if(named===root)return true;
            try{return sameDirectory(named,root);}catch(error){if(!missing(error))locatorUnverified=true;return false;}
          });
          if(!ownerPresent&&(recordedNative||locatorUnverified||(creationPresent&&typeof creationRoot!=='string')||unverifiedNativeReceipt)){
            projectOwnershipReason='Native checkout or creation ownership is missing or unverifiable; detached cleanup is not authorized.';
          }
          worker=await json(join(root,'process.json'));nativeRoot=ownerPresent;
          if(!worker&&!nativeRoot){keep(root,'Working root has no worker receipt.');continue;}
          if(worker&&(worker.kind!==kind||(kind==='context'?worker.context:worker.target)!==owner)){keep(root,'Worker receipt belongs to a different owner.');continue;}
          if(worker&&!await stopped(root,worker)){keep(root,'Worker is not proved stopped.');continue;}
        }catch(error){keep(root,'Working root worker proof could not be verified: '+String((error as NodeJS.ErrnoException).code??'unavailable'));continue;}
        for(const name of ['ghidra','exports','explicit-exports'])if(await linked(join(root,name)))keep(join(root,name),'Links and special entries are never removed.');
        if(kind==='context'){
          const context=workspace.contextById(owner),stages=await peerStages(root,{context:owner,target:context.target});let ownershipReason:string|undefined;
          if(stages.length)try{
            const linkedOwner=await linked(join(root,'process.json'))||await linked(join(root,'native-owner.json'));
            const nativeOwner=nativeRoot&&!linkedOwner&&(await lstat(join(root,'native-owner.json'))).isFile()?await json(join(root,'native-owner.json')):undefined;
            if(!worker)ownershipReason='Cross-target working root has no worker receipt that proves it stopped.';
            else if(linkedOwner)ownershipReason='Cross-target working root ownership receipt is a link.';
            else if(worker&&worker.target!==context.target||nativeRoot&&(!nativeOwner||nativeOwner.context!==owner||nativeOwner.target!==context.target))ownershipReason='Cross-target working root receipt belongs to a different owner.';
            else if(typeof worker.root!=='string'||!sameDirectory(worker.root,root))ownershipReason='Cross-target worker receipt does not identify this working root.';
          }catch(error){ownershipReason='Cross-target working root ownership receipt could not be verified: '+String((error as NodeJS.ErrnoException).code??'unavailable');}
          for(const stage of stages){
            if(ownershipReason)keep(stage.folder,ownershipReason);
            else if('reason' in stage)keep(stage.folder,stage.reason);
            else if(stage.receipt.state!=='closed')keep(stage.folder,'Cross-target cleanup is incomplete; its temporary program removal is unverified.');
            else if(workspace.checkoutReferenced(context,root))keep(stage.folder,'An unresolved operation in another context references this checkout.');
            else if(stage.input)await remove(stage.input,'duplicate-exports');
          }
        }
        // Closed peer exports have their own complete ownership proof, independent of project disposal.
        if(projectOwnershipReason){keep(root,projectOwnershipReason);continue;}
        const given=kind==='context'&&discarded.has(owner);
        const candidates=kind==='context'?captured.get(owner)??[]:[...(targetCaptures.get(owner)??[])];
        if(kind!=='context')try{const shared=workspace.model(owner).sharedSnapshot;if(shared?.kind==='snapshot')candidates.push(shared);}catch{/* Unknown model roots cannot supply capture proof. */}
        if(!nativeRoot&&((worker?.program!=='program'&&worker?.program!=='/program')||typeof worker.root!=='string'||!sameDirectory(worker.root,root)||!given&&!await detachedCapture(workspace,root,candidates))){
          keep(root,'Project has no verified full detached program capture; native JSON receipts do not contain program bytes.');continue;
        }
        let cleanupComplete=true;
        for(const file of await files(join(root,'ghidra')))if(file.endsWith('.cache'))cleanupComplete=await remove(join(root,'ghidra',file),'temporary-caches')&&cleanupComplete;
        if(nativeRoot){
          // The project itself belongs to its checkout lifecycle, including uncertain creations.
          for(const run of await directories(join(root,'explicit-exports')))await remove(join(root,'explicit-exports',run,'program.gzf'),'duplicate-exports');
          continue;
        }
        for(const file of await files(join(root,'exports')))if(exportName.test(file))cleanupComplete=await remove(join(root,'exports',file),'duplicate-exports')&&cleanupComplete;
        // Facade edits are captured as they complete; a GUI save is captured only by an explicit close.
        const stop=worker&&await stopReceipt(root,worker);
        if(!given&&(!stop||worker?.mode!=='headless'&&stop.reason!=='explicit_close')){keep(join(root,'view.rep'),'Project has no clean stop receipt that proves capture.');continue;}
        if(!await soleProgram(root)){keep(join(root,'view.rep'),'Project holds additional files.');continue;}
        const projectFiles=['view.rep','view.gpr','view.lock','view.lock~'];
        for(const file of projectFiles)cleanupComplete=await remove(join(root,file),'detached-projects')&&cleanupComplete;
        // Every recognized removal must succeed before its full capture proof can be forgotten.
        if(cleanupComplete&&await remove(join(root,'saved.gzf'),'duplicate-exports'))disposedDetachedRoots.add(root);
      }
    }
  }
  for(const run of await directories(join(native,'explicit-exports')))await remove(join(native,'explicit-exports',run,'program.gzf'),'duplicate-exports');
  const calls=join(workspace.directory,'server','calls');
  for(const call of await directories(calls))for(const file of await files(join(calls,call,'ghidra')))
    if(file.endsWith('.cache'))await remove(join(calls,call,'ghidra',file),'temporary-caches');

  // Roots are live rows, unfinished or failed intents, every user-visible result and VT owners.
  const roots=workspace.artifactRoots();for(const id of nativeEvidence)roots.add(id);
  // Native release above can remove a project and its live context reference in this same pass.
  for(const [id,root] of nativeProjects)try{
    if(await present(join(root,'view.rep'))||await present(join(root,'view.gpr')))roots.add(id);
  }catch{
    roots.add(id);keep(root,'Native project inventory could not be verified; its receipt is retained.');
  }
  // Migration journals keep identity, not artifact liveness. A retained saved.gzf still needs its
  // canonical verification copy for the next collection attempt, even after the context migrated.
  for(const kind of ['context','shared','candidate'] as const)for(const owner of await directories(join(native,kind))){
    const proofs=kind==='context'?(discarded.has(owner)?[]:captured.get(owner)??[]):targetCaptures.get(owner)??[];
    if(!proofs.length)continue;
    for(const name of await directories(join(native,kind,owner))){
      const root=join(native,kind,owner,name);if(disposedDetachedRoots.has(root))continue;
      try{if(!await present(join(root,'saved.gzf')))continue;}
      catch{keep(root,'Retained capture metadata could not be verified; its snapshot proof is preserved.');}
      for(const artifact of proofs)roots.add(artifact.id);
    }
  }
  for(const tracking of await directories(join(workspace.directory,'version-tracking'))){
    let owner='';try{owner=await readFile(join(workspace.directory,'version-tracking',tracking,'owner.json'),'utf8');}catch(error){if(!missing(error))throw error;}
    for(const match of owner.matchAll(/(?:snapshot|native):[a-f0-9]{64}/g))roots.add(match[0]);
  }
  const rows=new Set(workspace.allArtifacts().map(a=>a.id));
  if(!dryRun)for(const artifact of workspace.allArtifacts())if(artifact.kind!=='input'&&!roots.has(artifact.id))workspace.forgetArtifact(artifact.id);
  const directory=join(workspace.directory,'artifacts');
  for(const file of await files(directory)){
    const match=artifactName.exec(file);
    const id=match&&(match[2]==='gzf'?'snapshot:':'native:')+match[1];
    // A capture writes its file before its row, so unrowed files are stale only after a day.
    if(id?!roots.has(id)&&(rows.has(id)||await older(join(directory,file),86400000)):pendingName.test(file)&&await older(join(directory,file),86400000))await remove(join(directory,file),'unreferenced-snapshots');
  }
  for(const [category,bytes] of Object.entries(reclaimed.bytes()))if(categories[category])categories[category].bytes+=bytes;
  const result={state:dryRun?'planned':'complete',dryRun,bytes:Object.values(categories).reduce((n,c)=>n+c.bytes,0),categories,retainedCount:retained.length};
  if(!dryRun)await durable(receipt,{schema:1,id,startedAt,endedAt:new Date().toISOString(),...result,retained});
  return {...result,...(dryRun?{}:{id}),retained:retained.slice(0,200)};
}
