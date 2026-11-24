import {access,lstat,mkdir,open,readdir,readFile,realpath,rename,rm,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {Workspace,type GhidraContext} from './workspace.js';
import {stable} from './model.js';

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
  async function remove(path:string,category:string):Promise<void>{
    const st=await present(path);if(!st)return;
    if(st.isSymbolicLink()||!st.isFile()&&!st.isDirectory())return keep(path,'Links and special entries are never removed.');
    await reclaimed.add(path,category);
    if(!dryRun)try{if(st.isDirectory())await rm(path,{recursive:true,maxRetries:3});else await unlink(path);}
      catch(error){return keep(path,'Removal failed: '+String((error as NodeJS.ErrnoException).code));}
    (categories[category]??={items:0,bytes:0}).items++;
  }

  // A context participates only when nothing about its private state is uncertain.
  const contexts=workspace.allContexts(),safe=new Set<string>(),blockedTargets=new Set<string>(),unsettled=new Set<string>();
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
    if(workspace.checkoutReferenced(context)){keep(checkout.root,'An unresolved operation in another context references this checkout.');continue;}
    const project=join(checkout.root,'view.rep');
    if(dryRun){if(workspace.unchangedNative(context))await remove(project,category);continue;}
    const sizes=new Reclaimed();if(await present(project))await sizes.add(project,category);
    try{
      progress('Verifying native checkout '+context.session+' / '+context.target);
      if(await port.release(context)){const row=categories[category]??={items:0,bytes:0};row.items++;row.bytes+=sizes.bytes()[category]??0;}
      else keep(checkout.root,'Native checkout is not proved unchanged.');
    }catch(error){keep(checkout.root,'Native release was refused: '+String((error as Error).message).slice(0,300));}
  }

  const known=new Set(contexts.map(c=>c.id)),captured=new Set<string>();
  for(const context of contexts)if(context.workingSnapshot)captured.add(context.id);
    else try{await access(join(workspace.directory,'legacy-migrations',context.target,context.id+'-detached.json'));captured.add(context.id);}catch(error){if(!missing(error))throw error;}
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
        const worker=await json(join(root,'process.json')),nativeRoot=Boolean(await present(join(root,'native-owner.json')));
        if(!worker&&!nativeRoot){keep(root,'Working root has no worker receipt.');continue;}
        if(worker&&(worker.kind!==kind||(kind==='context'?worker.context:worker.target)!==owner)){keep(root,'Worker receipt belongs to a different owner.');continue;}
        if(worker&&!await stopped(root,worker)){keep(root,'Worker is not proved stopped.');continue;}
        for(const file of await files(join(root,'ghidra')))if(file.endsWith('.cache'))await remove(join(root,'ghidra',file),'temporary-caches');
        if(nativeRoot){
          // The project itself belongs to its checkout lifecycle, including uncertain creations.
          for(const run of await directories(join(root,'explicit-exports')))await remove(join(root,'explicit-exports',run,'program.gzf'),'duplicate-exports');
          continue;
        }
        for(const file of await files(join(root,'exports')))if(exportName.test(file))await remove(join(root,'exports',file),'duplicate-exports');
        await remove(join(root,'saved.gzf'),'duplicate-exports');
        // Facade edits are captured as they complete; a GUI save is captured only by an explicit close.
        const stop=worker&&await stopReceipt(root,worker);
        if(!stop||worker.mode!=='headless'&&stop.reason!=='explicit_close'){keep(join(root,'view.rep'),'Project has no clean stop receipt that proves capture.');continue;}
        if(kind==='context'&&!captured.has(owner)){keep(join(root,'view.rep'),'Project has no verified saved or migrated view.');continue;}
        if(!await soleProgram(root)){keep(join(root,'view.rep'),'Project holds additional files.');continue;}
        for(const file of ['view.rep','view.gpr','view.lock','view.lock~'])await remove(join(root,file),'detached-projects');
      }
    }
  }
  for(const run of await directories(join(native,'explicit-exports')))await remove(join(native,'explicit-exports',run,'program.gzf'),'duplicate-exports');
  const calls=join(workspace.directory,'server','calls');
  for(const call of await directories(calls))for(const file of await files(join(calls,call,'ghidra')))
    if(file.endsWith('.cache'))await remove(join(calls,call,'ghidra',file),'temporary-caches');

  // Roots are live rows, unfinished or failed intents, every user-visible result and VT owners.
  const roots=workspace.artifactRoots();
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
