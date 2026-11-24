import {mkdir,readFile,open,rename} from 'node:fs/promises';
import {join} from 'node:path';import {randomUUID} from 'node:crypto';
import {Workspace,type GhidraContext,type ResearchTarget} from './workspace.js';
import {listProcesses} from './tool-runtime/supervisor.js';
import {fail,object,stable} from './model.js';
function pidAlive(pid:number){try{process.kill(pid,0);return true;}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH')return false;throw error;}}
export async function migrationProcessBlockers(directory:string){
  const blockers=[];
  for(const p of await listProcesses(directory,{tool:'ghidra'})){
    if(p.role==='server'||['exited','failed'].includes(p.state))continue;
    // Storage migration preserves historical supervisor receipts. A moved receipt
    // grants no process authority; only acknowledged direct completion plus absent
    // child AND owner PIDs establishes quiescence here, without rewriting it.
    if(p.phase==='profile_binding_changed'&&p.endedAt&&p.outcome==='completed'&&p.exitCode===0&&p.signal===null&&!p.metadata&&!('nativeChildren' in p)&&Number.isSafeInteger(p.pid)&&Number(p.pid)>0&&Number.isSafeInteger(p.ownerPid)&&p.ownerPid>0){
      const saved=object(JSON.parse(await readFile(join(directory,'runtime/processes',p.id+'.json'),'utf8')));
      if(saved.state==='exited'&&saved.phase==='direct_child_only'&&saved.pid===p.pid&&saved.ownerPid===p.ownerPid&&saved.endedAt===p.endedAt&&!pidAlive(Number(p.pid))&&!pidAlive(p.ownerPid))continue;
    }
    blockers.push(p);
  }
  return blockers;
}
export interface MigrationPort {
  binding():Promise<{origin:string;repository:string;runtimeFingerprint:string}>;
  probe(target:ResearchTarget,version?:number):Promise<Record<string,unknown>>;
  write(request:Record<string,unknown>):Promise<Record<string,unknown>>;
  verify(target:ResearchTarget,owner:Record<string,unknown>,candidate:Record<string,unknown>):Promise<void>;
  adopt(target:string):Promise<void>;
  closed(context:GhidraContext):Promise<boolean>;
  convert(context:GhidraContext):Promise<void>;
  knownCheckouts?(target:ResearchTarget,checkouts:unknown[]):Promise<boolean>;
  recoverOpen?(context:GhidraContext):Promise<void>;
}
export async function migrationDurable(path:string,value:unknown){
  const temp=path+'.new-'+randomUUID(),file=await open(temp,'wx',0o600);
  try{await file.writeFile(stable(value));await file.sync();}finally{await file.close();}
  await rename(temp,path);
}
async function read(path:string){try{return object(JSON.parse(await readFile(path,'utf8')))}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return;throw e}}
function identity(target:ResearchTarget,model:ReturnType<Workspace['model']>,value:Record<string,unknown>){
  if(value.state!=='verified'||typeof value.fileId!=='string'||typeof value.fingerprint!=='string'||typeof value.programIdentity!=='string'||!Number.isSafeInteger(value.version)||!Array.isArray(value.checkouts))fail('binding','Migration readback is incomplete.');
  if(model.settings.language&&model.settings.language!==value.language||model.settings.compilerSpec&&model.settings.compilerSpec!==value.compiler||model.settings.imageBase&&model.settings.imageBase.replace(/^0x/,'').replace(/^0+(?=.)/,'')!==String(value.imageBase).replace(/^0x/,'').replace(/^0+(?=.)/,''))fail('binding','Migration load identity does not match the bound target settings.',{target:target.id});
  if(value.engine!==''&&value.engine!=='native-checkout-v1')fail('migration','Unrecognized publication engine; the program is retained.');
}
/** Resume is the same explicit command. A native commit intent is reconciled, never replayed. */
export async function migrateLegacy(workspace:Workspace,port:MigrationPort,selected:string|undefined,dryRun:boolean){
  const targets:ResearchTarget[]=[];
  if(selected)targets.push(workspace.target(selected));else for(let offset=0;;offset+=100){const page=workspace.targets(100,offset);targets.push(...page);if(page.length<100)break;}
  const contexts:GhidraContext[]=[];
  for(let offset=0;;offset+=100){const sessions=workspace.sessions(100,offset);for(const session of sessions)for(let at=0;;at+=100){const page=workspace.contexts(session.id,100,at);contexts.push(...page.filter(c=>targets.some(t=>t.id===c.target)));if(page.length<100)break;}if(sessions.length<100)break;}
  for(const target of targets)if(workspace.activePublication(target.id))fail('blocked','Publication must be reconciled before migration.');
  for(const context of contexts)if(!await port.closed(context))fail('busy','Close the original context worker before migration.',{session:context.session,target:context.target});
  const binding=await port.binding(),items=[];
  for(const target of targets){
    let model:ReturnType<Workspace['model']>;
    try{model=workspace.model(target.id);}catch(error){if((error as {code?:string}).code!=='coordinator.notFound')throw error;items.push({target:target.id,state:'no_ghidra_model',contexts:[]});continue;}
    if(target.input.kind!=='input'||target.input.sha256!==target.binarySha256||target.input.size!==target.size)fail('binding','Migration input artifact and target source identity differ.');
    await workspace.artifacts.verify(target.input);
    const value=await port.probe(target);
    if(value.state==='absent'){items.push({target:target.id,state:'no_server_model',reason:'No canonical program exists in this profile repository; retained model/context data was not changed.',contexts:[]});continue;}
    identity(target,model,value);
    const root=join(workspace.directory,'legacy-migrations',target.id),journalPath=join(root,'migration.json');
    let journal=await read(journalPath),owner=journal?object(journal.owner):undefined;
    if(owner&&(owner.origin!==binding.origin||owner.repository!==binding.repository||owner.target!==target.id||owner.sourceSha!==target.binarySha256||owner.fileId!==value.fileId))fail('binding','Retained migration identity changed; all data remains retained.');
    const untouchedNative=value.engine==='native-checkout-v1'&&!journal;
    const detached=contexts.filter(c=>c.target===target.id&&!c.nativeCheckout&&c.workingSnapshot);
    const item:Record<string,unknown>={target:target.id,sourceSha:target.binarySha256,version:value.version,fileId:value.fileId,state:value.engine===''?'legacy':'native',contexts:[]};items.push(item);
    if(untouchedNative){item.state='native_unchanged';continue;}
    if(!dryRun&&(value.engine===''||journal&&journal.state!=='complete')){
      if(!journal){
        if((value.checkouts as unknown[]).length)fail('busy','Legacy model has existing checkouts; explicit reconciliation is required.');
        await mkdir(root,{recursive:true,mode:0o700});
        owner={schema:1,...binding,target:target.id,sourceSha:target.binarySha256,path:'/'+target.id+'.bin',fileId:value.fileId,version:value.version,fingerprint:value.fingerprint,programIdentity:value.programIdentity,marker:'insight migration '+randomUUID()};
        await migrationDurable(join(root,'migration-owner.json'),owner);journal={schema:1,state:'reserved',owner};await migrationDurable(journalPath,journal);
      }
      const bound=owner!;let native=await read(join(root,'native-migration.json'));
      if(!native||!['commit_intent','checked_in','released'].includes(String(native.phase))){
        if(value.engine!==''||value.version!==bound.version||value.fingerprint!==bound.fingerprint||value.programIdentity!==bound.programIdentity)fail('binding','Legacy baseline changed before migration.');
        await port.write({operation:'run',root,owner:bound});native=await read(join(root,'native-migration.json'));
      }
      if(!native||!['commit_intent','checked_in','released'].includes(String(native.phase))||typeof native.fingerprint!=='string')fail('unknown','Migration has no complete candidate/check-in evidence; retain its project and journal.');
      await port.verify(target,bound,native);
      await port.write({operation:'release',root,owner:bound,version:Number(bound.version)+1,fingerprint:native.fingerprint});
      journal={...journal,state:'complete',publishedVersion:Number(bound.version)+1,fingerprint:native.fingerprint};await migrationDurable(journalPath,journal);
      item.state='migrated';item.version=Number(bound.version)+1;
    }
    if(!dryRun)await port.adopt(target.id);
    // Packed programs lack native checkout ancestry/change sets. Exact equality can safely
    // establish an unchanged context. Replaying scalar diagnostics cannot prove arbitrary work.
    for(const original of detached){
      const snapshot=original.workingSnapshot!,retained=await workspace.artifacts.verify(snapshot);
      const record:Record<string,unknown>={session:original.session,target:target.id,snapshot,state:'retained',reason:'Packed detached work has no provable native checkout ancestry/change sets; native conversion is refused. No scalar or script replay was performed.'};
      const before=owner??(value.engine===''?value:undefined);
      const observed=await port.write({operation:'snapshot',snapshot:retained});
      if(observed.sourceSha!==target.binarySha256){record.reason='Detached snapshot source SHA256 differs from its target; snapshot and context retained.';}
      else if(before&&observed.fingerprint===before.fingerprint&&observed.programIdentity===before.programIdentity&&!original.scalars.length&&!original.complexChanges.length&&!original.debugger?.traces.length&&!workspace.unresolved(original).length){
        record.state=dryRun?'convertible_unchanged':'converted_unchanged';record.reason='Complete saved buffers equal the verified pre-migration version.';
        if(!dryRun){await migrationDurable(join(root,original.id+'-detached.json'),{schema:1,original,observed});await port.convert(original);}
      }else{record.observed=observed;record.baseRevision=original.baseRevision??null;}
      (item.contexts as unknown[]).push(record);
    }
    if(dryRun){
      for(const original of contexts.filter(c=>c.target===target.id&&!c.nativeCheckout&&!c.workingSnapshot&&!c.scalars.length&&!c.complexChanges.length&&!c.debugger?.traces.length)){
        const requests=workspace.unresolved(original);if(!requests.length)continue;
        (item.contexts as unknown[]).push({session:original.session,target:target.id,state:requests.every(q=>q.operation==='ghidra.open')&&!(value.checkouts as unknown[]).length?'would_recover_open':'retained',requests:requests.map(q=>({id:q.id,operation:q.operation})),reason:'Recovery requires a verified native model and proof that no private work or uncertain checkout exists.'});
      }
    }
    if(!dryRun){
      const current=await port.probe(target);
      if(current.engine!=='native-checkout-v1')fail('migration','Model is still legacy; no open request was recovered.');
      for(const original of contexts.filter(c=>c.target===target.id&&!c.nativeCheckout&&!c.workingSnapshot&&!c.scalars.length&&!c.complexChanges.length&&!c.debugger?.traces.length)){
        // Any server checkout could belong to an uncertain historical open; refuse recovery.
        if((current.checkouts as unknown[]).length&&!await port.knownCheckouts?.(target,current.checkouts as unknown[])){(item.contexts as unknown[]).push({session:original.session,state:'retained',reason:'Server checkouts prevent proving that the historical open did no work.'});continue;}
        if(workspace.unresolved(original).every(q=>q.operation==='ghidra.open')){
          if(workspace.unresolved(original).length)await port.recoverOpen?.(original);
          const recovered=workspace.recoverMigrationOpen(original);
          if(recovered)(item.contexts as unknown[]).push({session:original.session,state:'open_recovered',requests:recovered});
        }else (item.contexts as unknown[]).push({session:original.session,state:'retained',reason:'Unresolved operations other than ghidra.open are retained; migration cannot establish their effects.'});
      }
      await migrationDurable(join(root,'contexts.json'),{schema:1,target:target.id,contexts:item.contexts});
    }
  }
  return {state:dryRun?'planned':'complete',dryRun,items,retainedContexts:items.flatMap(x=>x.contexts as Record<string,unknown>[]).filter(x=>x.state==='retained').length};
}
