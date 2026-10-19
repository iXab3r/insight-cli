import {CliError,Permission,ProfileStore,privateDirectory,command,type CommandContext,type CommandDefinition,type ProfileStoreContract} from '@eyeauras/cli-factory';
import {constants,existsSync} from 'node:fs';
import {access,lstat,mkdir,open,readFile,readdir,readlink,realpath,rename,rm,statfs,symlink,unlink} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {basename,dirname,isAbsolute,join,relative,resolve,sep} from 'node:path';
import {atomicWrite,readJson,toolProfileBusy} from './tool-runtime/store.js';
import {listProcesses} from './tool-runtime/supervisor.js';
import {runtimeProcesses} from './runtime-manager.js';
import {digest} from './model.js';

// Move the complete runtime tree too: installation stages must share a filesystem with
// installations, and both native checks and process runs can contain large generated DBs.
// Stable aliases preserve references in immutable native journals, selections and results.
export const analysisTrees=['workspace','materials','temp','runtime'];
const terminal=(state:string)=>['committed','rolled_back','cleaned'].includes(state);
const inside=(parent:string,child:string)=>{const r=relative(parent,child);return r===''||!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+sep);};
function fail(code:string,message:string):never{throw new CliError(message,{code:'storage.'+code});}
const missing=(e:unknown)=>(e as NodeJS.ErrnoException).code==='ENOENT';
async function present(path:string){try{return await lstat(path);}catch(e){if(missing(e))return;throw e;}}
async function sync(path:string,directory=false){
  if(directory&&process.platform==='win32')return;
  // Windows FlushFileBuffers requires write access even when no bytes are changed.
  const f=await open(path,process.platform==='win32'&&!directory?'r+':'r');try{await f.sync();}finally{await f.close();}
}
export function analysisDirectory(c:Pick<CommandContext,'profile'|'appArguments'>):string{
  const value=c.profile.values.analysisDirectory;
  if(value===undefined||value===null)return c.appArguments.AppDataDirectory;
  if(typeof value!=='string'||!isAbsolute(value)||value!==resolve(value))fail('configuration','Invalid analysis directory in the Factory profile.');
  return value;
}
interface Entry {path:string;kind:'directory'|'file'|'link';size:number;mode:number;stamp:string;sha256?:string;link?:string}
interface Journal {
  schema:1;id:string;profile:string;binding:string;source:string;destination:string;previous:string|null;
  sourceIdentity:string;destinationAnchor:string;destinationIdentity:string;
  state:'copying'|'verified'|'activating'|'committed'|'rolling_back'|'rolled_back'|'cleaning'|'cleaned';
  entries:Entry[];trees:string[];manifest:string;createdAt:string;bytes:number;files:number;
  rollbackUnactivated?:boolean;
  targetIdentity?:string;backupIdentity?:string;backupParentIdentity?:string;
}
function stamp(st:import('node:fs').BigIntStats){return [st.dev,st.ino,st.mode,st.size,st.mtimeNs,st.ctimeNs].join(':');}
async function hash(path:string,signal?:AbortSignal){
  const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{const st=await f.stat({bigint:true});if(!st.isFile())fail('changed','Analysis file is no longer regular.');const h=createHash('sha256');
    for await(const chunk of f.createReadStream({autoClose:false})){signal?.throwIfAborted();h.update(chunk);}
    if(stamp(st)!==stamp(await f.stat({bigint:true})))fail('changed','Analysis file changed while checking it.');return h.digest('hex');
  }finally{await f.close();}
}
async function inventory(root:string,trees:readonly string[],hashes:boolean,signal?:AbortSignal,validateLinks=true){
  const entries:Entry[]=[];
  async function visit(path:string,depth:number){
    signal?.throwIfAborted();if(depth>128||entries.length>=1_000_000)fail('limit','Analysis inventory exceeds one million entries or 128 directory levels.');
    const at=join(root,path),st=await lstat(at,{bigint:true});
    if(st.size>BigInt(Number.MAX_SAFE_INTEGER))fail('limit','Analysis file exceeds the supported size counter.');
    const base={path,size:st.isFile()?Number(st.size):0,mode:Number(st.mode)&0o777,stamp:stamp(st)};
    if(st.isDirectory()){
      entries.push({...base,kind:'directory'});for(const name of (await readdir(at)).sort())await visit(path+'/'+name,depth+1);
      if(stamp(st)!==stamp(await lstat(at,{bigint:true})))fail('changed','Analysis directory changed during inventory.');
    }else if(st.isFile())entries.push({...base,kind:'file',...(hashes?{sha256:await hash(at,signal)}:{})});
    else if(st.isSymbolicLink()){
      if(validateLinks){const target=await realpath(at);if(!analysisTrees.some(tree=>inside(join(root,tree),target)))fail('link','An analysis link escapes the migrated trees; retain and inspect it before migration.');}
      entries.push({...base,kind:'link',link:await readlink(at)});
    }else fail('type','Analysis storage contains a special file; no migration was started.');
  }
  for(const tree of trees)if(await present(join(root,tree)))await visit(tree,0);
  return entries;
}
function content(entries:Entry[]){return entries.map(({path,kind,size,sha256,link})=>({path,kind,size,...(sha256?{sha256}:{}),...(link?{link}:{})}));}
async function canonicalFuture(path:string):Promise<string>{
  const st=await present(path);if(st){if(st.isSymbolicLink()||!st.isDirectory())fail('path','Choose an ordinary directory, without a symlink at its root.');return realpath(path);}
  const parent=dirname(path);if(parent===path)fail('path','No existing parent for the destination.');return join(await canonicalFuture(parent),basename(path));
}
async function existingParent(path:string):Promise<string>{return await present(path)?path:existingParent(dirname(path));}
async function directoryIdentity(path:string){const st=await lstat(path,{bigint:true});if(!st.isDirectory()||await realpath(path)!==path)fail('volume','Migration volume or directory was replaced.');return [st.dev,st.ino].join(':');}

/** Factory remains the only owner of profiles, settings, keyring and IPC admission. */
export class AnalysisStorage {
  private active=new Map<string,number>();private changing=new Set<string>();
  constructor(private readonly storeOverride:ProfileStoreContract|undefined,private readonly release:(c:CommandContext)=>Promise<void>,private readonly checkpoint?:(phase:string)=>Promise<void>){}
  private control(c:CommandContext){return join(c.appArguments.AppDataDirectory,'storage');}
  private store(c:CommandContext){return this.storeOverride??new ProfileStore({applicationId:c.appArguments.AppName,appArguments:c.appArguments});}
  private async binding(c:CommandContext){await mkdir(c.appArguments.AppDataDirectory,{recursive:true,mode:0o700});return digest(await realpath(c.appArguments.AppDataDirectory));}
  private async journal(c:CommandContext,loadEntries=false):Promise<Journal|undefined>{
    const record=await readJson<Omit<Journal,'entries'>>(join(this.control(c),'migration.json'));if(!record)return;
    if(!/^[-a-f0-9]{36}$/.test(record.id))fail('journal','Invalid migration identity.');
    const j:Journal={...record,entries:loadEntries?(await readJson<Entry[]>(join(this.control(c),'manifests',record.id+'.json')))??[]:[]};
    if(j.schema!==1||j.profile!==c.profile.name||j.binding!==await this.binding(c)||!/^[-a-f0-9]{36}$/.test(j.id)||
      !isAbsolute(j.source)||!isAbsolute(j.destination)||inside(j.source,j.destination)||inside(j.destination,j.source)||
      !isAbsolute(j.destinationAnchor)||!inside(j.destinationAnchor,j.destination)||typeof j.sourceIdentity!=='string'||typeof j.destinationIdentity!=='string'||
      !['copying','verified','activating','committed','rolling_back','rolled_back','cleaning','cleaned'].includes(j.state)||
      !Array.isArray(j.trees)||j.trees.some(t=>!analysisTrees.includes(t))||!Array.isArray(j.entries)||
      j.entries.some(e=>!j.trees.some(t=>e.path===t||e.path.startsWith(t+'/'))||e.path.split('/').some(p=>p==='..'||p==='.'||p===''))||
      !/^[a-f0-9]{64}$/.test(j.manifest)||loadEntries&&j.manifest!==digest(content(j.entries)))fail('journal','Migration journal failed its profile/path/integrity binding; preserve it.');
    return j;
  }
  private async save(c:CommandContext,j:Journal){
    const manifest=join(this.control(c),'manifests',j.id+'.json');if(!await present(manifest))await atomicWrite(manifest,j.entries);
    const {entries,...record}=j;await atomicWrite(join(this.control(c),'migration.json'),record);
  }
  private async validate(c:CommandContext){
    const root=analysisDirectory(c),j=await this.journal(c);
    if(j&&!terminal(j.state))fail('pending','Migration is incomplete. Use storage show, resume or rollback before research.');
    if(j&&['committed','cleaned'].includes(j.state)&&root!==j.destination)fail('configuration','Factory profile and committed migration differ; preserve both and inspect storage show.');
    if(root===c.appArguments.AppDataDirectory)return;
    const marker=await readJson<{schema:number;binding:string}>(join(root,'.insight-analysis.json'));
    if(!marker||marker.schema!==1||marker.binding!==await this.binding(c)||await realpath(root)!==root)
      fail('unavailable','Configured analysis storage is missing or changed; mount its volume. No fallback was created.');
    if(j&&['committed','cleaned'].includes(j.state)&&j.targetIdentity&&await directoryIdentity(root)!==j.targetIdentity)
      fail('binding','Committed analysis directory was replaced.');
    for(const tree of analysisTrees){
      if(await realpath(join(c.appArguments.AppDataDirectory,tree))!==join(root,tree))
        fail('binding','An analysis compatibility path was replaced; inspect storage show.');
    }
  }
  wrap(entry:CommandDefinition):CommandDefinition{
    const run=entry.run;return {...entry,...(entry.children?{children:entry.children.map(e=>this.wrap(e))}:{}),...(run?{run:async(input,c)=>{
      const key=c.appArguments.AppDataDirectory;if(this.changing.has(key))fail('busy','Storage migration is in progress.');
      this.active.set(key,(this.active.get(key)??0)+1);
      try{await this.validate(c);return await run(input,c);}finally{const n=this.active.get(key)!-1;if(n)this.active.set(key,n);else this.active.delete(key);}
    }}:{})};
  }
  busy(directory:string){return this.changing.has(directory);}
  private async exclusive<T>(c:CommandContext,action:()=>Promise<T>){
    const key=c.appArguments.AppDataDirectory;if(this.changing.has(key)||this.active.get(key)||toolProfileBusy(key))fail('busy','Finish active commands before storage migration.');
    this.changing.add(key);try{
      const processes=(await listProcesses(key)).filter(p=>!['exited','failed'].includes(p.state));
      const native=await runtimeProcesses(key);
      if(processes.length||native.length)throw new CliError('Close the profile contexts and stop its owned server/processes before migration. Unverified lifetimes also block copying.',{code:'storage.busy',result:{processes,native},next:[['tools','processes']]});
      await this.release(c);return await action();
    }finally{this.changing.delete(key);}
  }
  private async preflight(c:CommandContext,directory:unknown){
    if(typeof directory!=='string'||!isAbsolute(directory)||/[\0\r\n]/.test(directory))fail('path','Supply an absolute destination base directory.');
    const source=await canonicalFuture(analysisDirectory(c)),destination=await canonicalFuture(join(resolve(directory),c.appArguments.AppName,c.profile.name));
    const app=await canonicalFuture(c.appArguments.RoamingAppDataDirectory);
    if(inside(source,destination)||inside(destination,source)||inside(app,destination)||inside(destination,app))fail('path','Source, destination and profile configuration roots must be separate, non-nested directories.');
    const current=await this.journal(c);if(current&&!['cleaned','rolled_back'].includes(current.state))fail('pending','Finish or roll back the current migration; clean its retained source before starting another.');
    const st=await present(destination);if(st&&(await readdir(destination)).length)fail('destination','Destination profile directory must be empty; existing data is never adopted or overwritten.');
    const parent=await existingParent(destination);await access(parent,constants.R_OK|constants.W_OK|constants.X_OK);
    if(await present(source))await access(source,constants.R_OK|constants.W_OK|constants.X_OK);
    const entries=await inventory(source,analysisTrees,false,c.signal),bytes=entries.reduce((n,e)=>n+e.size,0);
    if(!Number.isSafeInteger(bytes))fail('limit','Analysis inventory exceeds the supported size counter.');
    const fs=await statfs(parent,{bigint:true}),available=fs.bavail*fs.bsize,reserve=BigInt(entries.length)*8192n+16n*1024n*1024n;
    if(available<BigInt(bytes)+reserve)fail('capacity','Destination has insufficient free space for data and migration overhead.');
    return {source,destination,destinationAnchor:parent,destinationIdentity:await directoryIdentity(parent),bytes,entries:entries.length,availableBytes:available.toString(),requiredBytes:(BigInt(bytes)+reserve).toString(),trees:analysisTrees,sourceRetained:true,compatibilityPathsRetained:true};
  }
  async show(c:CommandContext){
    const j=await this.journal(c),root=analysisDirectory(c);let usage:unknown,availability='available';
    try{await this.validate(c);const entries=await inventory(root,analysisTrees,false,c.signal);usage={files:entries.filter(e=>e.kind==='file').length,bytes:entries.reduce((n,e)=>n+e.size,0)};}
    catch(error){availability=error instanceof CliError?error.code:((error as NodeJS.ErrnoException).code??'unavailable');}
    return {profile:c.profile.name,directory:root,configuration:'Factory profile analysisDirectory',defaultDirectory:c.appArguments.AppDataDirectory,availability,usage,
      trees:analysisTrees,appData:c.appArguments.AppDataDirectory,included:['snapshots, immutable inputs, native projects and local server repositories','tool execution/verification working data','runtime installations, acquisition caches, selections and process receipts'],excluded:['profiles, permissions, IPC, logs and OS keyring secrets'],
      migration:j?{id:j.id,state:j.state,source:j.source,destination:j.destination,manifest:j.manifest,bytes:j.bytes,files:j.files,retainedSource:join(j.source,'.storage-retained',j.id),retainedSourceBytes:j.state==='committed'?j.bytes:0,progress:await readJson(join(this.control(c),'progress.json'))}:null};
  }
  async migrate(c:CommandContext,directory:unknown,dryRun=false,emptyOnly=false){return this.exclusive(c,async()=>{
    await this.validate(c);const plan=await this.preflight(c,directory);if(dryRun)return {state:'preflight',...plan};
    if(emptyOnly&&plan.entries)fail('data','This profile already has analysis data. Use storage migrate --directory to preserve it.');
    const entries=await inventory(plan.source,analysisTrees,true,c.signal),id=randomUUID();
    const binding=await this.binding(c);
    const j:Journal={schema:1,id,profile:c.profile.name,binding,source:plan.source,destination:plan.destination,
      sourceIdentity:await directoryIdentity(plan.source),destinationAnchor:plan.destinationAnchor,destinationIdentity:plan.destinationIdentity,
      previous:typeof c.profile.values.analysisDirectory==='string'?c.profile.values.analysisDirectory:null,state:'copying',entries,trees:[...analysisTrees],manifest:digest(content(entries)),createdAt:new Date().toISOString(),bytes:entries.reduce((n,e)=>n+e.size,0),files:entries.filter(e=>e.kind==='file').length};
    // Reserve durably before any destination or source changes. All ordinary commands now freeze.
    await this.save(c,j);await this.checkpoint?.('reserved');return this.continue(c,j);
  });}
  private async checkCopy(c:CommandContext,j:Journal){
    if(await canonicalFuture(j.destination)!==j.destination||j.targetIdentity&&await directoryIdentity(j.destination)!==j.targetIdentity)
      fail('binding','Destination directory was replaced.');
    const actual=await inventory(j.destination,j.trees,true,c.signal,false);
    // Empty managed roots also exist to receive future writes; normalize them out of the manifest.
    const expected=content(j.entries),actualContent=content(actual).filter(e=>!j.trees.includes(e.path)||expected.some(x=>x.path===e.path));
    if(digest(actualContent)!==j.manifest)fail('verification','Copied analysis bytes or directory membership differ; source remains retained.');
  }
  private async continue(c:CommandContext,j:Journal){
    if(await directoryIdentity(j.source)!==j.sourceIdentity||await directoryIdentity(j.destinationAnchor)!==j.destinationIdentity)
      fail('volume','A migration volume changed or disappeared. Mount the original volume before resuming; no fallback was created.');
    if(await canonicalFuture(j.destination)!==j.destination||j.targetIdentity&&await directoryIdentity(j.destination)!==j.targetIdentity)
      fail('binding','Destination directory was replaced; no migration write was made.');
    if(j.state==='rolling_back')return this.restore(c,j);
    if(j.state==='cleaning')return this.finishCleanup(c,j);
    if(terminal(j.state))return this.show(c);
    if(j.state==='copying'){
      await privateDirectory(j.destination);
      if(!j.targetIdentity){
        if((await readdir(j.destination)).length)fail('destination','Unreserved destination contents appeared before copying.');
        j.targetIdentity=await directoryIdentity(j.destination);await this.save(c,j);
      }
      let remaining=0n;
      for(const e of j.entries)if(e.kind==='file'&&!await present(join(j.destination,e.path))){
        if(await canonicalFuture(dirname(join(j.destination,e.path)))!==dirname(join(j.destination,e.path)))fail('binding','A destination parent was replaced.');
        // Reclaim only this transaction's unacknowledged file before checking capacity.
        await unlink(join(j.destination,e.path)+'.insight-copy-'+j.id).catch(e=>{if(!missing(e))throw e;});remaining+=BigInt(e.size);
      }
      const fs=await statfs(j.destinationAnchor,{bigint:true});
      if(fs.bavail*fs.bsize<remaining+BigInt(j.entries.length)*8192n+16n*1024n*1024n)fail('capacity','Destination no longer has sufficient free space; source and journal remain retained.');
      const marker=join(j.destination,'.insight-analysis.json'),old=await readJson<{id:string;binding:string}>(marker);
      if(old&&(old.id!==j.id||old.binding!==j.binding))fail('destination','Destination is claimed by another migration.');
      await atomicWrite(marker,{schema:1,id:j.id,binding:j.binding,profile:j.profile});
      for(const tree of j.trees){const path=join(j.destination,tree);if(await canonicalFuture(path)!==path)fail('binding','A destination tree was replaced.');await mkdir(path,{recursive:true,mode:0o700});}
      let completed=0;
      for(const entry of j.entries){
        c.signal.throwIfAborted();const at=join(j.destination,entry.path),source=join(j.source,entry.path);
        if(await canonicalFuture(entry.kind==='directory'?at:dirname(at))!==(entry.kind==='directory'?at:dirname(at)))fail('binding','A destination directory was replaced.');
        if(entry.kind==='directory')await mkdir(at,{recursive:true,mode:0o700});
        else if(entry.kind==='link'){
          const st=await present(at);if(st){if(!st.isSymbolicLink()||await readlink(at)!==entry.link)fail('destination','A destination link changed.');}
          else await symlink(entry.link!,at);
        }else{
          const st=await present(at);
          if(st){if(!st.isFile()||st.size!==entry.size||await hash(at,c.signal)!==entry.sha256)fail('verification','A completed destination file changed; preserve and inspect it.');}
          else{
            const partial=at+'.insight-copy-'+j.id;await rm(partial,{force:true});
            const input=await open(source,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK),output=await open(partial,'wx',0o600);
            try{
              if(stamp(await input.stat({bigint:true}))!==entry.stamp)fail('changed','Source changed since migration reservation. Roll back before retrying.');
              const h=createHash('sha256');let size=0;
              for await(const chunk of input.createReadStream({autoClose:false})){c.signal.throwIfAborted();size+=chunk.length;h.update(chunk);await output.writeFile(chunk);}
              if(size!==entry.size||h.digest('hex')!==entry.sha256||stamp(await input.stat({bigint:true}))!==entry.stamp)fail('changed','Source changed during copy.');
              await output.chmod((entry.mode&0o700)|0o400);await output.sync();
            }finally{await input.close();await output.close();}
            await rename(partial,at);await sync(dirname(at),true);
          }
        }
        await this.checkpoint?.('copied');
        if(++completed%32===0)await atomicWrite(join(this.control(c),'progress.json'),{completed,total:j.entries.length,phase:'copying'});
      }
      const source=await inventory(j.source,j.trees,true,c.signal);
      if(digest(source)!==digest(j.entries))fail('changed','Source changed while copying; switching was refused.');
      await this.checkCopy(c,j);
      for(const e of [...j.entries].reverse())if(e.kind==='directory')await sync(join(j.destination,e.path),true);
      await sync(j.destination,true);j.state='verified';await this.save(c,j);
    }
    if(j.state==='verified'){
      const source=await inventory(j.source,j.trees,true,c.signal);if(digest(source)!==digest(j.entries))fail('changed','Source changed before activation.');
      await this.checkCopy(c,j);j.state='activating';await this.save(c,j);
    }
    if(j.state==='activating'){
      await this.checkCopy(c,j);
      const backupRoot=join(j.source,'.storage-retained',j.id),backupParent=dirname(backupRoot);
      if(!j.backupIdentity){
        if(await canonicalFuture(backupRoot)!==backupRoot)fail('binding','Retained source ancestry was replaced.');
        await mkdir(backupRoot,{recursive:true,mode:0o700});
        if((await readdir(backupRoot)).length)fail('binding','Unreserved retained source contents appeared.');
        j.backupIdentity=await directoryIdentity(backupRoot);j.backupParentIdentity=await directoryIdentity(backupParent);await this.save(c,j);
      }
      await this.checkBackup(j);
      // After this durable intent, cancellation leaves a recoverable alias transaction.
      for(const tree of j.trees){
        const source=join(j.source,tree),backup=join(j.source,'.storage-retained',j.id,tree),target=join(j.destination,tree);
        const st=await present(source);
        if(st?.isSymbolicLink()){
          if(await realpath(source)!==target)fail('binding','An activating source alias changed.');continue;
        }
        if(st){await mkdir(dirname(backup),{recursive:true,mode:0o700});if(await present(backup))fail('binding','Retained source already exists beside an ordinary source.');await rename(source,backup);await sync(dirname(source),true);await sync(dirname(backup),true);await this.checkpoint?.('source-retained');}
        await mkdir(dirname(source),{recursive:true,mode:0o700});await symlink(target,source,process.platform==='win32'?'junction':'dir');await sync(dirname(source),true);
      }
      await this.checkCopy(c,j);await this.checkpoint?.('aliases-installed');
      await this.store(c).set(c.profile.name,{analysisDirectory:j.destination});
      await sync(join(c.appArguments.RoamingAppDataDirectory,'profiles.json'));await sync(c.appArguments.RoamingAppDataDirectory,true);
      await this.checkpoint?.('profile-switched');
      j.state='committed';await this.save(c,j);
      await atomicWrite(join(this.control(c),'progress.json'),{completed:j.entries.length,total:j.entries.length,phase:'committed'});
    }
    return {state:j.state,id:j.id,directory:j.destination,manifest:j.manifest,sourceRetained:true,rollback:'storage rollback',cleanup:'storage cleanup'};
  }
  async resume(c:CommandContext){return this.exclusive(c,async()=>{const j=await this.journal(c,true);if(!j)fail('missing','No migration journal exists.');return this.continue(c,j);});}
  async rollback(c:CommandContext){return this.exclusive(c,async()=>{
    const j=await this.journal(c,true);if(!j)fail('missing','No migration journal exists.');
    if(j.state==='cleaned'||j.state==='cleaning')fail('retention','Retained source cleanup has begun. Resume cleanup; rollback can no longer restore a complete source.');
    if(j.state==='rolled_back')return {state:j.state,id:j.id};
    if(j.state==='committed'||j.state==='activating')await this.checkCopy(c,j);
    if(j.state==='copying'||j.state==='verified')j.rollbackUnactivated=true;
    else await this.checkRetained(c,j);
    j.state='rolling_back';await this.save(c,j);return this.restore(c,j);
  });}
  private async restore(c:CommandContext,j:Journal){
    if(j.rollbackUnactivated){if(await directoryIdentity(j.source)!==j.sourceIdentity)fail('volume','Original source volume changed; rollback refused.');}
    else await this.checkRetained(c,j);
    for(const tree of j.rollbackUnactivated?[]:j.trees){
      const source=join(j.source,tree),backup=join(j.source,'.storage-retained',j.id,tree),st=await present(source);
      if(st?.isSymbolicLink()){
        if(await realpath(source)!==join(j.destination,tree))fail('binding','Rollback source alias changed.');await unlink(source);await sync(dirname(source),true);
      }
      if(await present(backup)){if(await present(source))fail('binding','Rollback destination contains unexpected data.');await rename(backup,source);await sync(dirname(source),true);await sync(dirname(backup),true);}
    }
    await this.store(c).set(c.profile.name,{analysisDirectory:j.previous});
    await sync(join(c.appArguments.RoamingAppDataDirectory,'profiles.json'));await sync(c.appArguments.RoamingAppDataDirectory,true);
    j.state='rolled_back';await this.save(c,j);return {state:j.state,id:j.id,directory:j.source,destinationRetained:j.destination};
  }
  async cleanup(c:CommandContext){return this.exclusive(c,async()=>{
    const j=await this.journal(c,true);if(!j||!['committed','cleaned'].includes(j.state))fail('retention','Cleanup requires a committed migration.');
    if(j.state==='cleaned')return {state:j.state,id:j.id};await this.validate(c);
    const root=join(j.source,'.storage-retained',j.id),retained=await inventory(root,j.trees,true,c.signal,false);
    if(digest(content(retained))!==j.manifest)fail('changed','Retained source changed; cleanup refused. Preserve it for inspection.');
    j.state='cleaning';await this.save(c,j);await this.checkpoint?.('cleanup-reserved');return this.finishCleanup(c,j);
  });}
  private async finishCleanup(c:CommandContext,j:Journal){
    await this.checkBackup(j,true);
    const root=join(j.source,'.storage-retained',j.id);
    await rm(root,{recursive:true,force:true});if(await present(dirname(root)))await sync(dirname(root),true);
    j.state='cleaned';await this.save(c,j);return {state:j.state,id:j.id,compatibilityPathsRetained:true};
  }
  private async checkRetained(c:CommandContext,j:Journal){
    if(await directoryIdentity(j.source)!==j.sourceIdentity)fail('volume','Original source volume changed; rollback refused.');
    if(j.backupIdentity)await this.checkBackup(j);
    const entries:Entry[]=[];
    for(const tree of j.trees){
      const backupRoot=join(j.source,'.storage-retained',j.id),backup=join(backupRoot,tree);
      if(await present(backup))entries.push(...await inventory(backupRoot,[tree],true,c.signal,false));
      else {const st=await present(join(j.source,tree));if(st&&!st.isSymbolicLink())entries.push(...await inventory(j.source,[tree],true,c.signal,false));}
    }
    if(digest(content(entries))!==j.manifest)fail('verification','Retained source bytes changed; rollback refused. The destination remains retained.');
  }
  private async checkBackup(j:Journal,allowAbsent=false){
    const root=join(j.source,'.storage-retained',j.id),parent=dirname(root);
    if(!j.backupIdentity||!j.backupParentIdentity||await directoryIdentity(parent)!==j.backupParentIdentity||await canonicalFuture(root)!==root)
      fail('binding','Retained source ancestry was replaced; no deletion or restore was attempted.');
    if(!await present(root)&&allowAbsent)return;
    if(await directoryIdentity(root)!==j.backupIdentity)fail('binding','Retained source directory was replaced; no deletion or restore was attempted.');
  }
  commands(){const directory={flags:'--directory <path>',description:'Absolute base directory; app name and profile are appended',required:true};return command('storage','Inspect and migrate profile analysis data',[
    command('show','Show effective analysis storage, usage and retained migration',(_i,c)=>this.show(c),{permission:Permission.ReadOnly}),
    command('configure','Choose storage for a profile with no analysis data',({options:o},c)=>this.migrate(c,o.directory,false,true),{permission:Permission.Update,options:[directory]}),
    command('migrate','Copy and verify all analysis data, retain source, then switch storage',({options:o},c)=>this.migrate(c,o.directory,Boolean(o.dryRun)),{permission:Permission.Update,options:[directory,{flags:'--dry-run',description:'Read-only path, capacity and quiescence preflight; create no migration'}]}),
    command('resume','Resume the retained copy/activation or rollback without replaying research',(_i,c)=>this.resume(c),{permission:Permission.Update}),
    command('rollback','Restore retained source; refuse after any destination content changes',(_i,c)=>this.rollback(c),{permission:Permission.Update}),
    command('cleanup','Delete verified retained source copies; retain compatibility paths permanently',(_i,c)=>this.cleanup(c),{permission:'Destructive'}),
  ]);}
}
