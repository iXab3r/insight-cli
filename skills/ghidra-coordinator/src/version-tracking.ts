import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {mkdir,readFile,open,rename,realpath,lstat,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {Workspace,type Scope} from './workspace.js';
import {Research,scope,address,number,type ResearchBackend} from './research.js';
import {id,text,object,fail,stable} from './model.js';
import {selectedOptions} from './arguments.js';
import type {Artifact} from './artifacts.js';
import {randomUUID} from 'node:crypto';
interface TrackingOwner {schema:1;tracking:string;profile:string;source:Scope;destination:Scope;sourceSnapshot:Artifact;destinationSnapshot:Artifact;sourceGeneration:number;destinationGeneration:number}
async function persist(path:string,value:unknown){const temp=path+'.new-'+randomUUID(),file=await open(temp,'wx',0o600);try{await file.writeFile(stable(value));await file.sync();}finally{await file.close();}await rename(temp,path);}
/** A native VT object belongs to an existing research session; it is not another agent session. */
export class VersionTracking {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>,private readonly tasks:Map<string,Promise<unknown>>){}
  private async ordered<T>(tracking:string,action:()=>Promise<T>){const key='vt:'+tracking,previous=this.tasks.get(key),task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);this.tasks.set(key,task);try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}}
  private async root(tracking:string){id(tracking);if(!/^vt_a_[a-zA-Z0-9-]+$/.test(tracking))fail('invalid','Invalid Version Tracking object ID.');
    const root=join(this.workspace.directory,'version-tracking',tracking);if(await realpath(root)!==resolve(root)||(await lstat(root)).isSymbolicLink())fail('binding','VT object left its owned storage.');return root;}
  private async owner(selected:Scope,tracking:string){const root=await this.root(tracking),owner=object(JSON.parse(await readFile(join(root,'owner.json'),'utf8'))) as unknown as TrackingOwner;
    if(owner.schema!==1||owner.tracking!==tracking||owner.profile!==this.workspace.profile||owner.destination.session!==selected.session||owner.destination.target!==selected.target)fail('binding','VT object belongs to another research scope.');
    await this.workspace.artifacts.verify(owner.sourceSnapshot);await this.workspace.artifacts.verify(owner.destinationSnapshot);return {root,owner};}
  private response(owner:TrackingOwner,value:unknown){return {...owner.destination,tracking:owner.tracking,source:{...owner.source,snapshotSha256:owner.sourceSnapshot.sha256},destination:{...owner.destination,snapshotSha256:owner.destinationSnapshot.sha256},
    sourceContextChanged:this.workspace.context(owner.source).generation!==owner.sourceGeneration,destinationContextChanged:this.workspace.context(owner.destination).generation!==owner.destinationGeneration,value};}
  private async native(operation:string,root:string,p:Record<string,unknown>){const backend=await this.backend();if(!backend.sdkFile)fail('configuration','Native VT is unavailable.');return backend.sdkFile('vt.'+operation,{...p,root});}
  async list(selected:Scope,offset:number,limit:number){
    this.workspace.context(selected);const parent=join(this.workspace.directory,'version-tracking');let entries;
    try{entries=await readdir(parent,{withFileTypes:true});}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return {...selected,items:[],complete:true};throw error;}
    entries.sort((a,b)=>a.name.localeCompare(b.name));const items=[];let index=offset,visited=0;
    for(;index<entries.length&&items.length<limit&&visited<1000;index++,visited++){
      const entry=entries[index]!;if(!entry.isDirectory()||!/^vt_a_[a-zA-Z0-9-]+$/.test(entry.name))fail('binding','VT inventory contains an unexpected storage entry.');
      const root=await this.root(entry.name);let owner:TrackingOwner;
      try{owner=JSON.parse(await readFile(join(root,'owner.json'),'utf8')) as TrackingOwner;}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')continue;fail('binding','VT owner record is malformed; retained storage requires inspection.');}
      if(owner.profile!==this.workspace.profile||owner.destination.session!==selected.session||owner.destination.target!==selected.target)continue;
      items.push({tracking:entry.name,source:owner.source,destination:owner.destination,sourceSnapshotSha256:owner.sourceSnapshot.sha256,destinationSnapshotSha256:owner.destinationSnapshot.sha256});
    }
    return {...selected,items,visited,complete:index===entries.length,...(index<entries.length?{nextOffset:index}:{})};
  }
  private decisionResult(request:string,owner:TrackingOwner,value:unknown){const result=this.response(owner,value);
    if(object(value).state==='rejected'){this.workspace.administrationState(request,'failed',result);fail('rejected','Native association constraints rejected this decision; its transaction was rolled back.',result);}
    this.workspace.administrationState(request,'applied',result);return result;}
  async create(selected:Scope,source:Scope,callerId?:string){const reserved=this.workspace.reserveAdministration('sdk.vt.create',{...selected,source},callerId),tracking='vt_'+reserved.request.id;
    return this.research.paired(selected,source,()=>this.ordered(tracking,async()=>{
      const request=this.workspace.administration(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        const {root,owner}=await this.owner(selected,tracking);let receipt;try{receipt=object(JSON.parse(await readFile(join(root,'created.json'),'utf8')));}catch{fail('unknown','VT creation is retained without a completed receipt; it is not repeated.');}
        if(receipt.request!==request.id||receipt.operation!=='create')fail('binding','VT creation receipt differs.');const result=this.response(owner,receipt.value);this.workspace.administrationState(request.id,'applied',result);return result;
      }
      const backend=await this.backend();await backend.open(selected);await backend.open(source);
      const sourceSnapshot=await backend.saved(source),destinationSnapshot=await backend.saved(selected),root=join(this.workspace.directory,'version-tracking',tracking);
      await mkdir(root,{recursive:true,mode:0o700});if(await realpath(root)!==resolve(root))fail('binding','VT storage moved.');
      const owner:TrackingOwner={schema:1,tracking,profile:this.workspace.profile,source,destination:selected,sourceSnapshot,destinationSnapshot,
        sourceGeneration:this.workspace.context(source).generation,destinationGeneration:this.workspace.context(selected).generation};await persist(join(root,'owner.json'),owner);
      this.workspace.administrationState(request.id,'running',{tracking});
      try{const value=await this.native('create',root,{request_id:request.id,source_snapshot:await this.workspace.artifacts.verify(sourceSnapshot),destination_snapshot:await this.workspace.artifacts.verify(destinationSnapshot),receipt:join(root,'created.json')});
        const result=this.response(owner,value);this.workspace.administrationState(request.id,'applied',result);return result;
      }catch(error){this.workspace.administrationState(request.id,'unknown',{...selected,tracking,state:'unknown'});throw error;}
    }));
  }
  async read(selected:Scope,tracking:string,operation:'matches'|'markup',p:Record<string,unknown>){return this.ordered(tracking,async()=>{const {root,owner}=await this.owner(selected,tracking);return this.response(owner,await this.native(operation,root,p));});}
  async decide(selected:Scope,tracking:string,p:Record<string,unknown>,callerId?:string){const reserved=this.workspace.reserveAdministration('sdk.vt.decide',{...selected,tracking,...p},callerId);
    return this.ordered(tracking,async()=>{const request=this.workspace.administration(reserved.request.id),{root,owner}=await this.owner(selected,tracking),receipts=join(root,'decisions');await mkdir(receipts,{recursive:true,mode:0o700});const receiptPath=join(receipts,request.id+'.json');
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        if(request.state==='failed')fail('rejected','The native association decision was rejected and is not repeated.',request.result);
        let receipt;try{receipt=object(JSON.parse(await readFile(receiptPath,'utf8')));}catch{fail('unknown','VT decision is uncertain and is not repeated.');}
        if(receipt.request!==request.id||receipt.operation!=='decide')fail('binding','VT decision receipt differs.');return this.decisionResult(request.id,owner,receipt.value);
      }
      if(this.workspace.unresolvedSessionAdministration(selected.session,selected.target).some(earlier=>earlier.id!==request.id&&object(object(earlier.intent).parameters).tracking===tracking))fail('blocked','An earlier decision on this VT object is unresolved.');
      this.workspace.administrationState(request.id,'running',{...selected,tracking});try{const value=await this.native('decide',root,{...p,request_id:request.id,receipt:receiptPath});return this.decisionResult(request.id,owner,value);}
      catch(error){if(this.workspace.administration(request.id).state!=='failed')this.workspace.administrationState(request.id,'unknown',{...selected,tracking,state:'unknown'});throw error;}
    });
  }
}
export function trackingCommands(service:(c:CommandContext)=>VersionTracking):CommandDefinition[]{
  const tracking={flags:'--tracking <id>',description:'Native VT object returned by create',required:true},request={flags:'--request-id <id>',description:'Retrieve a retained native decision without repeating it'},
    association=[{flags:'--source-address <address>',description:'Source address in this VT snapshot',required:true},{flags:'--destination-address <address>',description:'Destination address in this VT snapshot',required:true}];
  return [command('version-tracking','Native source/destination match sets, association decisions and markup inventory',[
    command('list','List VT objects owned by this destination research scope, including retained creation stages',({options:o},c)=>service(c).list(scope(o),number(o.offset,1000000),number(o.limit,1000,1)),
      {permission:Permission.ReadOnly,options:[...selectedOptions,{flags:'--limit <count>',description:'Maximum returned owned VT objects',defaultValue:100},{flags:'--offset <count>',description:'Inventory offset; use nextOffset after a partial scan',defaultValue:0}]}),
    command('create','Correlate immutable source/destination snapshots in a persistent owned native VT project',({options:o},c)=>{
      const selected=scope(o),source={session:o.sourceSession===undefined?selected.session:id(o.sourceSession),target:id(o.sourceTarget)};
      return service(c).create(selected,source,o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...selectedOptions,{flags:'--source-target <id>',description:'Source immutable target',required:true},{flags:'--source-session <id>',description:'Source research session (default destination session)'},request]}),
    command('matches','Read native match sets and correlator-specific scores from the saved VT object',({options:o},c)=>service(c).read(scope(o),id(o.tracking),'matches',{limit:number(o.limit,1000,1),offset:number(o.offset,100000)}),
      {permission:Permission.ReadOnly,options:[...selectedOptions,tracking,{flags:'--limit <count>',description:'Match page size 1–1000',defaultValue:100},{flags:'--offset <count>',description:'Page offset',defaultValue:0}]}),
    command('markup','Inspect native markup values for one association before agent-directed edits',({options:o},c)=>service(c).read(scope(o),id(o.tracking),'markup',{source_address:address(o.sourceAddress),destination_address:address(o.destinationAddress)}),
      {permission:Permission.ReadOnly,options:[...selectedOptions,tracking,...association]}),
    command('decide','Explicitly accept/reject/reset one native association; native one-to-one constraints apply',({options:o},c)=>{
      const decision=text(o.decision);if(!['accepted','rejected','available'].includes(decision))fail('invalid','Decision must be accepted, rejected or available.');
      return service(c).decide(scope(o),id(o.tracking),{source_address:address(o.sourceAddress),destination_address:address(o.destinationAddress),decision},o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...selectedOptions,tracking,...association,{flags:'--decision <state>',description:'accepted, rejected or available',required:true},request]}),
  ])];
}
