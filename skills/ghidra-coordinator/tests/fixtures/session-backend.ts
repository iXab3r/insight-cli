import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import type {Artifact} from '../../src/artifacts.js';
import {Workspace,type Scope,type ScalarChange,type Publication} from '../../src/workspace.js';
import type {ResearchBackend} from '../../src/research.js';
import type {ToolMode} from '../../src/contexts.js';
import {fieldKey} from '../../src/merge.js';

interface View {names:Record<string,string>;comments:Record<string,Record<string,string|null>>;opaque:string}
const empty=():View=>({names:{'1000':'first','1100':'second'},comments:{},opaque:'base'});
export class SessionBackend implements ResearchBackend {
  readonly nativeEngine='native-checkout-v1' as const;
  nativeUpdates=0;disposals=0;
  views=new Map<string,{epoch:number;view:View}>();
  shared=new Map<string,{revision:number;snapshot:Artifact}>();markers=new Map<string,number>();
  publications=0;edits=0;losePublication=false;loseSetter=false;cannotVerify=false;
  constructor(readonly workspace:Workspace){}
  private async decode(snapshot:Artifact):Promise<View>{return JSON.parse(await readFile(await this.workspace.artifacts.verify(snapshot),'utf8'));}
  async encode(view:View){const path=join(this.workspace.directory,'synthetic-'+randomUUID()+'.gzf');await writeFile(path,JSON.stringify(view));return this.workspace.captureSnapshot(path);}
  async open(scope:Scope,request?:string){
    if(this.workspace.unresolved(scope).some(item=>item.id!==request))throw Error('Unresolved fixture intent');
    let context=this.workspace.context(scope),model=this.workspace.model(scope.target);
    if(!model.sharedSnapshot){const snapshot=await this.encode(empty());model=this.workspace.establishModel(scope.target,1,snapshot);}
    if(!this.shared.has(scope.target))this.shared.set(scope.target,{revision:model.sharedRevision!,snapshot:model.sharedSnapshot!});
    const previous=this.views.get(context.id);
    if(previous&&previous.epoch===(context.viewEpoch??0))return context;
    const snapshot=context.workingSnapshot??this.shared.get(scope.target)!.snapshot;
    this.views.set(context.id,{epoch:context.viewEpoch??0,view:await this.decode(snapshot)});
    if(!context.workingSnapshot)context=this.workspace.saveContext(scope,context.generation,{state:'ready',baseRevision:model.sharedRevision!,
      baseSnapshot:model.sharedSnapshot!,workingSnapshot:snapshot});return context;
  }
  private view(scope:Scope){return this.views.get(this.workspace.context(scope).id)!.view;}
  async call(scope:Scope,operation:string,p:Record<string,unknown>={}):Promise<unknown> {
    const view=this.view(scope),at=String(p.address??p.functions);
    if(operation==='/get_comment')return {address:at,eol:null,pre:null,post:null,plate:null,repeatable:null,...view.comments[at]};
    if(operation==='/get_functions')return {functions:{[at]:{name:view.names[at],entry_point:at,signature:'int '+view.names[at]+'(void)'}}};
    if(operation==='/set_comment'){view.comments[at]??={};view.comments[at]![String(p.type)]=p.comment===''?null:String(p.comment);}
    else if(operation==='/rename_function')view.names[String(p.old_name)]=String(p.new_name);
    else throw Error('Unsupported fixture operation');
    this.edits++;if(this.loseSetter)throw Error('Synthetic setter response loss');return {status:'success'};
  }
  async saved(scope:Scope){return this.encode(this.view(scope));}
  async updateNative(scope:Scope,_request:string){
    this.nativeUpdates++;
    const context=this.workspace.context(scope),shared=this.shared.get(scope.target)!,original=await this.decode(context.baseSnapshot!),mine=this.view(scope),latest=await this.decode(shared.snapshot);
    // JSON-only fake backend for orchestration tests. Actual Ghidra semantics are established by native acceptance.
    const same=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
    function receive(base:unknown,local:unknown,remote:unknown):unknown{
      if(same(local,base))return remote;if(same(remote,base)||same(local,remote))return local;
      if([base,local,remote].every(v=>v!==null&&typeof v==='object'&&!Array.isArray(v))){
        const b=base as Record<string,unknown>,l=local as Record<string,unknown>,r=remote as Record<string,unknown>,out:Record<string,unknown>={};
        for(const key of new Set([...Object.keys(b),...Object.keys(l),...Object.keys(r)])){const value=receive(b[key],l[key],r[key]);if(value!==undefined)out[key]=value;}return out;
      }
      throw Error('Synthetic native resolver conflict');
    }
    let combined:View;try{combined=receive(original,mine,latest) as View;}catch{return {state:'conflict' as const,revision:context.baseRevision!,conflict:'Synthetic native resolver conflict'};}
    const snapshot=await this.encode(combined),receivedChanges=Number(context.baseRevision!==shared.revision),viewEpoch=(context.viewEpoch??0)+1;
    this.workspace.observeShared(scope.target,shared.revision,shared.snapshot);
    this.workspace.saveContext(scope,context.generation,{baseRevision:shared.revision,baseSnapshot:shared.snapshot,workingSnapshot:snapshot,viewEpoch});
    this.views.set(context.id,{epoch:viewEpoch,view:combined});
    return {state:same(combined,latest)?'empty' as const:'ready' as const,revision:shared.revision,snapshot,sharedSnapshot:shared.snapshot,receivedChanges,nativeMergeInvocations:receivedChanges};
  }
  async publishNative(publication:Publication){return this.publish(publication);}
  async dropNative(scope:Scope){this.disposals++;this.views.delete(this.workspace.context(scope).id);}
  async finishEmptyNative(scope:Scope){const c=this.workspace.context(scope),shared=this.shared.get(scope.target)!;
    this.workspace.saveContext(scope,c.generation,{workingSnapshot:shared.snapshot,baseSnapshot:shared.snapshot,baseRevision:shared.revision,scalars:[],complexChanges:[],viewEpoch:(c.viewEpoch??0)+1});
    await this.dropNative(scope);
  }
  async mode(_scope:Scope,_mode:ToolMode){}
  async close(scope:Scope){this.views.delete(this.workspace.context(scope).id);}
  async dispose(){this.views.clear();}
  async latest(target:string){return this.shared.get(target)!;}
  async fields(snapshot:Artifact,changes:Pick<ScalarChange,'address'|'field'>[]) {
    const view=await this.decode(snapshot);
    return Object.fromEntries(changes.map(change=>[fieldKey(change),{value:change.field==='function.name'?view.names[change.address]??null:
      view.comments[change.address]?.[change.field.slice(8)]??null,exists:Boolean(view.names[change.address]),dependency:'d'.repeat(64)}]));
  }
  async candidate(_target:string,snapshot:Artifact,changes:ScalarChange[]) {
    const view=await this.decode(snapshot);
    for(const change of changes){if(change.field==='function.name')view.names[change.address]=change.local!;
      else{view.comments[change.address]??={};view.comments[change.address]![change.field.slice(8)]=change.local;}}
    return this.encode(view);
  }
  async publish(publication:Publication):Promise<{state:'published';revision:number}|{state:'conflict';applied:0}> {
    const current=this.shared.get(publication.target)!;
    if(current.revision!==publication.expectedRevision)return {state:'conflict',applied:0};
    const revision=current.revision+1;this.publications++;this.shared.set(publication.target,{revision,snapshot:publication.snapshot});this.markers.set(publication.id,revision);
    if(this.losePublication)throw Error('Synthetic committed publication response loss');return {state:'published',revision};
  }
  async recover(publication:Publication):Promise<{state:'verified';revision:number}|{state:'unknown'}> {
    const revision=this.markers.get(publication.id);
    return !this.cannotVerify&&revision?{state:'verified',revision}:{state:'unknown'};
  }
  async recoverModel(_target:string){return true;}
}
