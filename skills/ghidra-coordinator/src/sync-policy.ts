import {command,Permission,type CommandDefinition,type CommandContext} from '@eyeauras/cli-factory';
import {Research,scope} from './research.js';
import {Workspace,type Scope,type SyncPolicy} from './workspace.js';
import {fail,id,object,text} from './model.js';
import {selectedOptions} from './arguments.js';
export const manualPolicy:SyncPolicy={publish:'manual',refresh:'manual'};
export function syncPolicy(value:unknown):SyncPolicy {
  const p=object(value);if(Object.keys(p).some(k=>!['publish','refresh'].includes(k))||!['manual','after-edit','after-save'].includes(String(p.publish))||!['manual','before-edit'].includes(String(p.refresh)))fail('invalid','Policy requires publish manual/after-edit/after-save and refresh manual/before-edit.');
  return {publish:p.publish as SyncPolicy['publish'],refresh:p.refresh as SyncPolicy['refresh']};
}
export class Synchronization {
  constructor(readonly workspace:Workspace,readonly research:Research,private readonly authorize:()=>Promise<void>=async()=>{}){}
  get(selected:Scope){return {...selected,...(this.workspace.context(selected).syncPolicy??manualPolicy)};}
  async set(selected:Scope,policy:SyncPolicy,callerId?:string){
    const reserved=this.workspace.reserveRequest(selected,'ghidra.sync-policy.set',policy,callerId);
    return this.research.ordered(selected,async()=>{const request=this.workspace.request(reserved.request.id);if(reserved.replay&&request.state==='applied')return request.result;
      if(request.state!=='accepted')fail('unknown','Policy change has a retained outcome.');
      if(this.workspace.unresolved(selected).length)fail('blocked','Reconcile the context outcome before changing its synchronization policy.');
      const current=this.workspace.context(selected),result={...selected,state:'configured',...policy};this.workspace.startRequest(request.id);
      this.workspace.completeSavedRequest(selected,request.id,current.generation,{syncPolicy:policy},result);return result;
    });
  }
  /** The outer command queue spans refresh, the durable local intent and publication. Inner
   * research queues remain unchanged, including their cross-context ordering and shared lane. */
  async execute(selected:Scope,path:string,input:Record<string,unknown>,run:(requestId:string)=>Promise<unknown>){
    const configured=this.workspace.context(selected).syncPolicy??manualPolicy;
    const caller=input.requestId===undefined?undefined:id(input.requestId);
    const recorded=caller?this.workspace.scopedRequest(selected,caller):undefined;
    if(caller&&recorded?.id===caller)return run(caller);
    const previous=caller?this.workspace.administrationByCaller(caller):undefined;
    if(!previous&&(configured.publish==='manual'&&configured.refresh==='manual'||input.requestId!==undefined&&this.workspace.requestByCaller(id(input.requestId))))return run(input.requestId===undefined?'':id(input.requestId));
    if(previous&&previous.operation!=='ghidra.automatic')fail('idempotency','Request ID already identifies another profile administration operation.');
    const policy=previous?syncPolicy(object(object(previous.intent).parameters).policy):configured;
    const reserved=this.workspace.reserveAdministration('ghidra.automatic',{...selected,path,input,policy},caller);
    const request=this.workspace.administration(reserved.request.id),requestId='auto-local-'+request.id;
    if(reserved.replay&&request.state==='applied')return request.result;
    if(reserved.replay&&request.state==='failed')fail(String(object(request.result??{}).failureCode??'coordinator.conflict').replace(/^coordinator\./,''),'This automatic workflow retains its original failed result.',request.result);
    if(policy.refresh==='before-edit'&&path!=='ghidra save'||policy.publish==='after-edit'||policy.publish==='after-save'&&path==='ghidra save')await this.authorize();
    let progress=object(request.result??{phase:'accepted'});
    const remember=(patch:Record<string,unknown>)=>{progress={...progress,...patch};this.workspace.administrationState(request.id,'unknown',progress);};
    try{
      // Re-entering a dispatched local command always uses its original request identity.
      // A lost merge reply is reconciled by merge itself; no check-in is re-dispatched.
      if(progress.phase==='accepted'&&policy.refresh==='before-edit'&&path!=='ghidra save'){
        remember({phase:'refresh'});const incoming=object(await this.research.refresh(selected,'auto-refresh-'+request.id));
        remember({incoming,phase:'ready'});if(incoming.state==='conflict'){
          const result={...selected,state:'conflict',phase:'refresh',localApplied:false,automatic:{refresh:incoming}};
          this.workspace.administrationState(request.id,'failed',result);fail('conflict','Automatic refresh retained conflicts; the requested edit was not started.',result);
        }
      }else if(progress.phase==='refresh'){
        // Refresh's candidate/context commit is already durable or explicitly unresolved.
        const incoming=object(await this.research.refresh(selected,'auto-refresh-'+request.id));remember({incoming,phase:'ready'});
        if(incoming.state==='conflict')fail('conflict','Automatic refresh retained conflicts; the edit was not started.',{...selected,state:'conflict',localApplied:false,automatic:{refresh:incoming}});
      }
      let local=progress.local===undefined?undefined:object(progress.local);
      if(!local){remember({phase:'local'});local=object(await run(requestId));if(!['applied','saved','preview'].includes(String(local.state)))fail('unknown','The local command has no verified saved acknowledgment.',local);remember({local,phase:'saved'});}
      const automatic:Record<string,unknown>={...(progress.incoming?{refresh:progress.incoming}:{})};
      const publish=(policy.publish==='after-save'&&path==='ghidra save'||policy.publish==='after-edit')&&
        (path==='ghidra save'||local.sharedState==='pending')&&Number(local.pendingChanges)>0;
      if(publish){remember({phase:'publish'});automatic.publication=await this.research.merge(selected,'auto-merge-'+request.id);}
      const current=this.workspace.context(selected),result={...local,pendingChanges:current.scalars.length+current.complexChanges.length,
        ...(local.sharedState!==undefined?{sharedState:current.scalars.length||current.complexChanges.length?'pending':'shared'}:{}),automatic};
      this.workspace.administrationState(request.id,'applied',result);return result;
    }catch(error){
      if(this.workspace.administration(request.id).state==='failed')throw error;
      const code=String((error as {code?:unknown}).code??'coordinator.unknown'),detail=(error as {result?:unknown}).result,child=this.workspace.requestByCaller(requestId);
      const notStarted=progress.phase==='local'&&(!child||child.state==='accepted'),rejected=progress.phase==='local'&&child?.state==='failed'&&object(child.result??{}).state==='rejected';
      const knownRejection=rejected||notStarted&&code.endsWith('.invalid');
      // Retain the local acknowledgment alongside a failed/uncertain publication. Its caller
      // can distinguish successful editing from a publication that needs intervention.
      const result={...selected,state:code.endsWith('.conflict')?'conflict':knownRejection?'rejected':'unknown',failureCode:code,phase:progress.phase,
        ...(progress.local?{localApplied:true,local:progress.local}:notStarted||rejected?{localApplied:false}:{localOutcome:progress.phase==='local'?'unknown':'not_started'}),automatic:{...(progress.incoming?{refresh:progress.incoming}:{}),...(detail?{outcome:detail}:{})}};
      if(code.endsWith('.conflict')||knownRejection)this.workspace.administrationState(request.id,'failed',result);
      else this.workspace.administrationState(request.id,'unknown',{...progress,outcome:result});
      fail(code.endsWith('.conflict')?'conflict':knownRejection?code.replace(/^coordinator\./,''):'unknown','Automatic synchronization did not complete; retained local effects are not replayed.',result);
    }
  }
}
export function synchronizationCommands(service:(c:CommandContext)=>Synchronization):CommandDefinition[]{return [command('sync-policy','Configure opt-in synchronization for one saved tool context',[
  command('get','Read the persisted policy; default is manual',({options:o},c)=>service(c).get(scope(o)),{permission:Permission.ReadOnly,options:selectedOptions}),
  command('set','Choose manual, publication after edit/save and optional refresh before edit',({options:o},c)=>service(c).set(scope(o),syncPolicy({publish:text(o.publish),refresh:text(o.refresh)}),o.requestId===undefined?undefined:id(o.requestId)),{permission:Permission.Update,options:[...selectedOptions,
    {flags:'--publish <mode>',description:'manual, after-edit or after-save',required:true},{flags:'--refresh <mode>',description:'manual or before-edit',required:true},{flags:'--request-id <id>',description:'Retrieve the recorded policy change'}]}),
])];}
