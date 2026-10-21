import {command,Permission,CliError,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Research,scope,type ResearchBackend} from './research.js';
import {Workspace,type Scope,type DebuggerState} from './workspace.js';
import {id,fail,object,digest} from './model.js';
import {selectedOptions} from './arguments.js';
import type {Artifact} from './artifacts.js';
export class Lifecycle {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>){}
  async health(selected:Scope) {
    return this.research.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const connection=object(await backend.call(selected,'/check_connection')),health=object(await backend.call(selected,'/mcp/health'));
      if(connection.status!=='ok'||health.status!=='ok'||health.connected!==true||!['headless','gui'].includes(String(health.server_kind)))fail('partial','Tool health did not verify the selected context.');
      return {...this.research.status(selected),health:{connected:true,mode:health.server_kind,version:health.version,memory:health.memory_mb}};
    });
  }
  async change(selected:Scope,operation:'save'|'close',callerId?:string) {
    const reserved=this.workspace.reserveRequest(selected,'ghidra.'+operation,{},callerId);
    return this.research.ordered(selected,async()=>{
      let request=this.workspace.request(reserved.request.id),backend:ResearchBackend|undefined;
      if(reserved.replay&&['running','unknown'].includes(request.state)){
        backend=await this.backend();await this.research.reconcileRequests(selected,backend);request=this.workspace.request(request.id);
      }
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        throw new CliError('This lifecycle outcome remains unresolved; inspect its retained worker before retrieving it again.',{
          code:'coordinator.unknown',result:{...selected,state:request.state,requestId:request.callerId??request.id},
          next:[['sessions','status',selected.session,'--target',selected.target],
            ...(operation==='close'?[['tools','processes','--tool','ghidra','--session',selected.session,'--target',selected.target]]:[['ghidra','open','--session',selected.session,'--target',selected.target]])]});
      }
      backend??=await this.backend();const unresolved=this.workspace.unresolved(selected);
      const closingExternal=operation==='close'&&unresolved.length>0&&unresolved.every(intent=>['debugger','ui'].includes(String(object(intent.execution??{}).kind)));
      const alreadyEnded=closingExternal&&backend.closed?await backend.closed(selected):false;
      if(!closingExternal)await backend.open(selected);const before=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:operation,generation:before.generation,workingSnapshot:before.workingSnapshot});
      let savedSnapshot:Artifact|undefined;
      try {
        if(operation==='close'&&!alreadyEnded)await backend.close(selected);
        const current=this.workspace.context(selected),snapshot=operation==='save'?await backend.saved(selected):current.workingSnapshot;
        if(!snapshot)fail('partial','Lifecycle operation did not retain its private snapshot.');
        savedSnapshot=snapshot;
        if(closingExternal&&backend.closed&&await backend.closed(selected))for(const intent of unresolved){
          const before=this.workspace.context(selected),execution=object(intent.execution??{}),outcome=object(intent.result??{}),retained=outcome.savedDebugger as DebuggerState|undefined;
          if(execution.kind==='debugger'&&before.generation===execution.generation){
            const program=outcome.metadataChanged===true?outcome.savedSnapshot as Artifact|undefined:undefined;
            if(program)await this.workspace.artifacts.verify(program);for(const trace of retained?.traces??[])await this.workspace.artifacts.verify(trace.snapshot);
            if(retained||program)this.workspace.saveContext(selected,before.generation,{...(retained?{debugger:{...retained,connected:false,traces:retained.traces.map(trace=>({...trace,connected:false}))}}:{}),
              ...(program?{workingSnapshot:program,complexChanges:before.complexChanges.includes(intent.id)?before.complexChanges:[...before.complexChanges,intent.id]}:{})});
          }
          this.workspace.recordRequest(intent.id,'failed',{...selected,state:'disconnected',outcome:'unknown',operation:object(intent.execution??{}).operation});
        }
        const retained=this.workspace.context(selected);
        const result={...selected,state:operation==='save'?'saved':'closed',pendingChanges:retained.scalars.length+retained.complexChanges.length};
        this.workspace.completeSavedRequest(selected,request.id,retained.generation,{workingSnapshot:operation==='close'?retained.workingSnapshot??snapshot:snapshot,...(operation==='close'?{state:'stopped' as const,
          ...(retained.debugger?{debugger:{...retained.debugger,connected:false,traces:retained.debugger.traces.map(trace=>({...trace,connected:false}))}}:{})}:{} )},result);return result;
      }catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',...(savedSnapshot?{savedSnapshot}:{})});throw error;}
    });
  }
  async discard(selected:Scope,callerId?:string) {
    const reserved=this.workspace.reserveRequest(selected,'ghidra.changes.discard',{},callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){if(request.state==='applied')return request.result;fail('unknown','Local discard outcome is retained; continue the context before retrieving it.',request.result);}
      const backend=await this.backend();await backend.open(selected);
      if(this.workspace.context(selected).debugger?.connected)fail('busy','Close the live debugger context before discarding static program edits.');
      // Resource save/release precedes the local atomic switch, as with mode preparation.
      await backend.close(selected);const context=this.workspace.context(selected);
      if(!context.baseSnapshot||!context.workingSnapshot)fail('binding','Discard requires retained base and private snapshots.');
      await this.workspace.artifacts.verify(context.baseSnapshot);
      const result={...selected,state:'discarded',discardedChanges:context.scalars.length+context.complexChanges.length,pendingChanges:0,
        baseRevision:'R'+context.baseRevision,discardedSnapshot:context.workingSnapshot};
      this.workspace.startRequest(request.id,{kind:'discard',generation:context.generation,baseSnapshot:context.baseSnapshot,discardedSnapshot:context.workingSnapshot,result});
      this.workspace.completeSavedRequest(selected,request.id,context.generation,{workingSnapshot:context.baseSnapshot,state:'stopped',viewEpoch:(context.viewEpoch??0)+1,scalars:[],complexChanges:[]},result);return result;
    });
  }
  async saveAll(session:string,callerId?:string) {
    this.workspace.session(session);const reserved=this.workspace.reserveAdministration('session.ghidra.save',{session},callerId),request=this.workspace.administration(reserved.request.id);
    if(reserved.replay&&request.state!=='accepted'){if(request.state==='applied')return request.result;fail('unknown','Session save outcomes are retained and are not repeated.',request.result);}
    const contexts=[];for(let offset=0;;offset+=100){const page=this.workspace.contexts(session,100,offset);contexts.push(...page);if(page.length<100)break;if(contexts.length>=1000)fail('limit','Session-wide save supports fewer than 1000 contexts; save explicitly selected contexts.');}
    const result={session,state:'saving',saved:0,errors:0,items:[] as Record<string,unknown>[]};this.workspace.administrationState(request.id,'running',result);
    for(const context of contexts){const selected={session,target:context.target};this.workspace.administrationState(request.id,'unknown',{...result,pending:selected});
      try{const value=object(await this.change(selected,'save','save-'+digest([request.id,context.id])));result.items.push(value);result.saved++;}
      catch{result.items.push({...selected,state:'unknown'});result.errors++;}
      this.workspace.administrationState(request.id,'unknown',result);
    }
    result.state=result.errors?'partial':'saved';this.workspace.administrationState(request.id,result.errors?'unknown':'applied',result);
    if(result.errors)fail('partial','Some selected context saves need recovery; completed saves remain retained.',result);return result;
  }
}
export function lifecycleCommands(service:(context:CommandContext)=>Lifecycle,runtimeStatus?:(context:CommandContext)=>Promise<unknown>):CommandDefinition[] {
  return [command('changes','Manage unpublished edits in the selected context',[
    command('discard','Save a retained copy, then restore the opening base without publication',({options:o},c)=>service(c).discard(scope(o),o.requestId===undefined?undefined:id(o.requestId)),
      {permission:'Destructive',options:[...selectedOptions,{flags:'--request-id <id>',description:'Retrieve the same local discard result'}]})]),
    command('save-all','Save every Ghidra context in the explicit session; outcomes are per context',({options:o},c)=>service(c).saveAll(id(o.session),o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[{flags:'--session <id>',description:'Explicit session whose contexts are saved',required:true},{flags:'--request-id <id>',description:'Retrieve the recorded session save outcomes'}]}),
    command('status','Inspect the installed runtime, or verify a selected context',({options:o},c)=>{
      if(o.session===undefined&&o.target===undefined&&runtimeStatus)return runtimeStatus(c);
      if(o.session===undefined||o.target===undefined)fail('invalid','Context status requires both --session and --target.');
      return service(c).health(scope(o));
    },{permission:Permission.ReadOnly,options:selectedOptions.map(option=>({...option,required:false}))}),
    ...(['save','close'] as const).map(name=>command(name,name==='save'?'Save private work without publication':'Save and release the owned context; reopen retains local work',({options:o},c)=>service(c).change(scope(o),name,o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[...selectedOptions,{flags:'--request-id <id>',description:'Retrieve the lifecycle outcome after a lost response'}]}))];
}
