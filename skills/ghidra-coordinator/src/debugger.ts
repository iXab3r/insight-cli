import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {resolve} from 'node:path';
import {Workspace,type Scope,type DebuggerState} from './workspace.js';
import {Research,scope,address,number,type ResearchBackend} from './research.js';
import {id,text,object,fail} from './model.js';
import {selectedOptions} from './arguments.js';
import {debuggerResult,debuggerProgramMetadata as metadata} from './debugger-results.js';
import {setTimeout as delay} from 'node:timers/promises';
import {randomUUID} from 'node:crypto';
import type {Artifact} from './artifacts.js';
const lists=['launch_offers','modules','list_breakpoints','stack_trace'];
export class Debugger {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>){}
  private async prepared(selected:Scope,trace?:string,reading=false){
    const backend=await this.backend(),unresolved=this.workspace.unresolved(selected);
    if(!backend.debuggerCall||!backend.debuggerStart||!backend.debuggerSaved)fail('configuration','Selected backend lacks debugger support.');
    if(unresolved.length){if(!reading||unresolved.some(request=>object(request.execution??{}).kind!=='debugger'))fail('blocked','Selected context retains an unresolved operation.');}
    else{await backend.open(selected);await backend.mode(selected,'gui');await backend.debuggerStart(selected);}
    if(trace){if(!backend.debuggerSelect||!this.workspace.context(selected).debugger?.traces.some(item=>item.id===trace))fail('notFound','Trace is not saved in the selected context.');await backend.debuggerSelect(selected,trace);}
    return backend as ResearchBackend&Required<Pick<ResearchBackend,'debuggerCall'|'debuggerStart'|'debuggerSaved'>>;
  }
  async read(selected:Scope,operation:string,p:Record<string,unknown>,trace?:string){return this.research.ordered(selected,async()=>{
    const backend=await this.prepared(selected,trace,true);
    let value:unknown;
    if(operation!=='traces')value=debuggerResult(operation,p,await backend.debuggerCall(selected,operation,Object.fromEntries(Object.entries(p).filter(([key])=>!['limit','offset'].includes(key)))));
    const saved=await backend.debuggerSaved(selected),current=this.workspace.context(selected),snapshot=await backend.saved(selected);
    const changed=current.workingSnapshot&&await metadata(backend,current.workingSnapshot)!==await metadata(backend,snapshot);
    const complexChanges=changed?[...current.complexChanges,'debugger-metadata-'+randomUUID()]:current.complexChanges;
    this.workspace.saveContext(selected,current.generation,{debugger:saved,workingSnapshot:snapshot,complexChanges});
    if(operation==='traces')value=saved.traces.map(row=>({trace:row.id,name:this.workspace.target(selected.target).name,current:row.id===saved.active,snap:row.snap,module_count:row.modules,thread_count:row.threads,connected:row.connected}));
    if(operation==='traces'||lists.includes(operation)){
      const rows=value as unknown[],offset=Number(p.offset??0),limit=Number(p.limit??50);value={items:rows.slice(offset,offset+limit),total:rows.length,offset,limit,truncated:offset+limit<rows.length};
    }
    return {...selected,...(saved.active?{trace:saved.active}:{}),connectionState:saved.connected?'connected':saved.traces.length?'disconnected':'idle',pendingChanges:current.scalars.length+complexChanges.length,value};
  });}
  async change(selected:Scope,operation:string,p:Record<string,unknown>,callerId?:string,trace?:string){
    const reserved=this.workspace.reserveRequest(selected,'ghidra.debugger.'+operation,{...p,...(trace?{trace}:{})},callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);if(reserved.replay&&request.state!=='accepted'){if(request.state==='applied')return request.result;
        const result=object(request.result??{});if(request.state==='failed'&&result.reason==='disconnected')fail('disconnected','Selected trace has no live target.',result);
        if(request.state==='failed'&&result.reason==='busy')fail('busy','This context already has a live debug target; use another session for another process.',result);
        fail('unknown','Debugger action is retained and is not repeated.',request.result);}
      const backend=await this.prepared(selected,trace),context=this.workspace.context(selected);
      if(operation==='launch'&&(await backend.debuggerSaved(selected)).connected){const result={...selected,state:'not_started',reason:'busy'};this.workspace.recordRequest(request.id,'failed',result);fail('busy','This context already has a live debug target; use another session for another process.',result);}
      const before=debuggerResult('status',{},await backend.debuggerCall(selected,'status'));
      if(operation!=='launch'&&object(before).target_connected!==true){const result={...selected,state:'not_started',reason:'disconnected'};this.workspace.recordRequest(request.id,'failed',result);fail('disconnected','Selected trace has no live target.',result);}
      const beforeMetadata=context.workingSnapshot?await metadata(backend,context.workingSnapshot):undefined;
      this.workspace.startRequest(request.id,{kind:'debugger',operation,generation:context.generation,before});let saved:DebuggerState|undefined,savedSnapshot:Artifact|undefined,metadataChanged=false;
      try{
        let raw:unknown;
        if(operation==='launch'){if(!backend.debuggerLaunch)fail('configuration','Owned target staging is unavailable.');raw=await backend.debuggerLaunch(selected,p,request.id);}
        else raw=await backend.debuggerCall(selected,operation,p);
        const value=debuggerResult(operation,p,raw);
        if(['resume','interrupt','step'].includes(operation)){
          const wanted=operation==='resume'?'RUNNING':'STOPPED';let observed=false;
          for(let attempt=0;attempt<40;attempt++){const status=object(debuggerResult('status',{},await backend.debuggerCall(selected,'status')));
            if(status.execution_state===wanted||operation==='resume'&&status.execution_state==='STOPPED'&&BigInt(String(status.snap??0))>BigInt(String(object(before).snap??0))){observed=true;break;}await delay(100);}
          if(!observed)fail('partial','Debugger execution state did not settle after the action.');
        }
        if(operation==='set_breakpoint'||operation==='remove_breakpoint'){
          let observed=false;for(let attempt=0;attempt<50;attempt++){
            const rows=debuggerResult('list_breakpoints',{},await backend.debuggerCall(selected,'list_breakpoints')) as Record<string,unknown>[];
            if(rows.some(row=>address(row.address)===address(p.address)&&Number(row.trace_location_count)>0)===(operation==='set_breakpoint')){observed=true;break;}await delay(100);
          }
          if(!observed)fail('partial','Breakpoint inventory did not verify the action.');
        }
        saved=await backend.debuggerSaved(selected);savedSnapshot=await backend.saved(selected);
        metadataChanged=beforeMetadata!==undefined&&beforeMetadata!==await metadata(backend,savedSnapshot);
        const complexChanges=metadataChanged?[...context.complexChanges,request.id]:context.complexChanges;
        const result={...selected,state:'applied',...(saved.active?{trace:saved.active}:{}),pendingChanges:context.scalars.length+complexChanges.length,sharedState:context.scalars.length||complexChanges.length?'pending':'shared',value};
        this.workspace.completeSavedRequest(selected,request.id,context.generation,{debugger:saved,workingSnapshot:savedSnapshot,complexChanges},result);return result;
      }catch(error){try{saved??=await backend.debuggerSaved(selected);}catch{}
        try{savedSnapshot??=await backend.saved(selected);metadataChanged=beforeMetadata!==undefined&&beforeMetadata!==await metadata(backend,savedSnapshot);}catch{}
        this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',operation,...(saved?{savedDebugger:saved}:{}),...(savedSnapshot?{savedSnapshot,metadataChanged}:{})});throw error;}
    });
  }
}
export function debuggerCommands(service:(c:CommandContext)=>Debugger):CommandDefinition[]{
  const leaves:CommandDefinition[]=[],request={flags:'--request-id <id>',description:'Retrieve the outcome without repeating execution'},trace={flags:'--trace <id>',description:'Select a saved trace within this context'};
  const operations=['launch','launch_offers','status','traces','resume','interrupt','step','set_breakpoint','remove_breakpoint','list_breakpoints','registers','read_memory','stack_trace','modules','static_to_dynamic','dynamic_to_static'];
  for(const operation of operations){const changing=['launch','resume','interrupt','step','set_breakpoint','remove_breakpoint'].includes(operation),at=['set_breakpoint','remove_breakpoint','read_memory','static_to_dynamic','dynamic_to_static'].includes(operation),paged=operation==='traces'||lists.includes(operation);
    const options=[...selectedOptions,...(operation==='launch'?[]:[trace]),...(at?[{flags:'--address <address>',description:'Explicit static or trace address',required:true}]:[]),
      ...(operation==='read_memory'?[{flags:'--size <bytes>',description:'Read 1–4096 bytes',defaultValue:64}]:[]),...(operation==='stack_trace'?[{flags:'--depth <count>',description:'Maximum frames 1–1000',defaultValue:20}]:[]),
      ...(paged?[{flags:'--limit <count>',description:'Page size 1–100',defaultValue:50},{flags:'--offset <count>',description:'Page offset',defaultValue:0}]:[]),
      ...(operation==='step'?[{flags:'--kind <kind>',description:'into, over or out',defaultValue:'into'}]:[]),
      ...(operation==='launch'?[{flags:'--args <text>',description:'Target command-line arguments',defaultValue:''},{flags:'--cwd <directory>',description:'Target working directory (default owned run folder)'},
        {flags:'--offer <name>',description:'Launch offer title or configuration name',defaultValue:process.platform==='win32'?'dbgeng':process.platform==='darwin'?'lldb':'gdb'},{flags:'--timeout-seconds <count>',description:'Launch wait 1–300 seconds',defaultValue:60}]:[]),...(changing?[request]:[])];
    leaves.push(command(operation.replaceAll('_','-'),'Use the selected context debugger',({options:o},c)=>{
      const p:Record<string,unknown>={};if(at)p.address=address(o.address);if(paged){p.limit=number(o.limit,100,1);p.offset=number(o.offset,2147483647);}
      if(operation==='read_memory')p.size=number(o.size,4096,1);if(operation==='stack_trace')p.depth=number(o.depth,1000,1);
      if(operation==='step'){p.kind=text(o.kind);if(!['into','over','out'].includes(String(p.kind)))fail('invalid','Step kind must be into, over or out.');}
      if(operation==='launch'){if(typeof o.args!=='string'||o.args.length>8192||o.args.includes('\0'))fail('invalid','Arguments must be bounded text.');p.args=o.args;p.offer=text(o.offer,512);p.timeout_seconds=number(o.timeoutSeconds,300,1);if(o.cwd){p.cwd=resolve(c.cwd,text(o.cwd,4096));if(/[\r\n\0]/.test(String(p.cwd)))fail('invalid','Debugger working directory must be a single filesystem path.');}}
      const selected=scope(o),selectedTrace=o.trace===undefined?undefined:id(o.trace);
      return changing?service(c).change(selected,operation,p,o.requestId===undefined?undefined:id(o.requestId),selectedTrace):service(c).read(selected,operation,p,selectedTrace);
    },{permission:operation==='remove_breakpoint'?'Destructive':changing?Permission.Update:Permission.ReadOnly,options}));
  }
  return [command('debugger','Debug the selected immutable target in an owned GUI',leaves)];
}
