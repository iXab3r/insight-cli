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
const liveWrites=new Set(['write_memory','write_register']);
function traceInteger(value:unknown){const encoded=text(String(value),32);if(!/^-?\d+$/.test(encoded))fail('invalid','Trace positions require exact signed decimal integers.');const n=BigInt(encoded);
  if(n<-(1n<<63n)||n>=(1n<<63n))fail('invalid','Trace position exceeds signed 64-bit range.');return n.toString();}
export function debuggerWriteInputs(operation:string,p:Record<string,unknown>){
  if(operation==='write_memory'){
    for(const key of ['expect_hex','bytes_hex'])if(typeof p[key]!=='string'||! /^(?:[a-f0-9]{2}){1,4096}$/i.test(p[key] as string))fail('invalid','Live memory requires 1–4096 complete hex bytes.');
    if(String(p.expect_hex).length!==String(p.bytes_hex).length)fail('invalid','Live memory expected/replacement lengths must match.');
  }
  if(operation==='write_register')for(const key of ['expect_value','value'])if(! /^(?:0x)?[a-f0-9]{1,128}$/i.test(String(p[key])))fail('invalid','Register values must be exact unsigned hex integers.');
}
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
        if(request.state==='failed'&&result.reason==='native_precondition')fail('rejected','The native live precondition failed; the target write was not started.',result);
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
        if(liveWrites.has(operation)&&object(raw).status==='rejected'&&object(raw).target_effect_started===false){
          const result={...selected,state:'not_started',reason:'native_precondition',value:raw};this.workspace.recordRequest(request.id,'failed',result);
          fail('rejected','Native live preconditions rejected the write before target dispatch.',result);
        }
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
      }catch(error){if(this.workspace.request(request.id).state==='failed')throw error;
        try{saved??=await backend.debuggerSaved(selected);}catch{}
        try{savedSnapshot??=await backend.saved(selected);metadataChanged=beforeMetadata!==undefined&&beforeMetadata!==await metadata(backend,savedSnapshot);}catch{}
        this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',operation,...(saved?{savedDebugger:saved}:{}),...(savedSnapshot?{savedSnapshot,metadataChanged}:{})});throw error;}
    });
  }
}
export function debuggerCommands(service:(c:CommandContext)=>Debugger):CommandDefinition[]{
  const leaves:CommandDefinition[]=[],request={flags:'--request-id <id>',description:'Retrieve the outcome without repeating execution'},trace={flags:'--trace <id>',description:'Select a saved trace within this context'};
  const operations=['launch','launch_offers','status','traces','resume','interrupt','step','set_breakpoint','remove_breakpoint','list_breakpoints','registers','read_memory','stack_trace','modules','static_to_dynamic','dynamic_to_static','write_memory','write_register','timeline','objects','object_values','schedule'];
  for(const operation of operations){const changing=['launch','resume','interrupt','step','set_breakpoint','remove_breakpoint'].includes(operation)||liveWrites.has(operation),at=['set_breakpoint','remove_breakpoint','read_memory','static_to_dynamic','dynamic_to_static','write_memory'].includes(operation),paged=operation==='traces'||lists.includes(operation);
    const options=[...selectedOptions,...(operation==='launch'?[]:[trace]),...(at?[{flags:'--address <address>',description:'Explicit static or trace address',required:true}]:[]),
      ...(operation==='read_memory'?[{flags:'--size <bytes>',description:'Read 1–4096 bytes',defaultValue:64}]:[]),...(operation==='stack_trace'?[{flags:'--depth <count>',description:'Maximum frames 1–1000',defaultValue:20}]:[]),
      ...(operation==='write_memory'?[{flags:'--expect-hex <hex>',description:'Exact current bytes before stopped-target write',required:true},{flags:'--bytes-hex <hex>',description:'Equal-length replacement bytes, at most 4096',required:true}]:[]),
      ...(operation==='write_register'?[{flags:'--register <name>',description:'Exact target platform register',required:true},{flags:'--expect-value <hex>',description:'Exact current unsigned hex value',required:true},{flags:'--value <hex>',description:'Replacement unsigned hex value within native register width',required:true}]:[]),
      ...(['timeline','objects'].includes(operation)?[{flags:'--limit <count>',description:'Maximum returned rows 1–1000',defaultValue:100}]:[]),
      ...(operation==='timeline'?[{flags:'--before-snap <integer>',description:'Latest included snapshot key; result gives next-before-snap'}]:[]),
      ...(operation==='objects'?[{flags:'--path-prefix <text>',description:'Literal canonical path prefix; @target hides the owned staging root',defaultValue:''},{flags:'--max-scan <count>',description:'Maximum visited objects 1–200000',defaultValue:10000}]:[]),
      ...(['objects','object_values'].includes(operation)?[{flags:'--snap <integer>',description:'Snapshot key (default selected time)'}]:[]),
      ...(operation==='object_values'?[{flags:'--object-id <integer>',description:'Object ID returned by objects; scoped to the selected trace',required:true},{flags:'--key <name>',description:'Exact native attribute/element key',required:true},
        {flags:'--from-snap <integer>',description:'Start of a bounded history range'},{flags:'--to-snap <integer>',description:'End of a range of at most 1000 snaps'}]:[]),
      ...(operation==='schedule'?[{flags:'--schedule <time>',description:'Parse and validate a native time schedule without executing it',required:true}]:[]),
      ...(paged?[{flags:'--limit <count>',description:'Page size 1–100',defaultValue:50},{flags:'--offset <count>',description:'Page offset',defaultValue:0}]:[]),
      ...(operation==='step'?[{flags:'--kind <kind>',description:'into, over or out',defaultValue:'into'}]:[]),
      ...(operation==='launch'?[{flags:'--args <text>',description:'Target command-line arguments',defaultValue:''},{flags:'--cwd <directory>',description:'Target working directory (default owned run folder)'},
        {flags:'--offer <name>',description:'Launch offer title or configuration name',defaultValue:process.platform==='win32'?'dbgeng':process.platform==='darwin'?'lldb':'gdb'},{flags:'--timeout-seconds <count>',description:'Launch wait 1–300 seconds',defaultValue:60}]:[]),...(changing?[request]:[])];
    leaves.push(command(operation.replaceAll('_','-'),'Use the selected context debugger',({options:o},c)=>{
      const p:Record<string,unknown>={};if(at)p.address=address(o.address);if(paged){p.limit=number(o.limit,100,1);p.offset=number(o.offset,2147483647);}
      if(operation==='read_memory')p.size=number(o.size,4096,1);if(operation==='stack_trace')p.depth=number(o.depth,1000,1);
      if(operation==='write_memory'){p.expect_hex=text(o.expectHex,8192);p.bytes_hex=text(o.bytesHex,8192);}
      if(operation==='write_register'){p.register=text(o.register,128);p.expect_value=text(o.expectValue,130);p.value=text(o.value,130);}
      if(liveWrites.has(operation))debuggerWriteInputs(operation,p);
      for(const [key,publicKey]of [['snap','snap'],['before_snap','beforeSnap'],['from_snap','fromSnap'],['to_snap','toSnap']] as const)if(o[publicKey]!==undefined)p[key]=traceInteger(o[publicKey]);
      if(['timeline','objects'].includes(operation))p.limit=number(o.limit,1000,1);
      if(operation==='objects'){const prefix=typeof o.pathPrefix==='string'?o.pathPrefix:'';if(prefix.length>4096||prefix.includes('\0'))fail('invalid','Trace path prefix exceeds its text bound.');p.path_prefix=prefix;p.max_scan=number(o.maxScan,200000,1);}
      if(operation==='object_values'){p.object_id=traceInteger(o.objectId);if(BigInt(String(p.object_id))<0n)fail('invalid','Object ID must be nonnegative.');p.key=text(o.key,1024);
        if(p.from_snap!==undefined&&p.to_snap!==undefined&&(BigInt(String(p.to_snap))<BigInt(String(p.from_snap))||BigInt(String(p.to_snap))-BigInt(String(p.from_snap))>999n))fail('invalid','Trace value history is bounded to 1000 snaps.');}
      if(operation==='schedule')p.schedule=text(o.schedule,4096);
      if(operation==='step'){p.kind=text(o.kind);if(!['into','over','out'].includes(String(p.kind)))fail('invalid','Step kind must be into, over or out.');}
      if(operation==='launch'){if(typeof o.args!=='string'||o.args.length>8192||o.args.includes('\0'))fail('invalid','Arguments must be bounded text.');p.args=o.args;p.offer=text(o.offer,512);p.timeout_seconds=number(o.timeoutSeconds,300,1);if(o.cwd){p.cwd=resolve(c.cwd,text(o.cwd,4096));if(/[\r\n\0]/.test(String(p.cwd)))fail('invalid','Debugger working directory must be a single filesystem path.');}}
      const selected=scope(o),selectedTrace=o.trace===undefined?undefined:id(o.trace);
      return changing?service(c).change(selected,operation,p,o.requestId===undefined?undefined:id(o.requestId),selectedTrace):service(c).read(selected,operation,p,selectedTrace);
    },{permission:operation==='remove_breakpoint'||liveWrites.has(operation)?'Destructive':changing?Permission.Update:Permission.ReadOnly,options}));
  }
  return [command('debugger','Debug the selected immutable target in an owned GUI',leaves)];
}
