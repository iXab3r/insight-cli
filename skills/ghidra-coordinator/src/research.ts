import type { Artifact } from './artifacts.js';
import type { GhidraContext, Scope, ScalarChange } from './workspace.js';
import { Workspace } from './workspace.js';
import { fail, id, object, text } from './model.js';
import type { ToolMode } from './contexts.js';

export interface ResearchBackend {
  open(scope: Scope, request?: string): Promise<GhidraContext>;
  call(scope: Scope, operation: string, parameters?: Record<string,unknown>): Promise<unknown>;
  saved(scope: Scope): Promise<Artifact>;
  mode(scope: Scope, mode: ToolMode): Promise<void>;
  close(scope: Scope): Promise<void>;
  dispose(): Promise<void>;
}
export function address(value: unknown): string {
  const input=text(value,128);
  const match=/^(?:([A-Za-z0-9_]+):)?(?:0x)?([a-fA-F0-9]+)$/.exec(input);
  if(!match)fail('invalid','Address must be hexadecimal with an optional address-space prefix.');
  return (match[1]?match[1]+':':'')+match[2]!.toLowerCase().replace(/^0+(?=.)/,'');
}
export const publicAddress=(value: unknown)=>{const normalized=address(value);return normalized.includes(':')?normalized:'0x'+normalized;};
export function scalarText(value: unknown): string|null {
  if(value===null||value==='')return null;
  if(typeof value!=='string'||value.length>16000||value.includes('\0'))fail('invalid','Comment must be a string of at most 16000 characters, or null.');
  return value;
}
export function commentKind(value: unknown) {
  const kind=text(value);
  if(!['eol','pre','post','plate','repeatable'].includes(kind))fail('invalid','Comment kind must be eol, pre, post, plate or repeatable.');
  return kind as 'eol'|'pre'|'post'|'plate'|'repeatable';
}
export function number(value: unknown, maximum: number, minimum=0): number {
  if(typeof value!=='number'&&(typeof value!=='string'||!/^\d+$/.test(value)))fail('invalid','Numeric argument must be an integer.');
  const result=typeof value==='number'?value:Number(value);
  if(!Number.isSafeInteger(result)||result<minimum||result>maximum)fail('invalid','Numeric argument is outside its declared range.');
  return result;
}
export function scope(options: Record<string,unknown>): Scope {return {session:id(options.session),target:id(options.target)};}
const count=(context:GhidraContext)=>context.scalars.length+context.complexChanges.length;
const revision=(value?:number)=>value===undefined?undefined:'R'+value;
function comments(value: unknown) {
  const result=object(value),observed: Record<string,string|null>={};
  for(const kind of ['eol','pre','post','plate','repeatable']) {
    if(!Object.hasOwn(result,kind))fail('partial','Comment result omitted a requested field.');
    observed[kind]=scalarText(result[kind]);
  }
  return observed;
}
function functionResult(value: unknown, selector: string) {
  const result=object(value),functions=object(result.functions),found=object(functions[selector]);
  if(Object.keys(functions).length!==1||found.error||typeof found.name!=='string'||!found.name||!found.entry_point)
    fail('partial','Function result omitted, failed or changed the requested selector.');
  return found;
}
function pageResult(value: unknown, key: string, limit: number, offset: number) {
  const result=object(value);
  if(!Array.isArray(result[key])||result[key].length>limit||!Number.isSafeInteger(result.total)||Number(result.total)<0||
    result.offset!==offset||result.limit!==limit||result.count!==undefined&&result.count!==result[key].length)
    fail('partial','Paged result has inconsistent items, counts or selectors.');
  return {result,items:result[key] as unknown[],total:Number(result.total)};
}

/** One ordered working context per tuple, shared by every transport through the Factory owner. */
export class Research {
  constructor(readonly workspace: Workspace, private readonly backend: ()=>Promise<ResearchBackend>,
    private readonly tasks=new Map<string,Promise<unknown>>()) {}
  async ordered<T>(selected: Scope, action: ()=>Promise<T>): Promise<T> {
    const key=this.workspace.context(selected).id,previous=this.tasks.get(key);
    const task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);
    this.tasks.set(key,task);
    try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}
  }
  status(selected: Scope) {
    const context=this.workspace.context(selected),model=this.workspace.model(selected.target),unresolved=this.workspace.unresolved(selected);
    return {...selected,ghidra:{state:unresolved.length?'needs_recovery':context.state,baseRevision:revision(context.baseRevision),
      sharedRevision:revision(model.sharedRevision),pendingChanges:count(context),
      conflicts:context.scalars.filter(change=>change.conflict).map(change=>({address:publicAddress(change.address),field:change.field,
        original:change.original,local:change.local,shared:change.conflict!.shared})),
      unresolvedRequests:unresolved.map(request=>({...(request.callerId?{requestId:request.callerId}:{}),operation:request.operation,state:request.state}))}};
  }
  async open(target: string, session: string|'new', settings: {autoAnalyze:boolean;language?:string;compilerSpec?:string;imageBase?:string}, callerId?: string, mode?:ToolMode) {
    // Mode belongs to the request's effective intent. It does not alter target load identity.
    const reserved=this.workspace.reserveOpen(target,session,settings,callerId,mode);
    return this.ordered(reserved.context,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(request.state==='applied')return request.result;
      if(reserved.replay&&request.state!=='accepted')return {session:reserved.context.session,target,state:request.state,
        ...(request.callerId?{requestId:request.callerId}:{})};
      this.workspace.startRequest(request.id);
      try {
        const backend=await this.backend();await backend.open(reserved.context,request.id);
        if(mode)await backend.mode(reserved.context,mode);
        const context=this.workspace.context(reserved.context);
        const result={session:context.session,target:context.target,state:'ready',baseRevision:revision(context.baseRevision),
          sharedRevision:revision(this.workspace.model(target).sharedRevision),pendingChanges:count(context)};
        this.workspace.completeSavedRequest(context,request.id,context.generation,{},result);return result;
      } catch(error) {
        this.workspace.recordRequest(request.id,'unknown',{session:reserved.context.session,target,state:'unknown'});throw error;
      }
    });
  }
  async read(selected: Scope, operation: string, parameters: Record<string,unknown>) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);return backend.call(selected,operation,parameters);
    });
  }
  async strings(selected: Scope, contains: string, limit: number, offset: number) {
    const pattern=text(contains,4096).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const value=await this.read(selected,'/search_strings',{search_term:pattern,min_length:0,offset,limit});
    const page=pageResult(value,'matches',limit,offset);
    const items=page.items.map(item=>{const row=object(item);if(typeof row.value!=='string')fail('malformed','String result lacks decoded text.');
      return {address:publicAddress(row.address),text:row.value};});
    return {...selected,items,offset,limit,total:page.total,truncated:offset+items.length<page.total};
  }
  async function(selected: Scope, at: string, decompile=false) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const value=await backend.call(selected,'/get_functions',{functions:at,fields:decompile?'entry_point,signature,decompiled_code':'entry_point,signature',include_call_context:false});
      const result=functionResult(value,at);
      if(typeof result.signature!=='string')fail('partial','Function result lacks its signature.');
      if(decompile&&typeof result.decompiled_code!=='string')fail('partial','Function decompilation did not produce text.');
      const listing=object(await backend.call(selected,'/get_comment',{address:result.entry_point}));
      return {...selected,address:publicAddress(result.entry_point),name:result.name,signature:result.signature,comments:comments(listing),
        ...(decompile?{code:result.decompiled_code,truncated:Boolean(object(result.truncation??{}).decompiled_code)}:{})};
    });
  }
  async xrefs(selected: Scope, at: string, limit: number, offset: number) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const page=pageResult(await backend.call(selected,'/get_xrefs_to',{address:at,limit,offset}),'references',limit,offset);
      const items=[];
      for(const item of page.items) {
        const row=object(item),from=address(row.from_address);
        if(typeof row.type!=='string'||!row.type)fail('partial','Reference result lacks its kind.');
        let containing;
        if(row.from_function!==undefined) {
          const found=functionResult(await backend.call(selected,'/get_functions',{functions:from,fields:'entry_point',include_call_context:false}),from);
          if(found.name!==row.from_function)fail('binding','Reference function changed during ordered inspection.');
          containing={address:publicAddress(found.entry_point),name:found.name};
        }
        items.push({from:publicAddress(from),to:publicAddress(at),kind:row.type,...(containing?{function:containing}:{})});
      }
      return {...selected,items,offset,limit,total:page.total,truncated:offset+items.length<page.total};
    });
  }
  async comment(selected: Scope, at: string, kind?: ReturnType<typeof commentKind>) {
    const result=object(await this.read(selected,'/get_comment',{address:at}));
    if(address(result.address)!==address(at))fail('partial','Comment response changed its address selector.');
    const values=comments(result),context=this.workspace.context(selected);
    const change=context.scalars.find(change=>change.address===address(at)&&change.field==='comment.'+kind);
    return {...selected,address:publicAddress(at),...(kind?{kind,text:values[kind],sharedState:change?.conflict?'conflict':change?'pending':'shared'}:{comments:values})};
  }
  async edit(selected: Scope, at: string, field: ScalarChange['field'], value: string|null, callerId?: string) {
    at=address(at);
    const reserved=this.workspace.reserveRequest(selected,field==='function.name'?'ghidra.functions.rename':'ghidra.comments.set',{address:at,field,value},callerId);
    return this.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay) {
        if(request.state==='applied')return request.result;
        if(request.state!=='accepted')return {...selected,state:request.state,...(callerId?{requestId:callerId}:{})};
      }
      const backend=await this.backend();
      // Restore before starting this mutation; other uncertain effects still block the context.
      await backend.open(selected);
      const before=this.workspace.context(selected);
      const previous=before.scalars.find(change=>change.address===at&&change.field===field);
      let observed: string|null;
      if(field==='function.name') {
        observed=String(functionResult(await backend.call(selected,'/get_functions',{functions:at,fields:'entry_point',include_call_context:false}),at).name);
      } else observed=comments(await backend.call(selected,'/get_comment',{address:at}))[field.slice(8)]!;
      if(previous?.conflict)fail('conflict','This field has an unresolved shared conflict; use an explicit resolution.');
      this.workspace.startRequest(request.id);
      try {
        const changed=object(await backend.call(selected,field==='function.name'?'/rename_function':'/set_comment',
          field==='function.name'?{old_name:at,new_name:value,strict_mode:'off'}:{address:at,type:field.slice(8),comment:value??''}));
        if(changed.status!=='success'&&changed.success!==true)fail('partial','Editing operation was not acknowledged.');
        const after=field==='function.name'?String(functionResult(await backend.call(selected,'/get_functions',{functions:at,fields:'entry_point',include_call_context:false}),at).name):
          comments(await backend.call(selected,'/get_comment',{address:at}))[field.slice(8)]!;
        if(after!==value)fail('partial','Editing readback does not match the requested value.');
        const snapshot=await backend.saved(selected);
        const original=previous?previous.original:observed;
        const scalars=before.scalars.filter(change=>change.address!==at||change.field!==field);
        if(value!==original)scalars.push({address:at,field,original,local:value});
        const complexChanges=[...before.complexChanges];
        if(previous&&previous.local!==observed&&!complexChanges.includes(request.id))complexChanges.push(request.id);
        const result={...selected,state:'applied',sharedState:scalars.length||complexChanges.length?'pending':'shared',pendingChanges:scalars.length+complexChanges.length};
        this.workspace.completeSavedRequest(selected,request.id,before.generation,{workingSnapshot:snapshot,scalars,complexChanges},result);
        return result;
      } catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown'});throw error;}
    });
  }
}
