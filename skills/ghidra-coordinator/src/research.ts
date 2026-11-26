import {textWindow} from './text-window.js';
import {functionResult,functionFailure} from './function-results.js';
import {inspectFunctions,type FunctionInspectionOptions} from './function-inspection.js';
import {entryRequest} from './function-entries.js';
import {inspectAnchors,type AnchorRequest} from './string-anchors.js';
import type { Artifact } from './artifacts.js';
import type { GhidraContext, Scope, ScalarChange, Publication, ResearchRequest,DebuggerState,GhidraLoadSettings,NativeCheckout } from './workspace.js';
import { Workspace } from './workspace.js';
import { fail, id, object, text,digest,fieldKey } from './model.js';
import type { ToolMode } from './contexts.js';
import type {ScriptPage} from './scripts.js';
import {verifyMutation} from './mutation-effects.js';
import {transferResult} from './cross-results.js';
import {CliError} from '@eyeauras/cli-factory';
import {timed} from './internal-timing.js';
import {navigationResult} from './context-diagnostics.js';
import {inspectCodeReferences,type ReferenceRequest} from './code-references.js';

export interface ResearchBackend {
  snapshotFile?(snapshot:Artifact):Promise<string>;
  readonly nativeEngine?:'native-checkout-v1';
  migrate?(target:string|undefined,dryRun:boolean):Promise<unknown>;
  collect?(dryRun:boolean):Promise<unknown>;
  releaseUnchanged?(scope:Scope):Promise<boolean>;
  detachedStopped?(scope:Scope):Promise<boolean>;
  /** Proves that the checkout's project is gone and nothing of it runs; returns the receipt it proved. */
  missingCheckout?(scope:Scope):Promise<NativeCheckout>;
  /** Ends exactly that checkout on its server, or with check only proves that it could. Repeating it is safe. */
  abandonMissing?(scope:Scope,check:boolean):Promise<void>;
  updateNative?(scope:Scope,request:string):Promise<{state:'ready'|'empty';revision:number;snapshot:Artifact;sharedSnapshot:Artifact;receivedChanges:number;nativeMergeInvocations:number}|{state:'conflict';revision:number;conflict:string}>;
  recoverUpdate?(scope:Scope,request:string):Promise<{state:'ready'|'empty';revision:number;snapshot:Artifact;sharedSnapshot:Artifact;receivedChanges:number;nativeMergeInvocations:number}|{state:'conflict';revision:number;conflict:string}|{state:'unknown'}>;
  publishNative?(publication:Publication):Promise<{state:'published';revision:number;snapshot?:Artifact}|{state:'conflict';applied:0;conflict?:string}>;
  dropNative?(scope:Scope,request?:string):Promise<void>;
  finishEmptyNative?(scope:Scope,request?:string):Promise<void>;
  recoverEmptyNative?(scope:Scope,request:string):Promise<{state:'verified';revision:number}|{state:'unknown'}>;
  discardNative?(scope:Scope,request:string):Promise<{baseRevision:number;retainedKeepFile:string}>;
  recoverDiscardNative?(scope:Scope,request:string,original:NativeCheckout):Promise<{state:'verified';baseRevision:number;retainedKeepFile:string}|{state:'unknown'}>;
  inlineScript?(scope:Scope,parameters:Record<string,unknown>,requestId:string):Promise<{response:Record<string,unknown>;safe:boolean}>;
  observation?(scope:Scope):Promise<unknown>;
  inspectObservation?(scope:Scope):Promise<unknown>;
  sdkFile?(operation:string,p:Record<string,unknown>):Promise<Record<string,unknown>>;
  archivePayloads?(scope:Scope,p:Record<string,unknown>):Promise<unknown>;
  debuggerStart?(scope:Scope):Promise<void>;
  debuggerCall?(scope:Scope,operation:string,p?:Record<string,unknown>):Promise<unknown>;
  debuggerSaved?(scope:Scope):Promise<DebuggerState>;
  debuggerSelect?(scope:Scope,trace:string):Promise<void>;
  debuggerStop?(scope:Scope):Promise<void>;
  debuggerLaunch?(scope:Scope,p:Record<string,unknown>,request:string):Promise<unknown>;
  ui?(scope:Scope,operation:string,parameters:Record<string,unknown>):Promise<Record<string,unknown>>;
  project?(operation:string,parameters:Record<string,unknown>):Promise<Record<string,unknown>>;
  projectOutcome?(requestId:string,expected:Record<string,unknown>):Promise<Record<string,unknown>|undefined>;
  administration?(operation:string,parameters:Record<string,unknown>):Promise<Record<string,unknown>>;
  open(scope: Scope, request?: string): Promise<GhidraContext>;
  call(scope: Scope, operation: string, parameters?: Record<string,unknown>): Promise<unknown>;
  saved(scope: Scope): Promise<Artifact>;
  mode(scope: Scope, mode: ToolMode): Promise<void>;
  close(scope: Scope): Promise<void>;
  closed?(scope:Scope):Promise<boolean>;
  dispose(): Promise<void>;
  latest?(target:string):Promise<{revision:number;snapshot:Artifact}>;
  fields?(snapshot:Artifact,changes:Pick<ScalarChange,'address'|'field'>[]):Promise<Record<string,{value:string|null;dependency:string;exists:boolean}>>;
  recover?(publication:Publication):Promise<{state:'verified';revision:number;snapshot?:Artifact}|{state:'unknown'}>;
  recoverModel?(target:string):Promise<boolean>;
  scripts?(scope:Scope,filter:string,limit:number,offset:number):Promise<ScriptPage>;
  inspect?(snapshot:Artifact,parameters:Record<string,unknown>):Promise<Record<string,unknown>>;
  pair?(selected:Scope,other:Scope,snapshot:Artifact,operation:string,parameters:Record<string,unknown>):Promise<unknown>;
  transfer?(selected:Scope,source:Artifact,dryRun:boolean):Promise<unknown>;
  transferCheck?(selected:Scope,source:Artifact,candidate:Artifact):Promise<unknown>;
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
  private retainedDisposal(selected:Scope,request:string,error:unknown){
    if(!error||typeof error!=='object')return;
    const failure=error as {code?:string;result?:{state?:string;retention?:{schema?:number;source?:string;checkout?:unknown;request?:string;snapshot?:Artifact}}},proof=failure.result?.retention,current=this.workspace.context(selected),outcome=this.workspace.request(request);
    if(failure.code==='coordinator.conflict'&&failure.result?.state==='retained'&&proof?.schema===1&&proof.source==='native-release-status'&&
      proof.request===request&&proof.snapshot?.id===current.workingSnapshot?.id&&outcome.context===current.id&&outcome.state==='failed'&&digest(outcome.result)===digest(failure.result)&&
      proof.checkout&&current.nativeCheckout?.state==='active'&&digest(proof.checkout)===digest(current.nativeCheckout))return failure.result;
  }
  async ordered<T>(selected: Scope, action: ()=>Promise<T>): Promise<T> {
    const key=this.workspace.context(selected).id,previous=this.tasks.get(key);
    const task=timed('facade.queue','research',async()=>{await previous?.catch(()=>{});}).then(action);
    this.tasks.set(key,task);
    try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}
  }
  async boundary<T>(selected:Scope,action:()=>Promise<T>):Promise<T>{
    const key='command:'+this.workspace.context(selected).id,previous=this.tasks.get(key),task=timed('facade.queue','command',async()=>{await previous?.catch(()=>{});}).then(action);
    this.tasks.set(key,task);try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}
  }
  status(selected: Scope) {
    const context=this.workspace.context(selected),model=this.workspace.model(selected.target),unresolved=this.workspace.unresolved(selected);
    const external=this.workspace.unresolvedSessionAdministration(selected.session,selected.target);
    return {...selected,externalRequests:external.map(request=>({...(request.callerId?{requestId:request.callerId}:{}),operation:request.operation,state:request.state})),externalRequestsTruncated:external.length===100,
      ghidra:{syncPolicy:context.syncPolicy??{publish:'manual',refresh:'manual'},state:unresolved.length?'needs_recovery':context.state,baseRevision:revision(context.baseRevision),
      engine:context.nativeCheckout?'ghidra-native':'uninitialized-or-legacy',...(context.nativeCheckout?{checkout:{id:context.nativeCheckout.checkoutId,fileId:context.nativeCheckout.fileId,baseRevision:revision(context.nativeCheckout.baseVersion),state:context.nativeCheckout.state}}:{}),
      sharedRevision:revision(model.sharedRevision),pendingChanges:count(context),
      mergeState:model.state==='unknown'?'unknown':'idle',
      conflicts:[...(context.nativeCheckout?.conflict?[{engine:'ghidra-native',...context.nativeCheckout.conflict}]:[]),...context.scalars.filter(change=>change.conflict).map(change=>({address:publicAddress(change.address),field:change.field,
        original:change.original,local:change.local,shared:change.conflict!.shared}))],
      unresolvedRequests:unresolved.map(request=>({id:request.id,...(request.result?{detail:request.result}:{}),...(request.callerId?{requestId:request.callerId}:{}),operation:request.operation,state:request.state}))}};
  }
  async abandon(selected:Scope,requestId:string,acknowledged:boolean) {
    return this.ordered(selected,async()=>{
      if(!acknowledged)fail('invalid','Explicit --acknowledge-unknown-effects is required.');
      const context=this.workspace.context(selected),requests=this.workspace.unresolved(selected);
      if(context.nativeCheckout)fail('unsupported','A native unknown program outcome must be reconciled on its original project; detached snapshot rollback is disabled.');
      const request=this.workspace.scopedRequest(selected,requestId);
      if(request?.state==='failed'&&object(request.result??{}).state==='abandoned')return request.result;
      if(!request||!['running','unknown'].includes(request.state)||requests.length!==1||object(request.execution??{}).kind!=='program')fail('blocked','Abandon requires exactly one unresolved private program operation.');
      if(this.workspace.activePublication(selected.target)||context.debugger?.connected)fail('blocked','Publication or a live debugger prevents private abandonment.');
      const execution=object(request.execution!),snapshot=context.workingSnapshot;
      if(!snapshot||execution.generation!==context.generation||object(execution.workingSnapshot).id!==snapshot.id)fail('binding','The previous saved program view no longer matches the attempt.');
      await this.workspace.artifacts.verify(snapshot);
      const backend=await this.backend();
      if(!backend.closed||!await backend.closed(selected))fail('busy','The original native worker must be stopped before abandoning its uncertain program attempt.');
      return this.workspace.abandonProgramRequest(selected,request.id,context.generation);
    });
  }
  async open(target: string, session: string|'new', settings: GhidraLoadSettings, callerId?: string, mode?:ToolMode) {
    // Mode belongs to the request's effective intent. It does not alter target load identity.
    const reserved=this.workspace.reserveOpen(target,session,settings,callerId,mode);
    // Older reconciliation accidentally persisted internal context fields in ready results.
    // Project the public envelope without rewriting an immutable historical request record.
    const opened=(value:unknown)=>{const result=object(value);return Object.fromEntries(['session','target','state','baseRevision','sharedRevision','pendingChanges'].filter(key=>Object.hasOwn(result,key)).map(key=>[key,result[key]]));};
    const retained=(state:string)=>({session:reserved.context.session,target,state,...(callerId?{requestId:callerId}:{})});
    const next=[['sessions','status',reserved.context.session,'--target',target],['ghidra','open','--session',reserved.context.session,'--target',target]];
    const openingFailure=(error:unknown,state:string)=>new CliError(error instanceof CliError?error.message:'Ghidra open did not complete; the context is retained for reconciliation.',{
      code:error instanceof CliError?error.code:'coordinator.unknown',result:{...retained(state),...(error instanceof CliError&&error.result&&typeof error.result==='object'?{detail:error.result}:{})},next:error instanceof CliError&&error.code==='coordinator.migration'?[['ghidra','migrate','--target',target,'--dry-run'],['ghidra','migrate','--target',target],...next]:next});
    return this.ordered(reserved.context,async()=>{
      if(this.workspace.request(reserved.request.id).state==='applied')return opened(this.workspace.request(reserved.request.id).result);
      let backend:ResearchBackend;
      try{backend=await this.backend();await this.sharedOrder(target,()=>this.reconcile({session:reserved.context.session,target},backend,true));}
      catch(error){
        const request=this.workspace.request(reserved.request.id);
        if(request.state==='accepted')this.workspace.recordRequest(request.id,'failed',retained('blocked'));
        throw openingFailure(error,this.workspace.request(request.id).state);
      }
      const request=this.workspace.request(reserved.request.id);
      if(request.state==='applied')return opened(request.result);
      if(reserved.replay&&request.state!=='accepted')throw new CliError('This open retains an unproved outcome; inspect the retained context before continuing.',{code:'coordinator.unknown',result:retained(request.state),next});
      const unresolved=this.workspace.unresolved(reserved.context).filter(other=>other.id!==request.id);
      if(unresolved.length) {
        const result={session:reserved.context.session,target,state:'blocked'};
        this.workspace.recordRequest(request.id,'failed',result);
        const close=unresolved.find(other=>other.operation==='ghidra.close');
        throw new CliError('This context retains an unproved effect; continuation did not start a second operation.',{
          code:'coordinator.blocked',result,next:close?[['ghidra','close','--session',reserved.context.session,'--target',target,'--request-id',close.callerId??close.id]]:next});
      }
      this.workspace.startRequest(request.id);
      try {
        await backend.open(reserved.context,request.id);
        if(mode)await backend.mode(reserved.context,mode);
        const context=this.workspace.context(reserved.context);
        const result={session:context.session,target:context.target,state:'ready',baseRevision:revision(context.baseRevision),
          sharedRevision:revision(this.workspace.model(target).sharedRevision),pendingChanges:count(context)};
        this.workspace.completeSavedRequest(context,request.id,context.generation,{},result);return result;
      } catch(error) {
        const migration=error instanceof CliError&&error.code==='coordinator.migration';
        const result={...retained(migration?'blocked':'unknown'),...(migration?{reason:'explicit_native_migration_required',detail:error.message}:{})};this.workspace.recordRequest(request.id,migration?'failed':'unknown',result);
        throw openingFailure(error,migration?'blocked':'unknown');
      }
    });
  }
  async read(selected: Scope, operation: string, parameters: Record<string,unknown>) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);return backend.call(selected,operation,parameters);
    });
  }
  async scripts(selected:Scope,filter:string,limit:number,offset:number) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      if(!backend.scripts)fail('configuration','Selected backend does not provide the configured script inventory.');
      return backend.scripts(selected,filter,limit,offset);
    });
  }
  async paired<T>(selected:Scope,other:Scope,action:()=>Promise<T>):Promise<T> {
    const scopes=[selected,other].sort((a,b)=>this.workspace.context(a).id.localeCompare(this.workspace.context(b).id));
    if(this.workspace.context(selected).id===this.workspace.context(other).id)return this.ordered(selected,action);
    return this.ordered(scopes[0]!,()=>this.ordered(scopes[1]!,action));
  }
  async crossRead(selected:Scope,other:Scope,operation:string,parameters:Record<string,unknown>) {
    return this.paired(selected,other,async()=>{
      const backend=await this.backend();await backend.open(selected);await backend.open(other);
      if(!backend.pair)fail('configuration','Selected backend does not support explicit cross-target comparisons.');
      return backend.pair(selected,other,await backend.saved(other),operation,parameters);
    });
  }
  private async savedScalars(context:GhidraContext,backend:ResearchBackend,snapshot:Artifact) {
    if(!context.scalars.length)return context.scalars;
    if(!backend.fields)fail('configuration','Tracked scalar fields require saved-state inspection.');
    const fields=await backend.fields(snapshot,context.scalars);
    return context.scalars.flatMap(change=>{
      const observed=fields[fieldKey(change)];if(!observed)fail('partial','Saved inspection omitted a tracked scalar field.');
      if(!observed.exists)return [{...change,local:null,removed:true as const}];
      const {removed,...previous}=change;
      if(observed.value===previous.original&&!previous.conflict)return [];
      return [{...previous,local:observed.value}];
    });
  }
  async transfer(selected:Scope,source:Scope,dryRun:boolean,callerId?:string) {
    if(this.workspace.context(selected).id===this.workspace.context(source).id)fail('invalid','Documentation source and destination contexts must differ.');
    const reserved=this.workspace.reserveRequest(selected,'/merge_program_documentation',{source,dryRun},callerId);
    return this.paired(selected,source,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted') {
        if(request.state==='applied')return request.result;
        fail('unknown','This documentation transfer retains an unproved outcome and is not repeated.',request.result);
      }
      const backend=await this.backend();await backend.open(source);const sourceSnapshot=await backend.saved(source);
      await backend.open(selected);if(!backend.transfer||!backend.transferCheck)fail('configuration','Selected backend cannot verify documentation transfer.');
      const context=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:'transfer',generation:context.generation,workingSnapshot:context.workingSnapshot,source,sourceSnapshot,dryRun});
      try {
        const value=transferResult(await backend.transfer(selected,sourceSnapshot,dryRun),dryRun);
        const snapshot=await backend.saved(selected);
        if(!dryRun&&transferResult(await backend.transferCheck(selected,sourceSnapshot,snapshot),true).total!==0)
          fail('partial','Saved destination retains untransferred documentation.');
        const scalars=dryRun?context.scalars:await this.savedScalars(context,backend,snapshot);
        const complexChanges=dryRun||value.total===0?context.complexChanges:[...context.complexChanges,request.id];
        const result={...selected,source,state:dryRun?'preview':'applied',sharedState:'pending',
          pendingChanges:scalars.length+complexChanges.length,value};
        this.workspace.completeSavedRequest(selected,request.id,context.generation,{workingSnapshot:snapshot,complexChanges,scalars},result);return result;
      }catch(error){let savedSnapshot:Artifact|undefined;try{savedSnapshot=await backend.saved(selected);}catch{}
        this.workspace.recordRequest(request.id,'unknown',{...selected,source,state:'unknown',sourceSnapshot,...(savedSnapshot?{savedSnapshot}:{})});throw error;}
    });
  }
  async strings(selected: Scope, contains: string, limit: number, offset: number) {
    const pattern=text(contains,4096).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const value=await this.read(selected,'/search_strings',{search_term:pattern,min_length:0,offset,limit});
    const page=pageResult(value,'matches',limit,offset);
    const items=page.items.map(item=>{const row=object(item);if(typeof row.value!=='string')fail('malformed','String result lacks decoded text.');
      return {address:publicAddress(row.address),text:row.value};});
    return {...selected,items,offset,limit,total:page.total,truncated:object(value).truncated===true||offset+items.length<page.total,
      ...(object(value).scan?{scan:object(value).scan,totalKnown:object(value).total_known!==false}:{})};
  }
  async function(selected: Scope, at: string, decompile=false,page?:{limit:number;offset:number}) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const value=await backend.call(selected,'/get_functions',{functions:at,fields:decompile?'entry_point,signature,decompiled_code':'entry_point,signature',include_call_context:false});
      const result=functionResult(value,at);
      if(typeof result.signature!=='string')functionFailure(at,'missing_signature');
      if(decompile&&typeof result.decompiled_code!=='string')functionFailure(at,'missing_decompiler_text');
      const listing=object(await backend.call(selected,'/get_comment',{address:result.entry_point}));
      const window=decompile?textWindow(String(result.decompiled_code),page?.limit??16000,page?.offset??0,Boolean(object(result.truncation??{}).decompiled_code)):undefined;
      const {content,...paging}=window??{content:undefined};
      return {...selected,address:publicAddress(result.entry_point),name:result.name,signature:result.signature,comments:comments(listing),...(window?{code:content,...paging}:{})};
    });
  }
  async inspectFunctions(selected:Scope,parameters:Record<string,unknown>,options:FunctionInspectionOptions){
    const lookup=entryRequest(parameters,options);
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const context=this.workspace.context(selected);
      const observe=backend.inspectObservation?()=>backend.inspectObservation!(selected):backend.observation?()=>backend.observation!(selected):undefined;
      if(lookup&&!observe)fail('unsupported','Address resolution requires guarded native observations.');
      const observation=await observe?.();
      const view={revision:revision(context.baseRevision),identity:digest({target:selected.target,context:context.id,generation:context.generation,snapshot:context.workingSnapshot,epoch:context.viewEpoch??0,observation})};
      return inspectFunctions(backend,selected,parameters,options,view,observation,observe);
    });
  }
  async stringAnchors(selected:Scope,request:AnchorRequest){
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const observe=backend.inspectObservation?()=>backend.inspectObservation!(selected):backend.observation?()=>backend.observation!(selected):undefined;
      if(!observe)fail('unsupported','String anchors require guarded native observations.');
      const context=this.workspace.context(selected),observation=await observe();
      const view=digest({target:selected.target,context:context.id,generation:context.generation,snapshot:context.workingSnapshot,epoch:context.viewEpoch??0,observation});
      return inspectAnchors(backend,selected,request,view,observation,observe);
    });
  }
  async codeReferences(selected:Scope,request:ReferenceRequest){
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      if(!backend.observation)fail('unsupported','Code-reference continuation requires native view observation.');
      const context=this.workspace.context(selected),observation=await backend.observation(selected);
      const view=digest({target:selected.target,context:context.id,generation:context.generation,snapshot:context.workingSnapshot,epoch:context.viewEpoch??0,observation});
      return inspectCodeReferences(backend,selected,request,view,observation);
    });
  }
  async navigation(selected:Scope,maximum:number){
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const value=navigationResult(await backend.call(selected,'/navigation_diagnostic',{max_scan:maximum}),maximum);
      return {...selected,value:{...value,initialAnalysis:this.workspace.model(selected.target).settings.autoAnalyze?'requested':'none',priorAnalysis:'unknown',provenance:'Initial facade policy only; imported/saved metadata may have an unknown analysis history.'}};
    });
  }
  async xrefs(selected: Scope, at: string, limit: number, offset: number) {
    return this.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const page=pageResult(await backend.call(selected,'/get_xrefs_to',{address:at,limit,offset}),'references',limit,offset);
      const items=[];
      for(const item of page.items) {
        const row=object(item);
        if(typeof row.type!=='string'||!row.type)fail('partial','Reference result lacks its kind.');
        // Ghidra's external-entry reference is metadata, not a navigable address.
        if(row.from_address==='Entry Point'&&row.type==='EXTERNAL') {
          items.push({from:null,to:publicAddress(at),kind:row.type,source:'entry-point'});continue;
        }
        const from=address(row.from_address);
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
  async edit(selected: Scope, at: string, field: ScalarChange['field'], value: string|null, callerId?: string,
    resolution?:{expectedShared:string|null}) {
    at=address(at);
    const reserved=this.workspace.reserveRequest(selected,field==='function.name'?'ghidra.functions.rename':'ghidra.comments.set',
      {address:at,field,value,...(resolution?{resolution}:{})},callerId);
    const action=async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay) {
        if(request.state==='applied')return request.result;
        if(request.state!=='accepted')return {...selected,state:request.state,...(callerId?{requestId:callerId}:{})};
      }
      const backend=await this.backend();
      // Restore before starting this mutation; other uncertain effects still block the context.
      await backend.open(selected);
      const before=this.workspace.context(selected);
      if(resolution&&before.nativeCheckout)fail('unsupported','Native conflicts require Ghidra resolver decisions; the legacy scalar resolution option cannot choose a native winner.');
      const previous=before.scalars.find(change=>change.address===at&&change.field===field);
      let observed: string|null;
      if(field==='function.name') {
        observed=String(functionResult(await backend.call(selected,'/get_functions',{functions:at,fields:'entry_point',include_call_context:false}),at).name);
      } else observed=comments(await backend.call(selected,'/get_comment',{address:at}))[field.slice(8)]!;
      let original=previous?previous.original:observed,dependency=previous?.dependency;
      if(resolution) {
        if(!previous?.conflict)fail('conflict','Explicit resolution requires an existing field conflict.');
        if(!backend.latest||!backend.fields)fail('configuration','Resolution requires verified shared-state inspection.');
        if(this.workspace.activePublication(selected.target)||this.workspace.model(selected.target).state==='unknown')
          fail('blocked','Shared publication outcome must be reconciled before resolving a field.');
        const shared=await backend.latest(selected.target);this.workspace.observeShared(selected.target,shared.revision,shared.snapshot);
        const current=(await backend.fields(shared.snapshot,[previous]))[fieldKey(previous)];
        if(!current||!current.exists)fail('conflict','The shared field dependency disappeared; transfer work onto a current context.');
        if(current.value!==resolution.expectedShared) {
          const result={...selected,state:'conflict',reason:'shared_changed',expected:resolution.expectedShared,shared:current.value,local:observed,applied:0};
          this.workspace.recordRequest(request.id,'failed',result);fail('conflict','Shared value changed since the explicit decision; local work is retained.',result);
        }
        original=current.value;dependency=current.dependency;
      } else if(previous?.conflict)fail('conflict','This field has an unresolved shared conflict; use an explicit resolution.');
      if(dependency===undefined&&backend.fields&&before.workingSnapshot) {
        const anchor=(await backend.fields(before.workingSnapshot,[{address:at,field}]))[at+'@'+field];
        if(!anchor)fail('partial','Saved private dependency inspection omitted the edited field.');dependency=anchor.dependency;
      }
      const scalars=before.scalars.filter(change=>change.address!==at||change.field!==field);
      if(value!==original)scalars.push({address:at,field,original,local:value,...(dependency?{dependency}:{})});
      const complexChanges=[...before.complexChanges];
      if(previous&&previous.local!==observed&&!complexChanges.includes(request.id))complexChanges.push(request.id);
      const result={...selected,state:'applied',sharedState:scalars.length||complexChanges.length?'pending':'shared',
        ...(resolution?{conflict:'resolved'}:{}),pendingChanges:scalars.length+complexChanges.length};
      this.workspace.startRequest(request.id,{kind:'scalar',address:at,field,value,observed,generation:before.generation,
        workingSnapshot:before.workingSnapshot,scalars,complexChanges,result});
      try {
        const changed=object(await backend.call(selected,field==='function.name'?'/rename_function':'/set_comment',
          field==='function.name'?{old_name:at,new_name:value,strict_mode:'off'}:{address:at,type:field.slice(8),comment:value??''}));
        if(changed.status!=='success'&&changed.success!==true)fail('partial','Editing operation was not acknowledged.');
        const after=field==='function.name'?String(functionResult(await backend.call(selected,'/get_functions',{functions:at,fields:'entry_point',include_call_context:false}),at).name):
          comments(await backend.call(selected,'/get_comment',{address:at}))[field.slice(8)]!;
        if(after!==value)fail('partial','Editing readback does not match the requested value.');
        const snapshot=await backend.saved(selected);
        this.workspace.completeSavedRequest(selected,request.id,before.generation,{workingSnapshot:snapshot,scalars,complexChanges},result);
        return result;
      } catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown'});throw error;}
    };
    return this.ordered(selected,()=>resolution?this.sharedOrder(selected.target,action):action());
  }
  private async sharedOrder<T>(target:string,action:()=>Promise<T>):Promise<T> {
    const key='shared:'+target,previous=this.tasks.get(key),task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);
    this.tasks.set(key,task);try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}
  }
  async reconcileRequests(selected:Scope,backend:ResearchBackend) {
    return this.sharedOrder(selected.target,()=>this.reconcile(selected,backend));
  }
  private async reconcile(selected:Scope,backend:ResearchBackend,reportOpenFailure=false) {
    const active=this.workspace.activePublication(selected.target);
    if(active) {
      if(active.state==='preparing')this.workspace.rejectPublication(active.id,{session:active.session,target:active.target,state:'not_published',applied:0});
      else if(backend.recover) {
        const observed=await backend.recover(active);
        if(observed.state==='verified')this.workspace.finishPublication(active.id,observed.revision,{session:active.session,target:active.target,
          state:'merged',sharedRevision:revision(observed.revision),applied:active.scalars.length+(active.complexChanges?.length??Number(active.complex)),pendingChanges:0},observed.snapshot);
        if(observed.state==='verified'&&backend.dropNative)await backend.dropNative(active);
      }
    }
    for(const request of this.workspace.unresolved(selected)) {
      if(request.operation==='ghidra.merge') {
        let publication;
        try{publication=this.workspace.publication(request.id);}catch(error){if(!String((error as {code?:string}).code).endsWith('.notFound'))throw error;}
        if(!publication){
          let empty;
          try{empty=await backend.recoverEmptyNative?.(selected,request.id);}
          catch(error){
            const retained=this.retainedDisposal(selected,request.id,error);
            if(!retained)throw error;
            continue;
          }
          if(empty?.state==='verified'){
            const current=this.workspace.context(selected);this.workspace.completeSavedRequest(selected,request.id,current.generation,{}, {...selected,state:'empty',applied:0,pendingChanges:0,sharedRevision:revision(empty.revision),engine:'ghidra-native'});continue;
          }
          if(backend.nativeEngine){const update=await backend.recoverUpdate?.(selected,request.id);if(!update||update.state==='unknown')continue;}
          this.workspace.recordRequest(request.id,'failed',{...selected,state:'not_published',applied:0});
        }
        continue;
      }
      if(request.operation==='ghidra.refresh') {
        // Native Update may have changed the saved checkout. An interrupted result cannot be declared not_updated.
        if(backend.nativeEngine){
          const update=await backend.recoverUpdate?.(selected,request.id);if(!update||update.state==='unknown')continue;
          const context=this.workspace.context(selected);
          if(update.state==='conflict')this.workspace.recordRequest(request.id,'failed',{...selected,state:'conflict',receivedChanges:0,preservedLocalChanges:count(context),conflicts:[{engine:'ghidra',message:update.conflict}]});
          else this.workspace.completeSavedRequest(selected,request.id,context.generation,{}, {...selected,state:'updated',engine:'ghidra-native',sharedRevision:revision(update.revision),receivedChanges:update.receivedChanges,preservedLocalChanges:count(context),nativeMergeInvocations:update.nativeMergeInvocations,conflicts:[]});
        }else this.workspace.recordRequest(request.id,'failed',{...selected,state:'not_updated',receivedChanges:0});
        continue;
      }
      if(request.operation==='ghidra.open') {
        if(backend.recoverModel&&!await backend.recoverModel(selected.target))continue;
        try {
          await backend.open(selected,request.id);
          const intent=object(request.intent);if(intent.mode)await backend.mode(selected,intent.mode as ToolMode);
          const context=this.workspace.context(selected),result={...selected,state:'ready',baseRevision:revision(context.baseRevision),
            sharedRevision:revision(this.workspace.model(selected.target).sharedRevision),pendingChanges:count(context)};
          this.workspace.completeSavedRequest(selected,request.id,context.generation,{},result);
        }catch(error){if(reportOpenFailure)throw error;/* Status retains unresolved evidence without dispatching another intent. */}
        continue;
      }
      const execution=request.execution===undefined?undefined:object(request.execution);
      if(execution?.kind==='native-discard'){
        const discarded=await backend.recoverDiscardNative?.(selected,request.id,execution.checkout as NativeCheckout);
        if(discarded?.state==='verified'){
          const current=this.workspace.context(selected);
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{}, {...selected,state:'discarded',discardedChanges:Number(execution.discardedChanges),pendingChanges:0,
            baseRevision:revision(discarded.baseRevision),...(discarded.retainedKeepFile?{retainedKeepFile:discarded.retainedKeepFile}:{})});
        }
        continue;
      }
      if(execution?.kind==='discard'){
        try{const current=this.workspace.context(selected),base=execution.baseSnapshot as Artifact,discarded=execution.discardedSnapshot as Artifact;
          if(!backend.closed||!await backend.closed(selected)||current.generation!==execution.generation||current.baseSnapshot?.id!==base.id||current.workingSnapshot?.id!==discarded.id)continue;
          await this.workspace.artifacts.verify(base);await this.workspace.artifacts.verify(discarded);
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:base,state:'stopped',viewEpoch:(current.viewEpoch??0)+1,scalars:[],complexChanges:[]},execution.result);
        }catch{/* A local switch is reconstructed only from its unchanged retained snapshots. */}
        continue;
      }
      if(execution?.kind==='debugger'){
        try{if(backend.closed&&await backend.closed(selected)){
          const current=this.workspace.context(selected),outcome=object(request.result??{}),retained=outcome.savedDebugger as DebuggerState|undefined;
          const saved=retained&&current.generation===execution.generation?retained:current.debugger;
          const program=outcome.metadataChanged===true&&current.generation===execution.generation?outcome.savedSnapshot as Artifact|undefined:undefined;
          if(saved||program){
            if(program)await this.workspace.artifacts.verify(program);for(const trace of saved?.traces??[])await this.workspace.artifacts.verify(trace.snapshot);
            this.workspace.saveContext(selected,current.generation,{...(saved?{debugger:{...saved,connected:false,traces:saved.traces.map(trace=>({...trace,connected:false}))}}:{}),
              ...(program?{workingSnapshot:program,complexChanges:current.complexChanges.includes(request.id)?current.complexChanges:[...current.complexChanges,request.id]}:{})});
          }
          this.workspace.recordRequest(request.id,'failed',{...selected,state:'disconnected',outcome:'unknown',operation:execution.operation});
        }}
        catch{/* A CPU action is not replayed or inferred from a later program counter. */}
        continue;
      }
      if(execution?.kind==='ui') {
        try{
          if(backend.closed&&await backend.closed(selected)){
            this.workspace.recordRequest(request.id,'failed',{...selected,state:'disconnected',outcome:'unknown',operation:execution.operation});continue;
          }
          if(execution.operation==='goto'&&backend.ui){
            const p=object(object(request.intent).parameters),cursor=await backend.ui(selected,'cursor',{}),location=object(cursor.address),current=this.workspace.context(selected);
            if(location.session!==selected.session||location.target!==selected.target||address(location.address)!==address(p.address)||current.generation!==execution.generation)continue;
            const containing=cursor.function?object(cursor.function):undefined,value={address:publicAddress(location.address),...(containing&&typeof containing.function_name==='string'?{function:containing.function_name}:{})};
            this.workspace.completeSavedRequest(selected,request.id,current.generation,{}, {...selected,state:'applied',value});
          }
        }catch{/* Only the live verified cursor or a verified lost process establishes continuation. */}
        continue;
      }
      if(execution?.kind==='export') {
        try{const snapshot=execution.snapshot as Artifact;await this.workspace.artifacts.verify(snapshot);
          const observed=await this.workspace.artifacts.capture(text(execution.output,4096),'snapshot'),current=this.workspace.context(selected);
          if(observed.id!==snapshot.id||current.generation!==execution.generation)continue;
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:(execution.workingSnapshot as Artifact|undefined)??snapshot},
            {...selected,state:'exported',output:execution.output,sha256:snapshot.sha256,size:snapshot.size});
        }catch{/* Partial or changed output cannot prove an export and is never overwritten. */}
        continue;
      }
      if(execution?.kind==='close'&&backend.closed) {
        try{if(!await backend.closed(selected))continue;const current=this.workspace.context(selected);
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{state:'stopped'},
            {...selected,state:'closed',pendingChanges:count(current)});
        }catch{/* A stopped metadata flag alone never proves process release. */}
        continue;
      }
      if(execution?.kind==='save') {
        try{const snapshot=object(request.result).savedSnapshot as Artifact;if(!snapshot)continue;
          await this.workspace.artifacts.verify(snapshot);const current=this.workspace.context(selected);
          if(current.generation!==execution.generation)continue;
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot,viewEpoch:(current.viewEpoch??0)+1},
            {...selected,state:'saved',pendingChanges:count(current)});
        }catch{/* Unproved save outcome stays retained without another save dispatch. */}
        continue;
      }
      if(execution?.kind==='transfer'&&execution.dryRun===false&&backend.transferCheck) {
        try {
          const sourceSnapshot=execution.sourceSnapshot as Artifact,retained=request.result&&object(request.result).savedSnapshot;
          await this.workspace.artifacts.verify(sourceSnapshot);await backend.open(selected,request.id);
          const snapshot=retained?retained as Artifact:await backend.saved(selected);await this.workspace.artifacts.verify(snapshot);
          if(transferResult(await backend.transferCheck(selected,sourceSnapshot,snapshot),true).total!==0)continue;
          const current=this.workspace.context(selected);
          if(current.generation!==execution.generation&&current.workingSnapshot?.id!==object(execution.workingSnapshot).id)continue;
          const scalars=await this.savedScalars(current,backend,snapshot);
          const complexChanges=[...current.complexChanges,request.id];
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot,complexChanges,scalars,viewEpoch:(current.viewEpoch??0)+1},
            {...selected,source:execution.source,state:'applied',reconciled:true,sharedState:'pending',pendingChanges:scalars.length+complexChanges.length});
        }catch{/* Saved source/candidate remain retained; never execute transfer again as recovery. */}
        continue;
      }
      if(execution?.kind==='program'&&execution.savedVerification===true) {
        try {
          const retained=request.result&&object(request.result).savedSnapshot;
          let snapshot:Artifact;
          if(retained){snapshot=retained as Artifact;await this.workspace.artifacts.verify(snapshot);}
          else {await backend.open(selected,request.id);snapshot=await backend.saved(selected);}
          const intent=object(request.intent),parameters=object(intent.parameters);
          const value=await verifyMutation(backend,snapshot,request.operation,parameters,{});
          const current=this.workspace.context(selected);
          if(current.generation!==execution.generation)continue;
          const scalars=await this.savedScalars(current,backend,snapshot),complexChanges=[...current.complexChanges,request.id];
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot,complexChanges,scalars,viewEpoch:(current.viewEpoch??0)+1},
            {...selected,state:'applied',sharedState:'pending',pendingChanges:scalars.length+complexChanges.length,value});
        }catch{/* Retain both snapshots and the unresolved intent when complete effects cannot be proven. */}
        continue;
      }
      if(execution?.kind==='scalar') {
        try {
          await backend.open(selected,request.id);
          const field=text(execution.field) as ScalarChange['field'],at=address(execution.address);
          const observed=field==='function.name'?String(functionResult(await backend.call(selected,'/get_functions',
            {functions:at,fields:'entry_point',include_call_context:false}),at).name):comments(await backend.call(selected,'/get_comment',{address:at}))[field.slice(8)];
          if(observed!==execution.value)continue;
          const current=this.workspace.context(selected),snapshot=await backend.saved(selected);
          const expected=number(execution.generation,Number.MAX_SAFE_INTEGER);
          if(current.generation!==expected&&current.workingSnapshot?.id!==object(execution.workingSnapshot).id)continue;
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot,
            scalars:execution.scalars as ScalarChange[],complexChanges:execution.complexChanges as string[]},execution.result);
        }catch{/* Never replay an uncertain setter merely because its desired value was not observed. */}
      }
    }
  }
  async merge(selected:Scope,callerId?:string) {
    const reserved=this.workspace.reserveRequest(selected,'ghidra.merge',{},callerId);
    return this.ordered(selected,()=>this.sharedOrder(selected.target,async()=>{
      let request=this.workspace.request(reserved.request.id),backend:ResearchBackend|undefined;
      if(reserved.replay&&['running','unknown'].includes(request.state)){backend=await this.backend();await this.reconcile(selected,backend);request=this.workspace.request(request.id);}
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        fail(request.state==='failed'?'conflict':'unknown','This merge retains its recorded outcome; it is never checked in blindly again.',request.result);
      }
      if(this.workspace.activePublication(selected.target)||this.workspace.model(selected.target).state==='unknown')fail('blocked','Shared publication is unresolved; retain every working copy.');
      backend??=await this.backend();
      if(backend.nativeEngine!=='native-checkout-v1'||!backend.updateNative||!backend.publishNative||!backend.dropNative||!backend.finishEmptyNative)
        fail('configuration','The primary CLI requires native checkout/Update/check-in; scalar fallback is disabled.');
      await backend.open(selected);
      if(this.workspace.context(selected).debugger?.connected)fail('busy','Stop the live debugger before handing its native project to Update/check-in.');
      this.workspace.startRequest(request.id,{kind:'native-merge'});
      let publication:Publication|undefined;
      try{
        const update=await backend.updateNative(selected,request.id),context=this.workspace.context(selected);
        if(update.state==='conflict'){
          const result={...selected,state:'conflict',applied:0,pendingChanges:count(context),conflicts:[{engine:'ghidra',message:update.conflict}]};
          this.workspace.recordRequest(request.id,'failed',result);fail('conflict','Native conflict preserves the original working copy and checkout.',result);
        }
        if(update.state==='empty'){
          await backend.finishEmptyNative(selected,request.id);const current=this.workspace.context(selected);
          const result={...selected,state:count(context)?'merged':'empty',applied:0,pendingChanges:0,sharedRevision:revision(update.revision),engine:'ghidra-native'};
          this.workspace.completeSavedRequest(selected,request.id,current.generation,{},result);return result;
        }
        if(update.revision<(this.workspace.model(selected.target).sharedRevision??1)){
          const result={...selected,state:'conflict',reason:'shared_changed',applied:0,pendingChanges:count(context)};
          this.workspace.recordRequest(request.id,'failed',result);fail('conflict','Another context observed a newer server version; retain this checkout and perform a new native Update.',result);
        }
        publication=this.workspace.beginPublication(selected,request.id,update.revision,update.snapshot);
        publication=this.workspace.publicationIntent(publication.id);
        const published=await backend.publishNative(publication);
        if(published.state==='conflict'){
          const result={...selected,state:'conflict',reason:'shared_changed',applied:0,pendingChanges:count(context),conflicts:[{engine:'ghidra',message:published.conflict??'Shared head changed'}]};
          this.workspace.rejectPublication(publication.id,result);fail('conflict','Native check-in was refused; local work remains retained.',result);
        }
        const result={...selected,state:'merged',sharedRevision:revision(published.revision),applied:count(context),pendingChanges:0,engine:'ghidra-native'};
        this.workspace.finishPublication(publication.id,published.revision,result,published.snapshot);
        await backend.dropNative(selected);return result;
      }catch(error){
        const state=this.workspace.request(request.id).state;
        if(state!=='applied'&&state!=='failed'){
          // Proved empty-disposal retention already committed its terminal request atomically above.
          // An uncertain release or any publication still follows the unknown-outcome path below.
          if(publication&&['commit_intent','unknown'].includes(this.workspace.publication(publication.id).state))this.workspace.unknownPublication(publication.id,{state:'unknown',engine:'ghidra-native'});
          this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',engine:'ghidra-native'});
        }
        throw error;
      }
    }));
  }
  async refresh(selected:Scope,callerId?:string) {
    const reserved=this.workspace.reserveRequest(selected,'ghidra.refresh',{},callerId);
    return this.ordered(selected,()=>this.sharedOrder(selected.target,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        fail(request.state==='failed'?'conflict':'unknown','Native Update retains its recorded outcome; its saved checkout is preserved.',request.result);
      }
      if(this.workspace.activePublication(selected.target)||this.workspace.model(selected.target).state==='unknown')fail('blocked','Shared publication requires reconciliation before Update.');
      const backend=await this.backend();
      if(backend.nativeEngine!=='native-checkout-v1'||!backend.updateNative)fail('configuration','Native Update is required; scalar refresh fallback is disabled.');
      await backend.open(selected);
      if(this.workspace.context(selected).debugger?.connected)fail('busy','Stop the live debugger before handing its native project to Update.');
      this.workspace.startRequest(request.id,{kind:'native-update'});
      try{
        const update=await backend.updateNative(selected,request.id),context=this.workspace.context(selected);
        if(update.state==='conflict'){
          const result={...selected,state:'conflict',receivedChanges:0,preservedLocalChanges:count(context),conflicts:[{engine:'ghidra',message:update.conflict}]};
          this.workspace.recordRequest(request.id,'failed',result);fail('conflict','Native Update requires a decision; saved private work and ancestry are preserved.',result);
        }
        const result={...selected,state:'updated',engine:'ghidra-native',sharedRevision:revision(update.revision),receivedChanges:update.receivedChanges,
          preservedLocalChanges:count(context),nativeMergeInvocations:update.nativeMergeInvocations,conflicts:[]};
        this.workspace.completeSavedRequest(selected,request.id,context.generation,{},result);return result;
      }catch(error){if(!['applied','failed'].includes(this.workspace.request(request.id).state))this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',engine:'ghidra-native'});throw error;}
    }));
  }
  async mutate(selected:Scope,operation:string,parameters:Record<string,unknown>,
    verify:(backend:ResearchBackend,result:Record<string,unknown>)=>Promise<unknown>,callerId?:string,
    verifySaved?:(backend:ResearchBackend,snapshot:Artifact,result:Record<string,unknown>)=>Promise<unknown>) {
    const reserved=this.workspace.reserveRequest(selected,operation,parameters,callerId);
    return this.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted') {
        if(request.state==='applied')return request.result;
        if(operation==='/run_script_inline'&&request.state==='failed'&&object(request.result??{}).reason==='script_not_executed'){
          const result=object(request.result),execution=object(result.execution);
          fail('script.'+String(execution.stage),String(object(result.diagnostic).message),result);
        }
        if(operation.startsWith('/sdk/')&&request.state==='failed'&&object(request.result??{}).state==='rejected')fail('rejected','This SDK transaction was rolled back and is not repeated.',request.result);
        fail('unknown','This saved-state operation retains an unresolved outcome; it is not re-executed.',request.result);
      }
      const backend=await this.backend();await backend.open(selected);
      if(operation==='/batch_apply_documentation'&&parameters.goto===true)await backend.mode(selected,'gui');
      const context=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:'program',operation,generation:context.generation,workingSnapshot:context.workingSnapshot,
        savedVerification:!!verifySaved});
      let savedSnapshot:Artifact|undefined,phase='operation';
      try {
        let raw:unknown;
        if(operation==='/run_script_inline'&&backend.inlineScript){
          const attempt=await backend.inlineScript(selected,parameters,request.id);raw=attempt.response;
          if(attempt.response.success===false){
            const result={...selected,requestId:request.callerId??request.id,state:attempt.safe?'rejected':'unknown',
              contextState:attempt.safe?'ready':'needs_recovery',reason:attempt.safe?'script_not_executed':'script_execution_not_proven_complete',
              execution:attempt.response.execution,diagnostic:attempt.response.diagnostic,diagnostics:attempt.response.diagnostics,
              diagnosticsTruncated:attempt.response.diagnosticsTruncated,compilerOutput:attempt.response.compilerOutput,
              output:attempt.response.console_output,outputTruncated:attempt.response.outputTruncated};
            if(attempt.safe)this.workspace.recordRequest(request.id,'failed',result);
            fail('script.'+String(object(attempt.response.execution).stage),String(object(attempt.response.diagnostic).message),result);
          }
        }else raw=await backend.call(selected,operation,parameters);
        const response=raw&&typeof raw==='object'&&!Array.isArray(raw)?object(raw):{output:raw};
        if(['rejected','partial','failed','error'].includes(String(response.status))||response.success===false)
          fail('partial','Program operation reported a rejected or incomplete effect.');
        if(!verifySaved&&response.success!==true&&response.status!=='success')fail('partial','Program operation did not acknowledge its effect.');
        let value=await verify(backend,response);phase='save';const snapshot=await backend.saved(selected);savedSnapshot=snapshot;phase='verification';
        if(verifySaved)value=await verifySaved(backend,snapshot,response);
        const scalars=await this.savedScalars(context,backend,snapshot),complexChanges=[...context.complexChanges,request.id],result={...selected,state:'applied',sharedState:'pending',
          pendingChanges:scalars.length+complexChanges.length,value};
        this.workspace.completeSavedRequest(selected,request.id,context.generation,{workingSnapshot:snapshot,complexChanges,scalars},result);return result;
      }catch(error){
        if(operation==='/run_script_inline'&&this.workspace.request(request.id).state==='failed'&&object(this.workspace.request(request.id).result??{}).reason==='script_not_executed')throw error;
        if(operation.startsWith('/sdk/')&&String((error as {code?:unknown}).code).endsWith('.rejected')){
          this.workspace.recordRequest(request.id,'failed',{...selected,state:'rejected',reason:'native_transaction_rolled_back'});throw error;
        }
        // Retain supported structural candidates after a lost operation reply. Never
        // dispatch another save after a save deadline or an arbitrary script failure.
        if(phase==='operation'&&verifySaved&&!['/run_script_inline','/run_ghidra_script'].includes(operation)){
          try{savedSnapshot=await backend.saved(selected);}catch{/* Native evidence stays retained. */}
        }
        const detail=error instanceof CliError?{code:error.code,...(error.result?{result:error.result}:{})}:{};
        this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',phase,...detail,...(savedSnapshot?{savedSnapshot}:{})});throw error;
      }
    });
  }
}
