import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {mkdir,readFile,writeFile,rename,realpath} from 'node:fs/promises';
import {join,resolve,sep} from 'node:path';
import {randomUUID} from 'node:crypto';
import {scope,number,type Research} from './research.js';
import type {Workspace,Scope} from './workspace.js';
import {object,fail,stable} from './model.js';
import {selectedOptions} from './arguments.js';

export type StopReason='explicit_close'|'view_replaced'|'mode_changed'|'owner_dispose'|'startup_failed'|'temporary_complete'|'legacy_cleanup'|'backend_unresponsive'|'unknown';
type Event={at:string;event:'start'|'restore'|'stop';reason:string;pid:number};
const writes=new Map<string,Promise<void>>();
const journal=(workspace:Workspace,context:string)=>join(workspace.directory,'diagnostics','lifecycle',context+'.json');
const reasons=new Set(['explicit_close','view_replaced','mode_changed','owner_dispose','startup_failed','temporary_complete','legacy_cleanup','unknown','native_launch','saved_snapshot','backend_unresponsive']);
async function events(path:string):Promise<Event[]>{
 try{const rows=JSON.parse(await readFile(path,'utf8'));
  if(!Array.isArray(rows)||rows.length>128||rows.some(row=>!row||typeof row.at!=='string'||row.at.length>64||!Number.isFinite(Date.parse(row.at))||!['start','restore','stop'].includes(row.event)||!reasons.has(row.reason)||!Number.isSafeInteger(row.pid)||row.pid<1))fail('binding','Retained lifecycle observations are malformed.');
  return rows.map(({at,event,reason,pid})=>({at,event,reason,pid}));
 }catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return [];throw error;}
}
export async function recordLifecycle(workspace:Workspace,context:string,event:Event){
 const path=journal(workspace,context),previous=writes.get(path)??Promise.resolve();
 const pending=previous.catch(()=>{}).then(async()=>{const rows=[...await events(path),event].slice(-128),directory=join(workspace.directory,'diagnostics','lifecycle');await mkdir(directory,{recursive:true,mode:0o700});const temporary=path+'.new-'+randomUUID();await writeFile(temporary,JSON.stringify(rows)+'\n',{mode:0o600,flag:'wx'});await rename(temporary,path);});
 writes.set(path,pending);try{await pending;}catch{}finally{if(writes.get(path)===pending)writes.delete(path);}
}
export async function lifecycleDiagnostic(workspace:Workspace,selected:Scope){
 const context=workspace.context(selected),root=join(workspace.directory,'ghidra-native','context',context.id);let latest:Record<string,unknown>|undefined;
 try{
  const binding=object(JSON.parse(await readFile(join(root,'current.json'),'utf8')));
  if(binding.context!==context.id||binding.target!==selected.target||binding.session!==undefined&&binding.session!==selected.session||typeof binding.root!=='string'||!Number.isSafeInteger(binding.pid)||typeof binding.tokenSecret!=='string')fail('binding','Lifecycle receipt belongs to another context.');
  const physical=await realpath(binding.root);if(physical!==resolve(binding.root)||!physical.startsWith(resolve(root)+sep))fail('binding','Lifecycle receipt moved outside its context.');
  const persisted=object(JSON.parse(await readFile(join(physical,'process.json'),'utf8')));
  if(stable(persisted)!==stable(binding))fail('binding','Lifecycle process receipt changed.');
  latest={pid:binding.pid,state:'unobserved',reason:'unknown'};
  try{const stopped=object(JSON.parse(await readFile(join(physical,'stopped.json'),'utf8')));if(stopped.pid===binding.pid&&stopped.tokenSecret===binding.tokenSecret)latest={pid:binding.pid,state:'stopped',reason:reasons.has(String(stopped.reason))?stopped.reason:'unknown',...(typeof stopped.at==='string'?{at:stopped.at}:{})};}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 return {...selected,lifecycle:{events:await events(journal(workspace,context.id)),maximumEvents:128,...(latest?{latest}:{}),ownerShutdownCause:'unknown',coverage:'Retained facade observations, at most the latest 128 events; absent events and historical causes remain unknown. This read neither starts nor probes a native process.'}};
}
export function navigationResult(raw:unknown,maximum:number){
 const value=object(raw),scan=object(value.scan),functions=object(value.functions);
 const samples=['functions','instructions','references','definedData'].map(key=>object(value[key]));
 if(samples.some(row=>!Number.isSafeInteger(row.sampled)||Number(row.sampled)<0||Number(row.sampled)>128||typeof row.complete!=='boolean')||
  !Number.isSafeInteger(scan.visited)||Number(scan.visited)!==samples.reduce((n,row)=>n+Number(row.sampled),0)||Number(scan.visited)>maximum||scan.maximum!==maximum||scan.sampleLimitPerCategory!==128||typeof scan.complete!=='boolean'||scan.complete!==samples.every(row=>row.complete)||!['budget','sample_limit','exhausted'].includes(String(scan.reason))||
  !Number.isSafeInteger(functions.oneByteBodies)||Number(functions.oneByteBodies)<0||Number(functions.oneByteBodies)>Number(functions.sampled)||!Number.isSafeInteger(functions.entriesWithInstructions)||Number(functions.entriesWithInstructions)<0||Number(functions.entriesWithInstructions)>Number(functions.sampled)||!Number.isSafeInteger(functions.bodyBytes)||Number(functions.bodyBytes)<0||
  !Number.isSafeInteger(samples[3]!.strings)||Number(samples[3]!.strings)<0||Number(samples[3]!.strings)>Number(samples[3]!.sampled)||!['sparse-metadata','no-code-observed','observed-metadata'].includes(String(value.assessment))||!Array.isArray(value.recommendations)||value.recommendations.some(v=>typeof v!=='string')||object(value.read_only??{}).modification_unchanged!==true)fail('partial','Malformed navigation diagnostic.');
 return value;
}
export function contextDiagnosticCommands(research:(c:CommandContext)=>Research,workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{return [
 command('analysis','Analysis observations',[command('navigation','Inspect bounded navigation metadata; ready is not analysis completeness',({options:o},c)=>research(c).navigation(scope(o),number(o.maxScan??10000,200000,1)),{permission:Permission.ReadOnly,options:[...selectedOptions,{flags:'--max-scan <count>',description:'Maximum visited metadata inputs across all samples, 1–200000',defaultValue:10000}]})]),
 command('diagnostics','Inspect retained context diagnostics',[command('lifecycle','Read retained start/restore/stop reasons without starting Ghidra',({options:o},c)=>lifecycleDiagnostic(workspace(c),scope(o)),{permission:Permission.ReadOnly,options:selectedOptions})]),
 ];}
