import {mkdir,writeFile} from 'node:fs/promises';
import {resolve,join,isAbsolute} from 'node:path';
import type {ResearchBackend} from './research.js';
import type {Scope} from './workspace.js';
import {fail,object,digest} from './model.js';
import {functionResult} from './function-results.js';
import {timed} from './internal-timing.js';
import {textWindow} from './text-window.js';
import {CliError} from '@eyeauras/cli-factory';
import {entryAddress,entryRequest,functionSelectors,locatedEntries,type EntryOptions,type LocatedEntry} from './function-entries.js';
import {locatedBoundaries} from './function-boundaries.js';

export interface FunctionInspectionOptions extends EntryOptions {limit:number;offset:number;total:number;expectView?:string;saveDirectory?:string}
const fields=new Set('signature classification return_type entry_point body_start body_end decompiled_code plate_comment comments labels tags parameters locals callers call_context callees xrefs disassembly jump_targets refs'.split(' '));
export async function inspectFunctions(backend:ResearchBackend,scope:Scope,parameters:Record<string,unknown>,options:FunctionInspectionOptions,view:{revision?:string;identity:string},observation?:unknown,observe?:()=>Promise<unknown>){
  if(options.saveDirectory!==undefined&&!isAbsolute(options.saveDirectory))fail('invalid','Save directory must be an absolute path on the owner host.');
  const selectors=functionSelectors(parameters),lookup=entryRequest(parameters,options);
  const selectedFields=String(parameters.fields??'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
  if(selectedFields.some(s=>!fields.has(s)))fail('invalid','Unknown function field. Allowed fields: '+[...fields].join(', '));
  if(options.expectView!==undefined&&options.expectView!==view.identity)fail('binding','Function continuation view changed.',{reason:'changed_view',view});
  const observeAfter=observe??(backend.observation?()=>backend.observation!(scope):undefined);
  let entries:Map<string,LocatedEntry>|undefined,boundaryLookup:Record<string,unknown>|undefined,raw:Record<string,unknown>,nativeSelectors:string[];
  const guard=async()=>{if(observeAfter&&digest(observation)!==digest(await observeAfter()))fail('binding','Native view changed during bulk function inspection.',{reason:'changed_view',view});};
  try{
  if(lookup){
    if(!observeAfter||typeof object(observation??{}).modification!=='string')fail('unsupported','Address resolution requires guarded native observations.');
    if('unwindMaximum' in lookup){
      const result=locatedBoundaries(await backend.call(scope,'/insight/function-boundaries/v1',{addresses:lookup.addresses.join(','),max_unwind_bytes:lookup.unwindMaximum}),lookup,String(object(observation).modification));
      entries=result.entries;boundaryLookup=result.boundaryLookup;
    }else entries=locatedEntries(await backend.call(scope,'/insight/function-entries/v1',{addresses:lookup.addresses.join(','),max_entry_distance:lookup.maximum}),lookup,String(object(observation).modification));
  }
  nativeSelectors=entries?[...new Set([...entries.values()].flatMap(row=>row.entry?[row.entry]:[]))]:selectors;
  const nativeParameters={...parameters,...(entries?{function:''}:{}),functions:nativeSelectors.join(','),...(entries&&selectedFields.length?{fields:[...new Set([...selectedFields,'entry_point'])].join(',')}:{})};
  raw=nativeSelectors.length?object(await backend.call(scope,'/get_functions',nativeParameters)):{functions:{}};
  }catch(error){await guard();throw error;}
  await guard();
  return timed('adapter.normalize','functions.inspect',async()=>{
  const functions=object(raw.functions);
  if(Object.keys(functions).length!==nativeSelectors.length||nativeSelectors.some(s=>!Object.hasOwn(functions,s)))fail('partial','Bulk function selectors changed.');
  const output:Record<string,unknown>=Object.create(null),saved:{name:string;content:string}[]=[];let remaining=options.total;
  for(const [index,selector]of selectors.entries()){
    const located=entries?.get(entryAddress(selector)),selected=located?.entry??selector;
    const provenance=located?.resolution?{...(located.entry?{entry_point:located.entry}:{}),resolution:{...located.resolution,requestedAddress:selector}}:{};
    if(located?.reason){output[selector]={status:located.status??'not_found',selector,reason:located.reason,error:'No function was selected by the explicit address-resolution policy.',...provenance};continue;}
    let found:Record<string,unknown>;
    try{found=functionResult({functions:{[selected]:functions[selected]}},selected,{requireEntryPoint:Boolean(entries)||!selectedFields.length||selectedFields.includes('entry_point')});}
    catch(error){if(!(error instanceof CliError))throw error;const detail=object(error.result);output[selector]={error:error.message,...detail,...provenance,...(entries?{selector}:{}),status:detail.reason==='function_not_found'?'not_found':'failed'};continue;}
    if(located?.entry&&entryAddress(found.entry_point)!==located.entry)fail('binding','Inspected function differs from the resolved entry.',{reason:'selector_mismatch'});
    const row:Record<string,unknown>={...found,...provenance,status:'success'};
    if(typeof row.decompiled_code==='string'){
      const source=row.decompiled_code,window=textWindow(source,options.saveDirectory?0:Math.min(options.limit,remaining),options.saveDirectory?0:options.offset,Boolean(object(row.truncation??{}).decompiled_code));
      const {content,...metadata}=window;remaining-=Array.from(content).length;
      row.decompiled_code=content;row.text={...metadata,returnedCharacters:Array.from(content).length,nextOffset:Math.min(window.totalCharacters,window.offset+Array.from(content).length)};
      if(options.saveDirectory){
        if(Buffer.byteLength(source)>4*1024**2)fail('limit','Native function text exceeds the four MiB saved-file bound.');
        const name=String(index).padStart(2,'0')+'-'+window.textSha256+'.c';saved.push({name,content:source});
        delete row.decompiled_code;row.savedText={file:join(resolve(options.saveDirectory),name),textSha256:window.textSha256,totalCharacters:window.totalCharacters,sourceTruncated:window.sourceTruncated,coverage:'entire returned native text'};
      }
    }else if(!selectedFields.length||selectedFields.includes('decompiled_code')){row.status='partial';row.text={reason:'missing_decompiler_text'};}
    output[selector]=row;
  }
  if(!parameters.functions){const single=object(output[selectors[0]!]);if(single.status==='failed'||single.status==='not_found'||boundaryLookup&&single.reason)fail('partial',String(single.error),{...single,...(boundaryLookup?{boundaryLookup}:{}),view});}
  const result={...(parameters.functions?{...(entries?(typeof raw.program==='string'?{program:raw.program}:{}):raw),functions:output}:object(output[selectors[0]!])),...(boundaryLookup?{boundaryLookup}:{}),view,textBudget:{maximumCharacters:options.total,returnedCharacters:options.total-remaining},...(options.saveDirectory?{save:{host:'owner',directory:resolve(options.saveDirectory),manifest:join(resolve(options.saveDirectory),'manifest.json')}}:{})};
  if(Buffer.byteLength(JSON.stringify(result))>1048576)fail('limit','Function response exceeds one MiB; narrow fields or selectors.');
  if(options.saveDirectory){
    // A fresh directory prevents overwrite and makes a partial filesystem failure observable.
    await timed('adapter.save-text','functions.inspect',async()=>{
    const directory=resolve(options.saveDirectory!);await mkdir(directory,{recursive:false});
    for(const file of saved)await writeFile(join(directory,file.name),file.content,{flag:'wx',mode:0o600});
    await writeFile(join(directory,'manifest.json'),JSON.stringify({...scope,value:result},null,2)+'\n',{flag:'wx',mode:0o600});
    });
  }
  return {...scope,value:result};
  });
}
