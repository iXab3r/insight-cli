import {fail,object} from './model.js';

export interface EntryOptions {resolveAddress?:string;maxEntryDistance?:number;maxUnwindBytes?:number}
export interface LegacyEntryRequest {addresses:string[];maximum:number}
export type EntryRequest=LegacyEntryRequest|{addresses:string[];unwindMaximum:number};
export interface EntryResolution {requestedAddress:string;kind:string;recordedBodyContainsAddress:boolean;distanceBytes?:number;database?:unknown;boundary?:unknown}
export interface LocatedEntry {entry?:string;resolution?:EntryResolution;reason?:string;status?:'partial'}
export function functionSelectors(parameters:Record<string,unknown>):string[]{
  const selectors=String(parameters.functions||parameters.function||'').split(',').map(s=>s.trim());
  if(!selectors.length||selectors.length>20||selectors.some(s=>!s||s.length>128)||new Set(selectors).size!==selectors.length)
    fail('invalid','Select 1–20 distinct function names or addresses.');
  return selectors;
}
export function entryAddress(value:unknown):string {
  if(typeof value!=='string'||! /^(?:0x)?[a-f0-9]{1,16}$/i.test(value))fail('invalid','Address resolution requires 1–20 default-space hexadecimal addresses, not names.');
  return BigInt('0x'+value.replace(/^0x/i,'')).toString(16);
}
/** Validate before opening/probing native state; ordinary inspection keeps its original contract. */
export function entryRequest(parameters:Record<string,unknown>,options:EntryOptions):EntryRequest|undefined{
  if(options.resolveAddress===undefined){if(options.maxEntryDistance!==undefined||options.maxUnwindBytes!==undefined)fail('invalid','Resolution budgets require --resolve-address.');return;}
  if(options.resolveAddress==='containing-or-pe-runtime'){
    if(options.maxEntryDistance!==undefined)fail('invalid','PE runtime resolution excludes --max-entry-distance.');
    const unwindMaximum=options.maxUnwindBytes??4194304;
    if(!Number.isSafeInteger(unwindMaximum)||unwindMaximum<1||unwindMaximum>16777216)fail('invalid','--max-unwind-bytes must be between 1 and 16777216.');
    if(parameters.function&&parameters.functions)fail('invalid','Supply --function or --functions, not both, for address resolution.');
    return {addresses:[...new Set(functionSelectors(parameters).map(entryAddress))],unwindMaximum};
  }
  if(options.maxUnwindBytes!==undefined)fail('invalid','--max-unwind-bytes requires containing-or-pe-runtime.');
  if(options.resolveAddress!=='containing-or-preceding')fail('invalid','--resolve-address must be containing-or-preceding.');
  const maximum=options.maxEntryDistance;
  if(typeof maximum!=='number'||!Number.isSafeInteger(maximum)||maximum<1||maximum>65536)
    fail('invalid','Address resolution requires --max-entry-distance between 1 and 65536 bytes.');
  if(parameters.function&&parameters.functions)fail('invalid','Supply --function or --functions, not both, for address resolution.');
  return {addresses:[...new Set(functionSelectors(parameters).map(entryAddress))],maximum};
}
const misses=new Set(['address_out_of_range','address_not_in_initialized_executable_block','no_preceding_entry','entry_outside_block','entry_distance_exceeded']);
/** The authenticated native lookup supplies DB facts, never inferred semantic membership. */
export function locatedEntries(raw:unknown,request:LegacyEntryRequest,modification:string):Map<string,LocatedEntry>{
  const result=object(raw),items=object(result.items);
  if(result.protocol!=='insight-function-entries-v1'||typeof result.modification!=='string')fail('partial','Function-entry lookup returned malformed protocol facts.');
  if(result.modification!==modification)fail('binding','Native view changed during function-entry lookup.',{reason:'changed_view'});
  if(Object.keys(items).length!==request.addresses.length||
    request.addresses.some(at=>!Object.hasOwn(items,at)))fail('binding','Function-entry lookup returned another view or selector set.',{reason:'selector_mismatch'});
  const out=new Map<string,LocatedEntry>();
  for(const at of request.addresses){
    const row=object(items[at]);
    if(row.status==='not_found'){
      if(typeof row.reason!=='string'||!misses.has(row.reason))fail('partial','Function-entry lookup returned an invalid policy miss.');
      out.set(at,{reason:row.reason});continue;
    }
    if(row.status!=='resolved'||typeof row.entryPoint!=='string'||! /^[a-f0-9]{1,16}$/.test(row.entryPoint)||
      entryAddress(row.entryPoint)!==row.entryPoint||typeof row.recordedBodyContainsAddress!=='boolean')fail('partial','Function-entry lookup returned malformed entry facts.');
    const entry=row.entryPoint,contains=row.recordedBodyContainsAddress,kind=row.kind;
    // Address strings are hexadecimal even when they contain digits only.
    const actualDistance=BigInt('0x'+at)-BigInt('0x'+entry);
    if(kind==='exact-entry'){
      if(entry!==at||!contains||row.distanceBytes!==0)fail('partial','Function-entry lookup returned inconsistent exact-entry facts.');
    }else if(kind==='recorded-containing'){
      if(entry===at||!contains||row.distanceBytes!==undefined)fail('partial','Function-entry lookup returned inconsistent recorded containment.');
    }else if(kind==='preceding-entry-candidate'){
      if(contains||actualDistance<1n||actualDistance>BigInt(request.maximum)||row.distanceBytes!==Number(actualDistance))
        fail('partial','Function-entry lookup returned an out-of-policy candidate.');
    }else fail('partial','Function-entry lookup returned an unknown resolution kind.');
    out.set(at,{entry,resolution:{requestedAddress:at,kind,recordedBodyContainsAddress:contains,...(kind==='recorded-containing'?{}:{distanceBytes:row.distanceBytes as number})}});
  }
  return out;
}
