import {fail,object} from './model.js';
import type {LocatedEntry,EntryResolution} from './function-entries.js';

const hex=(v:unknown)=>{if(typeof v!=='string'||! /^(?:0|[1-9a-f][a-f0-9]{0,15})$/.test(v))fail('partial','Malformed runtime boundary address.');return v;};
const big=(v:string)=>BigInt('0x'+v);
const unavailable=new Set(['headers_not_mapped','unsupported_machine','unsupported_optional_header','unsupported_language','table_not_mapped','runtime_range_not_initialized_executable','unwind_not_mapped','memory_read_failed','short_read']);
const malformed=new Set(['invalid_dos_signature','invalid_pe_offset','invalid_pe_signature','short_optional_header','invalid_image_headers','address_overflow','invalid_rva','invalid_exception_directory','invalid_runtime_range','unordered_or_overlapping_ranges','invalid_unwind_rva']);
/** Validate evidence and selection policy independently, before any function inspection/save. */
export function locatedBoundaries(raw:unknown,request:{addresses:string[];unwindMaximum:number},modification:string){
 const v=object(raw),s=object(v.boundaryLookup),items=object(v.items);
 if(v.protocol!=='insight-function-boundaries-v1'||typeof v.modification!=='string')fail('partial','Malformed function-boundary protocol.');
 if(v.modification!==modification)fail('binding','Native view changed during boundary lookup.',{reason:'changed_view'});
 const state=String(s.state),complete=state==='validated'||state==='absent';
 const reason=String(s.reason),reasonValid=state==='validated'?reason==='validated':state==='absent'?reason==='no_exception_directory':state==='incomplete'?['byte_limit','timeout'].includes(reason):state==='unavailable'?unavailable.has(reason):state==='malformed'&&malformed.has(reason);
 if(!reasonValid||s.complete!==complete||s.headersSource!=='current-mapped-memory'||s.maximumBytes!==request.unwindMaximum||s.deadlineMilliseconds!==5000)fail('partial','Malformed function-boundary coverage.');
 for(const key of ['recordCount','recordsValidated','bytesRead'])if(!Number.isSafeInteger(s[key])||Number(s[key])<0)fail('partial','Malformed boundary counters.');
 if(Number(s.bytesRead)>request.unwindMaximum||Number(s.recordCount)>Math.floor(0xffffffff/12)||Number(s.recordsValidated)>Number(s.recordCount)||Number(s.recordsValidated)*12>Number(s.bytesRead)||state==='validated'&&(s.recordCount!==s.recordsValidated||Number(s.recordCount)<1)||state==='absent'&&Number(s.recordCount)!==0)fail('partial','Inconsistent function-boundary counters.');
 if(complete&&Number(s.bytesRead)<(state==='absent'?200:208+12*Number(s.recordCount)))fail('partial','Impossible complete boundary read accounting.');
 if(Object.keys(items).length!==request.addresses.length||request.addresses.some(at=>!Object.hasOwn(items,at)))fail('binding','Boundary selector set changed.',{reason:'selector_mismatch'});
 const entries=new Map<string,LocatedEntry>();
 for(const at of request.addresses){
   const row=object(items[at]);let database:Record<string,unknown>|null=null,boundary:Record<string,unknown>|null=null;
   if(row.database!==null){database=object(row.database);const entry=hex(database.entryPoint);
     if(!['exact-entry','recorded-containing'].includes(String(database.kind))||database.recordedBodyContainsAddress!==true||(database.kind==='exact-entry')!==(entry===at))fail('partial','Malformed recorded boundary facts.');
   }
   if(row.boundary!==null){
     boundary=object(row.boundary);const lo=hex(boundary.begin),hi=boundary.endExclusive==='10000000000000000'?boundary.endExclusive:hex(boundary.endExclusive);hex(boundary.tableRecordAddress);
     if(!complete||state!=='validated'||Number(s.recordCount)<1||big(lo)>big(at)||big(at)>=big(hi)||boundary.source!=='pe-exception-directory'||boundary.semanticMembership!=='not-established'||boundary.instructionBoundary!=='not-checked'||boundary.unwindInfo!=='not-parsed')fail('partial','Malformed or unvalidated runtime region.');
   }
   const conflict=boundary&&database&&boundary.begin!==database.entryPoint;
   const resolution:EntryResolution={requestedAddress:at,kind:'unresolved',recordedBodyContainsAddress:database!==null,database,boundary};
   if(row.status==='resolved'){
     const entry=hex(row.entryPoint),kind=boundary?'pe-runtime-range':database?.kind;
     if(!complete||conflict||!kind||row.kind!==kind||entry!==(boundary?.begin??database?.entryPoint)||row.recordedBodyContainsAddress!==(database!==null))fail('partial','Inconsistent runtime entry selection.');
     entries.set(at,{entry,resolution:{...resolution,kind:String(kind)}});
   }else{
     let expected:string;
     if(!complete)expected='boundary_lookup_'+state;
     else if(conflict)expected='boundary_conflict';
     else if(boundary)expected='runtime_entry_not_defined';
     else expected='no_runtime_range_or_recorded_function';
     if(row.status!=='unresolved'||row.reason!==expected||complete&&!boundary&&database||expected==='runtime_entry_not_defined'&&database||row.entryPoint!==undefined||row.kind!==undefined)fail('partial','Inconsistent unresolved runtime boundary.');
     entries.set(at,{status:'partial',reason:expected,resolution});
   }
 }
 return {entries,boundaryLookup:s};
}
