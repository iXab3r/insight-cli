import {object,fail,text} from './model.js';
import {address,publicAddress} from './research.js';
import type {Scope} from './workspace.js';
export function uiResult(operation:string,p:Record<string,unknown>,raw:unknown,selected:Scope,program:string,label:string,nativeName?:string){
  const value=object(raw),check=(value:unknown)=>{if(value!==program&&value!==program.slice(program.lastIndexOf('/')+1)&&!(nativeName!==undefined&&value===nativeName))fail('binding','UI selected an undeclared program.');};
  if(operation==='tools'){
    if(!Array.isArray(value.tools)||value.tools.length>100||value.count!==value.tools.length)fail('partial','UI tool inventory has inconsistent counts.');
    const tools=value.tools.map(raw=>{const row=object(raw);text(row.name);if(typeof row.has_program_manager!=='boolean')fail('partial','UI tool omitted its program-manager capability.');
      if(row.current_program!==undefined)check(row.current_program);
      if(row.has_program_manager&&(!Array.isArray(row.open_programs)||row.open_programs.length>100))fail('partial','UI tool omitted its open programs.');
      const open=Array.isArray(row.open_programs)?row.open_programs.map(value=>{check(value);return selected;}):[];
      return {name:row.name,hasProgramManager:row.has_program_manager,current:row.current_program===undefined?null:selected,open};});
    return {tools,count:tools.length};
  }
  if(operation==='goto'){
    if(value.success!==true||address(value.address)!==address(p.address))fail('partial','Navigation did not acknowledge the requested address.');
    return {address:publicAddress(value.address),...(typeof value.function==='string'?{function:value.function}:{})};
  }
  if(operation==='prompt_policy'){
    if(typeof value.enabled!=='boolean'||!Number.isSafeInteger(value.remaining_ms)||Number(value.remaining_ms)<0||typeof value.reason!=='string'||!Array.isArray(value.actions)||value.actions.length>1000)
      fail('partial','Prompt policy status is incomplete.');
    if(p.action==='enable'&&value.enabled!==true||p.action==='disable'&&value.enabled!==false)fail('partial','Prompt policy did not establish the requested state.');
    return value;
  }
  if(operation==='cursor'){
    const result:Record<string,unknown>={};
    for(const facet of ['address','function','selection','program']){
      if(!Object.hasOwn(value,facet)&&typeof value[facet+'_unavailable']!=='string')fail('partial','Cursor omitted a requested facet.');
      if(value[facet]===null||!Object.hasOwn(value,facet)){if(typeof value[facet+'_unavailable']!=='string')fail('partial','Unavailable cursor facet omitted its reason.');result[facet]=null;result[facet+'_unavailable']=value[facet+'_unavailable'];continue;}
      const row=object(value[facet]);
      if(facet==='program'){
        check(row.path);const {path,executable_path,name,...metadata}=row;
        for(const field of ['language','compiler','executable_format'])text(metadata[field]);
        for(const field of ['function_count','symbol_count','data_type_count','memory_size'])if(!Number.isSafeInteger(metadata[field])||Number(metadata[field])<0)fail('partial','Focused program metadata is incomplete.');
        result.program={...metadata,...selected,name:label};
      }else{
        check(row.program);const {program:route,...data}=row;
        if(facet==='address')data.address=publicAddress(row.address);
        if(facet==='function'){text(row.function_name);text(row.signature);data.address=publicAddress(row.address);}
        if(facet==='selection'){
          if(typeof row.is_empty!=='boolean'||!Array.isArray(row.ranges)||row.ranges.length>10000)fail('partial','Cursor selection is incomplete.');
          data.ranges=row.ranges.map(raw=>{const range=object(raw);if(!Number.isSafeInteger(range.length)||Number(range.length)<1)fail('partial','Cursor selection range is invalid.');return {...range,start:publicAddress(range.start),end:publicAddress(range.end)};});
        }
        result[facet]={...data,...selected};
      }
    }
    return result;
  }
  fail('schema','UI operation lacks a result contract.');
}
