import {readdir,open} from 'node:fs/promises';
import {join,relative,sep} from 'node:path';
import {constants} from 'node:fs';
import {fail} from './model.js';

export interface ScriptItem {script:string;name:string;language:'Java'|'Python';origin:'installation'|'context';category?:string}
export interface ScriptPage {items:ScriptItem[];count:number;total:number;offset:number;limit:number;truncated:boolean}
/** Resolve only an explicit inventory ID; native search paths never choose another script. */
export async function scriptPath(home:string,contextRoot:string,script:string):Promise<string> {
  if(!/^(installation|context):[^\0]+\.(java|py)$/.test(script)||script.includes('..')||script.includes('\\'))
    fail('invalid','Choose an explicit script ID returned by ghidra scripts list.');
  const page=await scriptInventory(home,contextRoot,script,20000,0),item=page.items.find(item=>item.script===script);
  if(!item)fail('notFound','Script ID is absent from this context and installation.');
  const part=script.slice(script.indexOf(':')+1);
  if(item.origin==='context')return join(contextRoot,'ghidra_scripts',part);
  const segments=part.split('/'),filename=segments.pop()!;
  return join(home,'Ghidra',...segments,'ghidra_scripts',filename);
}
/** Enumerate configured installation and owned context scripts without exposing native paths. */
export async function scriptInventory(home:string,contextRoot:string,filter:string,limit:number,offset:number):Promise<ScriptPage> {
  const items:ScriptItem[]=[];
  async function scripts(folder:string,origin:ScriptItem['origin'],module:string) {
    let entries;try{entries=await readdir(folder,{withFileTypes:true});}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
    for(const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))) {
      if(!entry.isFile()||!entry.name.endsWith('.java')&&!entry.name.endsWith('.py'))continue;
      if(items.length>=20000)fail('limit','Script inventory exceeds 20000 entries.');
      const name=entry.name,script=origin+':'+(module?module+'/':'')+name;
      const handle=await open(join(folder,name),constants.O_RDONLY|(constants.O_NOFOLLOW??0));let category:string|undefined;
      try{const data=Buffer.alloc(4096),read=await handle.read(data,0,data.length,0);
        if(!(await handle.stat()).isFile())fail('binding','Script inventory file changed during inspection.');
        category=/^\s*(?:\/\/|#)\s*@category\s+([^\r\n]+)/m.exec(data.subarray(0,read.bytesRead).toString('utf8'))?.[1]?.trim().slice(0,256);
      }finally{await handle.close();}
      items.push({script,name,language:name.endsWith('.java')?'Java':'Python',origin,...(category?{category}:{})});
    }
  }
  const installed=join(home,'Ghidra');
  async function modules(folder:string,depth:number) {
    if(depth>16)fail('limit','Script module nesting exceeds 16 levels.');
    for(const entry of (await readdir(folder,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))) {
      if(!entry.isDirectory())continue;
      const path=join(folder,entry.name);
      if(entry.name==='ghidra_scripts')await scripts(path,'installation',relative(installed,folder).split(sep).join('/'));
      else if(!['data','lib','os','src','docs'].includes(entry.name))await modules(path,depth+1);
    }
  }
  await modules(installed,0);await scripts(join(contextRoot,'ghidra_scripts'),'context','');
  const matched=items.filter(item=>!filter||[item.name,item.script,item.category??''].some(value=>value.toLowerCase().includes(filter.toLowerCase())))
    .sort((a,b)=>a.script.localeCompare(b.script));
  const page=matched.slice(offset,offset+limit);
  return {items:page,count:page.length,total:matched.length,offset,limit,truncated:offset+page.length<matched.length};
}
