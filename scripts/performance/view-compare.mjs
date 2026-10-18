import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {Stock} from './stock.mjs';
import {Recorder,hash} from './public.mjs';
const stable=v=>v&&typeof v==='object'?Array.isArray(v)?v.map(stable):Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
export async function compareView(o,manifest){
 const f=manifest.fixtures[0],r=new Recorder(o.root,{fixture:f.name,analysis:f.analyzed,label:'view-comparison'}),s=new Stock(o,join(o.root,'jvm'),r);let expected;
 const before=await readFile(resolve(dirname(o.cli),'../../references/native/InsightResearchQueries.java'),'utf8'),after=await readFile(o['view-source'],'utf8');
 const sources={before,after};await writeFile(join(o.root,'sources.json'),JSON.stringify({before:hash(before),after:hash(after)}));
 try{
  await s.start();await s.call('create_project',{name:'owned',parentDir:s.root});await s.call('import_program',{gzf_path:f.prepared,target_folder:'/',target_name:'program',overwrite:false});await s.call('open_program',{path:s.program});
  for(let i=-o.warmups;i<o.warm;i++)for(const variant of i%2?['after','before']:['before','after']){
   const source=sources[variant],base=source.match(/public class (\w+)/)[1],code=source.replace('public class '+base+' ','public class '+base+'_'+randomUUID().replaceAll('-','')+' ');
   await s.scoped('run_script_inline',{code,args:Buffer.from(JSON.stringify({operation:'/research_view',parameters:{}})).toString('base64')},{stage:'component.view',label:variant,sample:i,warmup:i<0,validate:result=>{assert.equal(result.success,true);const found=[...result.console_output.matchAll(/^INSIGHT_QUERY:(.+)$/gm)];assert.equal(found.length,1);const v=JSON.parse(found[0][1]).value;assert.equal(v.read_only.modification_unchanged,true);const observed=JSON.stringify(stable(v));expected??=observed;assert.equal(observed,expected);}});
  }
 }finally{await s.close();await writeFile(join(o.root,'cleanup.json'),JSON.stringify({ownedNativeExited:!s.child||s.child.exitCode!==null||s.child.signalCode!==null,bridgeClosed:true}));}
}
