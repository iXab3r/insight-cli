import {readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {distribution} from './compare.mjs';
export function union(intervals){let total=0,end;for(const [a,b] of intervals.sort((a,b)=>a[0]<b[0]?-1:1)){if(end===undefined||a>end){total+=Number(b-a);end=b;}else if(b>end){total+=Number(b-end);end=b;}}return total;}
export async function traceReport(directory){
 const records=[];for(const name of await readdir(directory)){if(!name.endsWith('.jsonl'))continue;for(const line of (await readFile(join(directory,name),'utf8')).trim().split('\n').filter(Boolean))records.push(JSON.parse(line));}
 const groups=new Map(),parents=new Map(),childrenByParent=new Map();for(const r of records){const key=r.pid+':'+r.request+':'+r.id;parents.set(key,r);if(r.parent!==undefined){const parent=r.pid+':'+r.request+':'+r.parent,list=childrenByParent.get(parent)??[];list.push(r);childrenByParent.set(parent,list);}}
 let danglingParents=0;for(const r of records){if(r.parent!==undefined&&!parents.has(r.pid+':'+r.request+':'+r.parent))danglingParents++;const key=r.stage,g=groups.get(key)??[];g.push(r);groups.set(key,g);}
 const stages={};for(const [stage,rows]of groups){const inclusive=rows.map(r=>Number(r.durationNs)/1e6),exclusive=rows.map(r=>{const start=BigInt(r.startNs),end=start+BigInt(r.durationNs),children=(childrenByParent.get(r.pid+':'+r.request+':'+r.id)??[]).map(c=>{const a=BigInt(c.startNs),b=a+BigInt(c.durationNs);return [a>start?a:start,b<end?b:end];}).filter(([a,b])=>b>a);return Math.max(0,Number(r.durationNs)-union(children))/1e6;});stages[stage]={count:rows.length,failed:rows.filter(r=>!r.ok).length,inclusiveMs:distribution(inclusive),exclusiveMs:distribution(exclusive)};}
 return {schema:1,records:records.length,pids:new Set(records.map(r=>r.pid)).size,requests:new Set(records.map(r=>r.pid+':'+r.request)).size,danglingParents,overlap:'Inclusive spans overlap; exclusive durations subtract the union of immediate child intervals. No cross-process span sums.',stages};
}
if(process.argv[1]===new URL(import.meta.url).pathname)console.log(JSON.stringify(await traceReport(process.argv[2]),null,2));
