import assert from 'node:assert/strict';
import {readFile,readdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
export function distribution(values){
 assert.ok(values.length);const a=[...values].sort((a,b)=>a-b),q=p=>a[Math.max(0,Math.ceil(p*a.length)-1)],median=q(.5),deviations=a.map(v=>Math.abs(v-median)).sort((a,b)=>a-b),mean=a.reduce((a,b)=>a+b,0)/a.length;
 return {n:a.length,p50:median,p95:q(.95),min:a[0],max:a.at(-1),mean,sd:a.length>1?Math.sqrt(a.reduce((s,v)=>s+(v-mean)**2,0)/(a.length-1)):0,mad:deviations[Math.ceil(deviations.length/2)-1]};
}
export async function rows(root){const out=[];for(const e of await readdir(root,{withFileTypes:true})){const path=join(root,e.name);if(e.isDirectory())out.push(...await rows(path));else if(e.name==='requests.jsonl')out.push(...(await readFile(path,'utf8')).trim().split('\n').filter(Boolean).map(x=>JSON.parse(x)));}return out;}
export function summarize(rows){const groups=new Map();for(const row of rows.filter(r=>!r.warmup)){const key=[row.label,row.fixture,row.analysis?'analysis':'no-analysis',row.route,row.stage].join('/'),a=groups.get(key)??[];a.push(row);groups.set(key,a);}return Object.fromEntries([...groups].map(([key,a])=>[key,{...a.some(r=>r.ok)?distribution(a.filter(r=>r.ok).map(r=>r.ms)):{n:0},failures:a.filter(r=>!r.ok).length,censored:a.filter(r=>r.censored).length}]));}
if(process.argv[1]===new URL(import.meta.url).pathname){const roots=process.argv.slice(2);assert.ok(roots.length);const all=(await Promise.all(roots.map(root=>rows(resolve(root))))).flat();console.log(JSON.stringify(summarize(all),null,2));}
