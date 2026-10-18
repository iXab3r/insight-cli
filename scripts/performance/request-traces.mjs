import {readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {rows,distribution} from './compare.mjs';
export async function requestTraces(root){
 const trace=[];for(const name of await readdir(join(root,'trace'))){if(name.endsWith('.jsonl'))for(const line of(await readFile(join(root,'trace',name),'utf8')).trim().split('\n').filter(Boolean)){const r=JSON.parse(line),start=BigInt(r.startNs);trace.push({...r,start,end:start+BigInt(r.durationNs)});}}
 const requests=await rows(join(root,'candidate-trace')),selected=requests.filter(r=>!r.warmup&&(r.stage.startsWith('read.')||['cold.open','warm.new-input','prepare.merge','persistence.edit','persistence.merge','persistence.refresh','persistence.read-script'].includes(r.stage))),windows=[];
 for(const r of selected){const start=BigInt(r.startNs),end=start+BigInt(Math.round(r.ms*1e6)),overlaps=selected.filter(other=>other!==r&&BigInt(other.startNs)<end&&BigInt(other.startNs)+BigInt(Math.round(other.ms*1e6))>start);if(overlaps.length)throw Error('Only isolated serial diagnostic windows may be correlated');
  const groups=new Map();for(const span of trace.filter(s=>s.start>=start&&s.end<=end)){const values=groups.get(span.stage)??[];values.push(Number(span.durationNs)/1e6);groups.set(span.stage,values);}
  windows.push({fixture:r.fixture,analysis:r.analysis,route:r.route,stage:r.stage,...r.sample===undefined?{coldTrial:r.coldTrial}:{sample:r.sample},endToEndMs:r.ms,stages:Object.fromEntries([...groups].map(([stage,values])=>[stage,{count:values.length,inclusiveSpanMs:distribution(values)}]))});
 }
 const result={schema:1,correlation:'Each span is wholly contained in an isolated externally timed serial request window. This is temporal correlation, not a cross-process causal ID. Counts retain repeated backend/save/export/hash work. Inclusive span durations overlap; do not sum across stages or processes.',windows};await writeFile(join(root,'trace-request-windows.json'),JSON.stringify(result,null,2)+'\n');return result;
}
if(process.argv[1]===new URL(import.meta.url).pathname)console.log(JSON.stringify({windows:(await requestTraces(process.argv[2])).windows.length}));
