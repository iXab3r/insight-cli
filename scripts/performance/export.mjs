import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {rows,summarize} from './compare.mjs';
import {traceReport} from './trace-report.mjs';
export async function exportEvidence(root,destination){
 await mkdir(destination,{recursive:true});const all=await rows(root),id=JSON.parse(await readFile(join(root,'identity.json'),'utf8'));
 const publicRows=all.map(r=>Object.fromEntries(['label','fixture','analysis','coldTrial','cache','n','stage','route','sample','warmup','pid','exitStatus','censored','resultHash','componentCalls','jarSha256','startNs','ms','observerMs','loadAtEnd','ok','failure'].filter(k=>r[k]!==undefined).map(k=>[k,r[k]])));
 const identity={...id,ghidraProperties:undefined,java:id.java.split('\n')[0],ghidraVersion:id.ghidraProperties.match(/^application.version=(.*)$/m)?.[1],bridge:{commit:id.bridge.commit,clean:id.bridge.status==='',python:id.bridge.python}};
 const outputs={'identity.json':JSON.stringify(identity,null,2),'requests.jsonl':publicRows.map(r=>JSON.stringify(r)).join('\n'),'summary.json':JSON.stringify(summarize(publicRows),null,2)};
 for(const name of ['gate.json','equivalence.json','phases.json']){try{outputs[name]=await readFile(join(root,name),'utf8');}catch(e){if(e.code!=='ENOENT')throw e;}}
 try{outputs['trace-summary.json']=JSON.stringify(await traceReport(join(root,'trace')),null,2);}catch(e){if(e.code!=='ENOENT')throw e;}
 for(const [name,content]of Object.entries(outputs)){assert.ok(!/\/Users\/|\/home\/|Bearer\s|[A-Z_]*(?:AUTH_TOKEN|API_KEY)\s*[=:]/i.test(content),'Private data in '+name);await writeFile(join(destination,name),content+'\n');}
}
if(process.argv[1]===new URL(import.meta.url).pathname)await exportEvidence(process.argv[2],process.argv[3]);
