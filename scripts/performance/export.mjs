import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,resolve,sep} from 'node:path';
import {summarize} from './compare.mjs';
import {traceReport} from './trace-report.mjs';
import {phasedRows} from './finalize.mjs';
export async function exportEvidence(root,destination){
 assert.ok(resolve(destination)!==resolve(root)&&!resolve(destination).startsWith(resolve(root)+sep),'Public export must be outside its source evidence tree');
 await mkdir(destination,{recursive:true});const all=await phasedRows(root),id=JSON.parse(await readFile(join(root,'identity.json'),'utf8'));
 const publicRows=all.map(r=>Object.fromEntries(['evidencePhase','label','fixture','analysis','coldTrial','cache','n','stage','route','sample','warmup','pid','exitStatus','censored','resultHash','componentCalls','jarSha256','startNs','ms','observerMs','loadAtEnd','ok','failure'].filter(k=>r[k]!==undefined).map(k=>[k,r[k]])));
 const identity={...id,ghidraProperties:undefined,java:id.java.split('\n')[0],ghidraVersion:id.ghidraProperties.match(/^application.version=(.*)$/m)?.[1],bridge:{commit:id.bridge.commit,clean:id.bridge.status==='',python:id.bridge.python,packages:id.bridge.packages}};
 const outputs={'identity.json':JSON.stringify(identity,null,2),'requests.jsonl':publicRows.map(r=>JSON.stringify(r)).join('\n'),'summary.json':JSON.stringify(summarize(publicRows),null,2)};
 for(const name of ['gate.json','equivalence.json','coverage.json','trace-coverage.json','trace-request-windows.json','script-effects.json','phases.json','summary-by-phase.json','summary-warm-by-phase.json','storage-addendum.json','stock-environment.json','candidate-update.json','postprocess.json']){try{outputs[name]=await readFile(join(root,name),'utf8');}catch(e){if(e.code!=='ENOENT')throw e;}}
 try{outputs['trace-summary.json']=JSON.stringify(await traceReport(join(root,'trace')),null,2);}catch(e){if(e.code!=='ENOENT')throw e;}
 for(const [name,content]of Object.entries(outputs)){assert.ok(!/\/Users\/|\/home\/|Bearer\s|[A-Z_]*(?:AUTH_TOKEN|API_KEY)\s*[=:]/i.test(content),'Private data in '+name);await writeFile(join(destination,name),content+'\n');}
}
if(process.argv[1]===new URL(import.meta.url).pathname)await exportEvidence(process.argv[2],process.argv[3]);
