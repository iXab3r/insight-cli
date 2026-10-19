import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
export async function scriptEffects(root,cold=5){
 const observations=[];
 for(const label of ['baseline','candidate'])for(const fixture of ['tiny','large'])for(const analysis of [false,true])for(let trial=0;trial<cold;trial++){
  const directory=join(root,label,`${fixture}-${analysis?'analysis':'no-analysis'}-${trial}`),records=(await readFile(join(directory,'requests.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),states=[];
  for(const stage of ['state.before-read-script','state.after-read-script']){const selected=records.filter(r=>r.stage===stage);assert.equal(selected.length,1);assert.equal(selected[0].ok,true);states.push(JSON.parse(await readFile(join(directory,selected[0].n+'.stdout'),'utf8')).ghidra);}
  const [before,after]=states;for(const state of states){assert.equal(state.state,'ready');assert.ok(Number.isSafeInteger(state.pendingChanges)&&state.pendingChanges>=0);assert.ok(typeof state.baseRevision==='string'&&state.baseRevision.length>0);assert.ok(typeof state.sharedRevision==='string'&&state.sharedRevision.length>0);assert.deepEqual(state.unresolvedRequests,[]);}assert.equal(before.baseRevision,after.baseRevision);assert.equal(before.sharedRevision,after.sharedRevision);
  observations.push({label,fixture,analysis,coldTrial:trial,pendingBefore:before.pendingChanges,pendingAfter:after.pendingChanges,baseRevisionUnchanged:true,sharedRevisionUnchanged:true,unresolvedRequests:0});
 }
 const failures=[];for(const row of observations.filter(r=>r.label==='baseline')){const peer=observations.find(r=>r.label==='candidate'&&r.fixture===row.fixture&&r.analysis===row.analysis&&r.coldTrial===row.coldTrial);if(peer.pendingBefore!==row.pendingBefore||peer.pendingAfter!==row.pendingAfter)failures.push({fixture:row.fixture,analysis:row.analysis,coldTrial:row.coldTrial});}
 const result={schema:1,passed:failures.length===0,observations,failures,meaning:'A program-only println script uses the ordinary opaque-program mutation/save/export path. Pending-change tracking is observed, not bypassed merely because the submitted script looks read-only.'};await writeFile(join(root,'script-effects.json'),JSON.stringify(result,null,2)+'\n');return result;
}
if(process.argv[1]===new URL(import.meta.url).pathname){const r=await scriptEffects(process.argv[2],Number(process.argv[3]??5));console.log(JSON.stringify({passed:r.passed,observations:r.observations.length}));if(!r.passed)process.exitCode=1;}
