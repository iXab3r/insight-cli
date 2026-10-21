import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export function semanticCliResult(input){
 const v=structuredClone(input);delete v.session;delete v.target;
 if(v.value?.view){assert.equal(typeof v.value.view.identity,'string');delete v.value.view.identity;}
 if(v.value?.revision){
  const r=v.value.revision;
  // Native provider identities vary between independently imported programs/processes.
  assert.equal(typeof r.epoch,'string');assert.equal(typeof r.token,'string');assert.ok(Number.isSafeInteger(r.saved_time));
  delete r.epoch;delete r.saved_time;delete r.token;
  // Preserve modification_number, unsaved_changes, decompiled and every other field.
 }
 return canonical(v);
}
/** Reverify recorded leaf results; no native calls or reconstruction from result hashes. */
export async function compareRecordedPair(root){
 const results=Object.fromEntries(await Promise.all(['before','after'].map(async label=>[label,JSON.parse(await readFile(join(root,label,'result.json'),'utf8'))])));
 assert.equal(results.before.inputHash,results.after.inputHash);
 for(const operation of ['memory-32','inspect-entry','context-status']){
  const semantic={};
  for(const label of ['before','after']){
   const raw=JSON.parse(await readFile(join(root,label,operation+'-one-shot.json'),'utf8'));
   assert.equal(raw.session,results[label].scope.session);assert.equal(raw.target,results[label].scope.target);
   semantic[label]=sha(semanticCliResult(raw));
   for(const row of results[label].rows.filter(x=>x.operation===operation)){
    assert.equal(row.outputSha256,sha(raw),'Every captured response must equal the retained raw sample within its own fixture');
    row.semanticSha256=semantic[label];
   }
  }
  assert.equal(semantic.before,semantic.after,'Different semantic result: '+operation);
 }
 const clients=await Promise.all(['before','after'].map(label=>readFile(results[label].persistentClient)));assert.ok(clients[0].equals(clients[1]));
 return {schema:1,passed:true,commonClientSha256:createHash('sha256').update(clients[0]).digest('hex'),buildOrder:'Counterbalanced before/after and after/before per round; leaf transport/operation order unchanged; both warm contexts retained until both workloads finish; no overlapping queries',comparison:'Every measured raw response hash matches its retained raw warmup sample. Semantic comparison sorts object keys and excludes only scope, view.identity and native revision epoch/saved_time/token; modification_number and flags remain.',...results};
}
