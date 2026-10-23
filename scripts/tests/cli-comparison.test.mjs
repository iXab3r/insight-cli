import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {semanticCliResult,compareRecordedPair} from '../benchmark-cli-compare.mjs';
const sample=(epoch,time)=>({session:'S',target:'T',value:{name:'main',entry_point:'140001000',revision:{epoch,saved_time:time,token:time+':'+epoch+':5',modification_number:5,unsaved_changes:false,decompiled:false},view:{identity:epoch,revision:'R1'},items:[1,2]}});
test('cross-fixture identities and JSON key order normalize, while program changes and array order remain observable',()=>{
 const a=sample('old',1),b=sample('new',2);b.session='other';b.target='another';assert.deepEqual(semanticCliResult(a),semanticCliResult(b));
 for(const mutate of [v=>v.value.revision.modification_number++,v=>v.value.revision.unsaved_changes=true,v=>v.value.entry_point='140002000',v=>v.value.items.reverse(),v=>v.value.view.revision='R2']){
  const changed=structuredClone(b);mutate(changed);assert.notDeepEqual(semanticCliResult(a),semanticCliResult(changed));
 }
 const reversed=Object.fromEntries(Object.entries(a).reverse());assert.deepEqual(semanticCliResult(a),semanticCliResult(reversed));
});
test('recorded comparison binds every measured response to retained raw bytes and validates the requested scope',async t=>{
 const root=await mkdtemp(join(tmpdir(),'cli-compare-'));t.after(()=>rm(root,{recursive:true,force:true}));const client=join(root,'client.js');await writeFile(client,'fixture client');
 for(const label of ['before','after']){
  const directory=join(root,label);await mkdir(directory);const raw=sample(label,label==='before'?1:2),hash=createHash('sha256').update(JSON.stringify(raw)).digest('hex');
  const rows=[];for(const operation of ['memory-32','inspect-entry','context-status']){await writeFile(join(directory,operation+'-one-shot.json'),JSON.stringify(raw));rows.push({operation,outputSha256:hash},{operation,outputSha256:hash});}
  await writeFile(join(directory,'result.json'),JSON.stringify({scope:{session:'S',target:'T'},inputHash:'same',persistentClient:client,rows}));
 }
 assert.equal((await compareRecordedPair(root)).passed,true);
 const path=join(root,'after/result.json');const {readFile}=await import('node:fs/promises');const data=JSON.parse(await readFile(path));data.rows.at(-1).outputSha256='corrupted';await writeFile(path,JSON.stringify(data));await assert.rejects(compareRecordedPair(root),/Every captured response/);
 data.rows.at(-1).outputSha256=data.rows[0].outputSha256;data.scope.session='wrong';await writeFile(path,JSON.stringify(data));await assert.rejects(compareRecordedPair(root));
});
