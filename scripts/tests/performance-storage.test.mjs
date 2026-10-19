import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,access,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {archivePayloads,restorePayloads,verifyClosedProfile,verifyReceiptNotLive} from '../performance/storage.mjs';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
test('reused inaccessible PIDs require readable evidence of a different process',async()=>{
 const receipt={pid:123,root:'/owned/native/context'},denied=()=>{throw Object.assign(new Error('denied'),{code:'EPERM'});};
 await verifyReceiptNotLive(receipt,{probe:denied,inspect:async()=>'/system/unrelated-service'});
 await assert.rejects(verifyReceiptNotLive(receipt,{probe:denied,inspect:async()=>'/java --root /owned/native/context'}),/still live/);
 await assert.rejects(verifyReceiptNotLive(receipt,{probe:denied,inspect:async()=>''}),/Cannot establish/);
 await assert.rejects(verifyReceiptNotLive(receipt,{probe:denied,inspect:async()=>{throw Object.assign(new Error('unreadable'),{code:'EPERM'});}}),/unreadable/);
 await verifyReceiptNotLive(receipt,{probe:denied,inspect:async()=>{throw Object.assign(new Error('gone'),{code:1});}});
});
test('completed fixture storage retains verified compressed backing bytes and restores without overwrite',async t=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'perf-storage-')));t.after(()=>rm(root,{recursive:true,force:true}));const profile=join(root,'profile'),directory=join(profile,'workspace/ghidra-native/owned/view.rep');await mkdir(directory,{recursive:true});
 const source=join(directory,'db.1.gbf'),bytes=Buffer.alloc(1024*1024,7);await writeFile(source,bytes);const journal=join(profile,'workspace/workspace.sqlite');await writeFile(journal,'retained-journal');
 const result=await archivePayloads(profile,join(root,'archives'),{minimum:1});assert.equal(result.archivedFiles,1);await assert.rejects(access(source),{code:'ENOENT'});assert.equal(await readFile(journal,'utf8'),'retained-journal');
 await restorePayloads(result.index);assert.deepEqual(await readFile(source),bytes);await assert.rejects(restorePayloads(result.index),{code:'EEXIST'});assert.deepEqual(await readFile(source),bytes);
});
test('archival refuses live, corrupt or uncertain disposable profiles',async t=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'perf-storage-')));t.after(()=>rm(root,{recursive:true,force:true}));const workspace=join(root,'workspace');await mkdir(join(workspace,'artifacts'),{recursive:true});await mkdir(join(workspace,'server'));await mkdir(join(workspace,'ghidra-native'));
 const bytes=Buffer.from('owned-snapshot'),sha=createHash('sha256').update(bytes).digest('hex');await writeFile(join(workspace,'artifacts',sha+'.gzf'),bytes);const db=new DatabaseSync(join(workspace,'workspace.sqlite'));t.after(()=>db.close());db.exec('CREATE TABLE contexts(data TEXT); CREATE TABLE requests(state TEXT); CREATE TABLE publications(state TEXT); CREATE TABLE administration_requests(state TEXT)');db.prepare('INSERT INTO contexts VALUES(?)').run(JSON.stringify({state:'stopped',workingSnapshot:{sha256:sha}}));await writeFile(join(workspace,'server/local.json'),JSON.stringify({phase:'stopped'}));await verifyClosedProfile(root);
 db.exec("INSERT INTO requests VALUES('unknown')");await assert.rejects(verifyClosedProfile(root),/Unresolved recovery/);db.exec('DELETE FROM requests');await writeFile(join(workspace,'artifacts',sha+'.gzf'),'corrupt');await assert.rejects(verifyClosedProfile(root),/snapshot does not verify/);await writeFile(join(workspace,'artifacts',sha+'.gzf'),bytes);await writeFile(join(workspace,'server/local.json'),JSON.stringify({phase:'running',pid:process.pid}));await assert.rejects(verifyClosedProfile(root));assert.deepEqual(await readFile(join(workspace,'artifacts',sha+'.gzf')),bytes);
});
test('linked fixture backing paths cannot redirect archival outside the owned tree',async t=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'perf-storage-')));t.after(()=>rm(root,{recursive:true,force:true}));const profile=join(root,'profile'),directory=join(profile,'workspace/ghidra-native');await mkdir(directory,{recursive:true});const outside=join(root,'outside.gbf');await writeFile(outside,'preserved');await symlink(outside,join(directory,'foreign.gbf'));
 await assert.rejects(archivePayloads(profile,join(root,'archives'),{minimum:1}),/linked paths/);assert.equal(await readFile(outside,'utf8'),'preserved');
});
