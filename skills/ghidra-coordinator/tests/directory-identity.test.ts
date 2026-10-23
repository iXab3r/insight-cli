import {runtimeSelection} from '../src/runtime-selection.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,symlink,rm,realpath,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {realpathSync} from 'node:fs';
import {sameDirectory,ownedDirectory} from '../src/directory-identity.js';

test('directory aliases retain ownership while sibling roots and inner escapes fail',async t=>{
  const root=await realpath(await mkdtemp(join(tmpdir(),'insight-identity-')));t.after(()=>rm(root,{recursive:true,force:true}));
  const owner=join(root,'owner'),other=join(root,'other'),alias=join(root,'alias');
  await mkdir(join(owner,'context','id','stage'),{recursive:true});await mkdir(join(other,'context','id','stage'),{recursive:true});
  await symlink(owner,alias,process.platform==='win32'?'junction':'dir');
  assert.equal(sameDirectory(owner,alias),true);assert.equal(sameDirectory(owner,other),false);
  assert.equal(ownedDirectory(join(alias,'context/id/stage'),owner,['context','id','stage']),true);
  assert.equal(ownedDirectory(join(other,'context/id/stage'),owner,['context','id','stage']),false);
  await symlink(join(other,'context'),join(owner,'escaped'),process.platform==='win32'?'junction':'dir');
  assert.equal(ownedDirectory(join(owner,'escaped/id/stage'),owner,['escaped','id','stage']),false);
});

// Model AppX projection behavior: realpath preserves two spellings of one directory.
test('distinct canonical spellings require matching nonzero directory file IDs',async t=>{
  const root=await realpath(await mkdtemp(join(tmpdir(),'insight-projection-')));t.after(()=>rm(root,{recursive:true,force:true}));
  const owner=join(root,'owner'),alias=join(root,'projection'),other=join(root,'other');
  const id='a'.repeat(64);
  await mkdir(join(owner,'runtime/installations',id,'ghidra'),{recursive:true});await mkdir(other);
  await symlink(owner,alias,process.platform==='win32'?'junction':'dir');
  const selected={schema:1,mode:'managed',id,ghidraHome:join(alias,'runtime/installations',id,'ghidra'),java:join(alias,'runtime/installations',id,'jdk/bin/java'),fingerprint:'b'.repeat(64),selectedAt:'fixture'};
  await writeFile(join(owner,'runtime/selection.json'),JSON.stringify(selected));
  const canonical=realpathSync.native;
  t.mock.method(realpathSync,'native',((path:string)=>resolve(path)) as typeof canonical);
  assert.notEqual(realpathSync.native(owner),realpathSync.native(alias));
  assert.equal(sameDirectory(owner,alias),true);assert.equal(sameDirectory(owner,other),false);
  assert.equal(ownedDirectory(join(alias,'runtime/installations',id,'ghidra'),owner,['runtime','installations',id,'ghidra']),true);
  assert.deepEqual(runtimeSelection(owner),selected);assert.deepEqual(runtimeSelection(alias),selected);
  t.mock.restoreAll();
});
