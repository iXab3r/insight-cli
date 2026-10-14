import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {scriptInventory} from '../src/scripts.js';

test('script inventory discovers installation/context scripts, pages deterministic IDs and excludes linked external files',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli'}),home=join(f.root,'installation'),context=join(f.root,'context');
  const bundled=join(home,'Ghidra/Features/Base/ghidra_scripts'),local=join(context,'ghidra_scripts');
  await mkdir(bundled,{recursive:true});await mkdir(local,{recursive:true});
  await writeFile(join(bundled,'Hello.java'),'// @category Examples\npublic class Hello {}');
  await writeFile(join(bundled,'Read.py'),'# @category Inspection\nprint(1)');
  await writeFile(join(local,'Private.java'),'// owned context script');
  await writeFile(join(f.root,'outside.java'),'// never part of this inventory');
  if(process.platform!=='win32')await symlink(join(f.root,'outside.java'),join(local,'Linked.java'));
  const first=await scriptInventory(home,context,'',1,0);assert.equal(first.total,3);assert.equal(first.count,1);assert.equal(first.truncated,true);
  assert.equal(first.items[0]!.script,'context:Private.java');
  const installed=await scriptInventory(home,context,'Examples',10,0);assert.equal(installed.total,1);
  assert.deepEqual(installed.items[0],{script:'installation:Features/Base/Hello.java',name:'Hello.java',language:'Java',origin:'installation',category:'Examples'});
  assert.ok(!JSON.stringify(installed).includes(f.root));
});
