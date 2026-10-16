import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, open, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createCli } from '@eyeauras/cli-factory';
import { createCliFixture } from '@eyeauras/cli-factory/testing';
import { artifactsCommands, saveMaterials, type SavedMaterials } from '../src/saved-materials.js';

async function directory(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'insight-materials-'));
  t.after(() => rm(root, {recursive: true, force: true})); return root;
}
test('file snapshots are independent, include empty files and never overwrite a previous save', async t => {
  const root = await directory(t), appData = join(root, 'profile'), source = join(root, 'finding.txt');
  await writeFile(source, 'first finding');
  const first = await saveMaterials(appData, source);
  await writeFile(source, 'later finding');
  const second = await saveMaterials(appData, source);
  assert.equal(first.state, 'saved'); assert.equal(first.kind, 'file'); assert.equal(first.files, 1);
  assert.equal(first.bytes, 13); assert.equal(first.sha256, createHash('sha256').update('first finding').digest('hex'));
  assert.notEqual(first.path, second.path); assert.equal(await readFile(first.path, 'utf8'), 'first finding');
  assert.equal(await readFile(second.path, 'utf8'), 'later finding');
  await writeFile(source, ''); const empty = await saveMaterials(appData, source);
  assert.equal(empty.files, 1); assert.equal(empty.bytes, 0);
  assert.equal(empty.sha256, createHash('sha256').update('').digest('hex'));
  await assert.rejects(stat(join(appData, 'workspace')));
});
test('directories preserve Unicode paths and empty directories with a deterministic manifest digest', async t => {
  const root = await directory(t), appData = join(root, 'profile'), source = join(root, 'исследование Ω');
  await mkdir(join(source, 'empty', 'nested'), {recursive: true});
  await writeFile(join(source, 'вывод.txt'), 'полезная находка'); await writeFile(join(source, 'empty-file'), '');
  const [first, second] = await Promise.all([saveMaterials(appData, source), saveMaterials(appData, source)]);
  assert.equal(first.kind, 'directory'); assert.equal(first.files, 2);
  assert.equal(first.bytes, Buffer.byteLength('полезная находка')); assert.equal(first.sha256, second.sha256);
  assert.equal((await stat(join(first.path, 'empty', 'nested'))).isDirectory(), true);
  assert.equal(await readFile(join(first.path, 'вывод.txt'), 'utf8'), 'полезная находка');
  const manifest = await readFile(join(dirname(dirname(first.path)), 'manifest.json'), 'utf8');
  assert.equal(first.sha256, createHash('sha256').update(manifest).digest('hex'));
  assert.ok(!manifest.includes(root));
  const emptySource = join(root, 'empty'); await mkdir(emptySource);
  const empty = await saveMaterials(appData, emptySource);
  assert.equal(empty.files, 0); assert.equal(empty.bytes, 0); assert.deepEqual(await readdir(empty.path), []);
});
test('symlinks and special files reject the whole save without following or silently dropping entries', {skip: process.platform === 'win32' && 'POSIX symlink/FIFO creation requires privileges unavailable in portable Windows CI'}, async t => {
  const root = await directory(t), appData = join(root, 'profile'), source = join(root, 'source');
  await mkdir(source); await writeFile(join(source, 'ordinary.txt'), 'kept only on a complete save');
  await symlink(join(source, 'ordinary.txt'), join(source, 'link'));
  await assert.rejects(saveMaterials(appData, source), /symbolic links/);
  await assert.rejects(saveMaterials(appData, join(source, 'link')), /symbolic links/);
  assert.deepEqual(await readdir(join(appData, 'materials')), []);
  await rm(join(source, 'link'));
  if (process.platform !== 'win32') {
    await promisify(execFile)('mkfifo', [join(source, 'pipe')]);
    await assert.rejects(saveMaterials(appData, source), /special files/);
    assert.deepEqual(await readdir(join(appData, 'materials')), []);
  }
});
test('sources containing destination storage and redirected storage are rejected', async t => {
  const root = await directory(t), appData = join(root, 'profile');
  await assert.rejects(saveMaterials(appData, root), /contains the materials storage/);
  if (process.platform === 'win32') return;
  const other = join(root, 'other'); await mkdir(other);
  await symlink(other, join(appData, 'materials'));
  const source = join(root, 'file'); await writeFile(source, 'source');
  await assert.rejects(saveMaterials(appData, source), /profile-owned/);
  assert.deepEqual(await readdir(other), []);
});
test('a changing source aborts the snapshot and removes partially copied bytes', async t => {
  const root = await directory(t), appData = join(root, 'profile'), source = join(root, 'large-file');
  const handle = await open(source, 'wx'); await handle.truncate(64 * 1024 * 1024); await handle.close();
  let stopped = false, changed = false;
  const mutate = (async () => {
    while (!stopped) {
      const storage = await readdir(join(appData, 'materials')).catch(() => []);
      if (storage.some(name => name.startsWith('.pending-'))) {
        // Once staging has begun, the pre-copy inventory has captured the original state.
        const writer = await open(source, 'r+'); try { await writer.write(Buffer.from('changed'), 0, 7, 0); } finally { await writer.close(); }
        changed = true; return;
      }
      await new Promise(resolve => setTimeout(resolve, 1));
    }
  })();
  try { await assert.rejects(saveMaterials(appData, source), /changed/); }
  finally { stopped = true; await mutate; }
  assert.equal(changed, true); assert.deepEqual(await readdir(join(appData, 'materials')), []);
});
test('cancelled and missing inputs report clean errors without leaking source paths', async t => {
  const root = await directory(t), appData = join(root, 'profile'), controller = new AbortController();
  controller.abort();
  await assert.rejects(saveMaterials(appData, join(root, 'missing'), controller.signal), /cancelled/);
  await assert.rejects(saveMaterials(appData, join(root, 'missing')), error => {
    assert.match(String(error), /ENOENT/); assert.ok(!String(error).includes(root)); return true;
  });
  await assert.rejects(stat(appData));
});
test('public command enforces Update and separates profile storage without creating Ghidra state', async t => {
  const fixture = await createCliFixture(t, {applicationId: 'insight-materials', profiles: [{name: 'default'}, {name: 'other'}]});
  const app = fixture.createApplication(runtime => createCli({name: 'insight-materials', applicationId: 'insight-materials', version: '0.1.0', description: 'Materials fixture', runtime, permissions: {}, commands: artifactsCommands()}));
  const source = join(fixture.root, 'a finding.txt'); await writeFile(source, 'a concrete finding');
  const denied = await fixture.run(app, ['artifacts', 'save', source, '--json']);
  assert.notEqual(denied.exitCode, 0); assert.match(denied.stderr, /permission/i);
  await assert.rejects(stat(join(fixture.appArguments.AppDataDirectory, 'materials')));
  await app.execute(['permissions', 'grant', 'Update']);
  const first = await fixture.json(app, ['artifacts', 'save', source]) as SavedMaterials;
  assert.equal(first.state, 'saved'); assert.equal(await readFile(first.path, 'utf8'), 'a concrete finding');
  await app.execute(['permissions', 'grant', 'Update', '--profile', 'other']);
  const other = await fixture.json(app, ['artifacts', 'save', source, '--profile', 'other']) as SavedMaterials;
  assert.ok(other.path.startsWith(fixture.appArguments.WithProfile('other').AppDataDirectory));
  assert.notEqual(first.path, other.path);
  await assert.rejects(stat(join(fixture.appArguments.AppDataDirectory, 'workspace')));
});
