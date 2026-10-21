import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, chmod, symlink, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import { Workspace, type Scope } from '../src/workspace.js';
import { Store } from '../src/store.js';

const settings = {autoAnalyze: true};
async function fixture(t: {after: (action: () => Promise<void>) => void}) {
  const root = await mkdtemp(join(tmpdir(), 'insight-workspace-'));
  const directory = join(root, 'profile');
  const store = new Workspace(directory, 'default');
  const stores = [store];
  function openWorkspace(path = directory, profile = 'default') {
    const selected = new Workspace(path, profile); stores.push(selected); return selected;
  }
  t.after(async () => { for (const selected of stores) selected.close(); await rm(root, {recursive: true, force: true}); });
  async function file(name: string, contents: string) {
    const path = join(root, name); await mkdir(join(path, '..'), {recursive: true});
    await writeFile(path, contents); return path;
  }
  return {root, directory, store, file, openWorkspace};
}

test('consumed bytes determine identity, immutable copies survive source edits, same basename is no selector', async t => {
  const {store, file} = await fixture(t);
  const a = await file('a/client.exe', 'first executable');
  const b = await file('b/client.exe', 'second executable');
  const duplicate = await file('c/different.exe', 'first executable');
  const [target, other, again] = await Promise.all([store.importTarget(a), store.importTarget(b), store.importTarget(duplicate)]);
  assert.equal(target.id, again.id); assert.notEqual(target.id, other.id);
  assert.equal(target.name, again.name); assert.ok(['client.exe', 'different.exe'].includes(target.name));
  assert.equal(other.name, 'client.exe');
  await writeFile(a, 'modified executable');
  assert.equal(await readFile(await store.artifacts.verify(target.input), 'utf8'), 'first executable');
  assert.notEqual((await store.importTarget(a)).id, target.id);
  assert.equal(store.targets().length, 3);
  await assert.rejects(store.importTarget(await file('empty.exe', '')), /nonempty regular file/);
});

test('schema upgrade preserves version-one research and prevents older readers from ignoring new request identities',async t=>{
  const {store,directory,file,openWorkspace}=await fixture(t),target=await store.importTarget(await file('fixture.exe','fixture'));
  const research=store.reserveOpen(target.id,'new',settings,'old-open');
  const sql=new DatabaseSync(join(directory,'workspace.sqlite'));
  try{
    sql.exec('DROP TABLE administration_requests; PRAGMA user_version=1;');
    assert.throws(()=>new Workspace(directory,'other'),/different profile/);assert.equal(sql.prepare('PRAGMA user_version').get()?.user_version,1);
    const upgraded=openWorkspace();assert.equal(upgraded.request(research.request.id).callerId,'old-open');
    assert.equal(sql.prepare('PRAGMA user_version').get()?.user_version,5);
    upgraded.reserveAdministration('server.connect',{},'new-admin');
    assert.throws(()=>upgraded.reserveOpen(target.id,research.context.session,settings,'new-admin'),/administration operation/);
    sql.exec('PRAGMA user_version=6;');assert.throws(()=>new Workspace(directory,'default'),/newer than this build/);
  }finally{sql.close();}
});

test('profile identity rejects foreign workspaces and selectors while old coordinator journals remain intact', async t => {
  const {store, directory, root, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const other = openWorkspace(join(root, 'other'), 'other');
  const foreign = await other.importTarget(await file('copy.exe', 'fixture'));
  assert.notEqual(target.id, foreign.id);
  assert.throws(() => other.target(target.id), /selected profile/);
  assert.throws(() => new Workspace(directory, 'other'), /different profile/);
  const old = new Store(directory, 'default', 'ghidra://127.0.0.1:14100');
  const oldTarget = old.register({profile: 'default', server: 'ghidra://127.0.0.1:14100', repository: 'owned',
    programPath: '/fixture.exe', binarySha256: 'a'.repeat(64), language: 'x86:LE:64:default', compilerSpec: 'windows', imageBase: '140000000'});
  old.close();
  const reopened = new Store(directory, 'default', 'ghidra://127.0.0.1:14100');
  try { assert.deepEqual(reopened.targets(), [oldTarget]); } finally { reopened.close(); }
  assert.equal(store.targets().length, 1);
});

test('open retry reserves one new session durably; equal context tuples share state, distinct agents and targets do not', async t => {
  const {store, directory, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('client.exe', 'client'));
  const other = await store.importTarget(await file('helper.exe', 'helper'));
  const opened = store.reserveOpen(target.id, 'new', settings, 'open-A');
  const reopened = openWorkspace();
  const replay = reopened.reserveOpen(target.id, 'new', settings, 'open-A');
  assert.equal(replay.replay, true); assert.equal(replay.request.id, opened.request.id);
  assert.equal(replay.context.session, opened.context.session); assert.equal(store.sessions().length, 1);
  const continued = reopened.reserveOpen(target.id, opened.context.session, settings);
  assert.equal(continued.context.id, opened.context.id); assert.notEqual(continued.request.id, opened.request.id);
  const b = store.reserveOpen(target.id, 'new', settings);
  const helper = store.reserveOpen(other.id, opened.context.session, settings);
  assert.notEqual(b.context.id, opened.context.id); assert.notEqual(helper.context.id, opened.context.id);
  assert.equal(store.contexts(opened.context.session).length, 2);
  assert.throws(() => store.reserveOpen(other.id, 'new', settings, 'open-A'), /different effective input/);
  assert.throws(() => store.reserveOpen(target.id, 'new', {...settings, language: 'other'}), /different Ghidra load settings/);
  assert.equal(store.sessions().length, 2, 'Rejected settings must not leak a new session');
});

test('real concurrent processes reserve one context and request without leaking sessions', async t => {
  const {store, directory, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const source = `import{Workspace}from ${JSON.stringify(new URL('../src/workspace.js', import.meta.url).href)};
    const s=new Workspace(process.argv[1],'default');
    try{const r=s.reserveOpen(process.argv[2],'new',{autoAnalyze:true},'concurrent-open');console.log(JSON.stringify(r));}finally{s.close();}`;
  async function run(): Promise<{context: {id: string}; request: {id: string}}> {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--input-type=module', '-e', source, directory, target.id], {stdio: ['ignore', 'pipe', 'pipe']});
      let output = '', errors = '';
      child.stdout.on('data', chunk => { output += chunk; }); child.stderr.on('data', chunk => { errors += chunk; });
      child.on('error', reject); child.on('exit', code => {
        if (code !== 0) reject(new Error(errors)); else { try { resolve(JSON.parse(output)); } catch (error) { reject(error); } }
      });
    });
  }
  const results = await Promise.all([run(), run(), run(), run()]);
  assert.equal(new Set(results.map(value => value.context.id)).size, 1);
  assert.equal(new Set(results.map(value => value.request.id)).size, 1); assert.equal(store.sessions().length, 1);
});

test('saved private and base snapshots survive restart; stale save cannot overwrite newer local changes', async t => {
  const {store, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const a = store.reserveOpen(target.id, 'new', settings).context;
  const b = store.reserveOpen(target.id, 'new', settings).context;
  const base = await store.captureSnapshot(await file('base.gzf', 'synthetic base snapshot'));
  const local = await store.captureSnapshot(await file('local.gzf', 'synthetic private snapshot'));
  store.establishModel(target.id, 1, base);
  const scope: Scope = {session: a.session, target: a.target};
  store.saveContext(scope, 0, {state: 'ready', baseRevision: 1, baseSnapshot: base, workingSnapshot: base});
  store.saveContext(scope, 1, {workingSnapshot: local, scalars: [{address: '140001000', field: 'comment.eol', original: null, local: 'private'}], complexChanges: ['type-change']});
  const reopened = openWorkspace();
  const observed = reopened.context(scope);
  assert.equal(observed.workingSnapshot?.id, local.id); assert.equal(observed.baseSnapshot?.id, base.id);
  assert.equal(observed.scalars[0]?.local, 'private'); assert.deepEqual(observed.complexChanges, ['type-change']);
  assert.equal(reopened.context(b).state, 'opening');
  assert.throws(() => reopened.saveContext(scope, 1, {workingSnapshot: base}), /Context changed/);
  assert.equal(store.context(scope).workingSnapshot?.id, local.id);
  assert.throws(() => store.saveContext(b, 0, {state: 'ready'}), /durable private and base/);
  assert.throws(() => store.saveContext(scope, 2, {workingSnapshot: {...local, sha256: 'f'.repeat(64), id: 'snapshot:' + 'f'.repeat(64)}}), /captured immutable/);
});

test('request retries retain recorded outcomes and never claim an unresolved operation applied', async t => {
  const {store, directory, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const context = store.reserveOpen(target.id, 'new', settings).context;
  const accepted = store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'private'}, 'edit-1');
  store.startRequest(accepted.request.id);
  const restarted = openWorkspace();
  const running = restarted.reserveRequest(context, 'ghidra.comments.set', {text: 'private', address: '140001000'}, 'edit-1');
  assert.equal(running.replay, true); assert.equal(running.request.state, 'running');
  assert.throws(() => restarted.startRequest(running.request.id), /already started/);
  restarted.recordRequest(running.request.id, 'unknown', {...context, state: 'unknown'});
  assert.equal(store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'private'}, 'edit-1').request.state, 'unknown');
  const sql = new DatabaseSync(join(directory, 'workspace.sqlite'));
  try {
    const shadow = {...running.request, id: 'q_blocked_retry', callerId: running.request.id, state: 'accepted'};
    sql.prepare('INSERT INTO requests SELECT ?, ?, hash, context, ?, ? FROM requests WHERE id=?')
      .run(shadow.id, shadow.callerId, shadow.state, JSON.stringify(shadow), running.request.id);
  } finally { sql.close(); }
  assert.equal(store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'private'}, running.request.id).request.id, running.request.id);
  assert.equal(store.request('q_blocked_retry').state, 'accepted');
  assert.throws(() => store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'different'}, running.request.id), /different effective input/);
  const other = store.reserveOpen(target.id, 'new', settings).context;
  assert.throws(() => store.reserveRequest(other, 'ghidra.comments.set', {address: '140001000', text: 'private'}, running.request.id), /different effective input/);
  assert.throws(() => store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'different'}, 'edit-1'), /different effective input/);
  const result = {session: context.session, target: target.id, state: 'applied'};
  store.recordRequest(running.request.id, 'applied', result);
  assert.deepEqual(restarted.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'private'}, 'edit-1').request.result, result);
  assert.throws(() => store.recordRequest(running.request.id, 'failed', {}), /immutable/);
  const newIntent = store.reserveRequest(context, 'ghidra.comments.set', {address: '140001000', text: 'private'});
  assert.notEqual(newIntent.request.id, running.request.id);
});

test('artifact corruption and symlink substitution fail instead of changing the target identity', async t => {
  const {store, file} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const saved = store.artifacts.path(target.input);
  await chmod(saved, 0o600); await writeFile(saved, 'changed');
  await assert.rejects(store.artifacts.verify(target.input), /contents changed/);
  await assert.rejects(store.importTarget(await file('copy.exe', 'fixture')), /contents changed/);
  await unlink(saved); await symlink(await file('outside.bin', 'fixture'), saved);
  await assert.rejects(store.artifacts.verify(target.input));
  assert.equal(store.target(target.id).binarySha256, target.binarySha256);
});

test('saved state and request outcome commit together; rejected acknowledgement rolls back context', async t => {
  const {store, directory, file, openWorkspace} = await fixture(t);
  const target = await store.importTarget(await file('fixture.exe', 'fixture'));
  const opened = store.reserveOpen(target.id, 'new', settings);
  const base = await store.captureSnapshot(await file('base.gzf', 'synthetic base'));
  store.establishModel(target.id, 1, base);
  assert.throws(() => store.completeSavedRequest(opened.context, opened.request.id, 0,
    {state: 'ready', baseRevision: 1, baseSnapshot: base, workingSnapshot: base}, {state: 'applied'}), /must start/);
  assert.equal(store.context(opened.context).generation, 0);
  store.startRequest(opened.request.id);
  const result = {session: opened.context.session, target: target.id, state: 'ready'};
  store.completeSavedRequest(opened.context, opened.request.id, 0,
    {state: 'ready', baseRevision: 1, baseSnapshot: base, workingSnapshot: base}, result);
  const restarted = openWorkspace();
  assert.equal(restarted.context(opened.context).state, 'ready');
  assert.deepEqual(restarted.request(opened.request.id).result, result);
  const other = store.reserveOpen(target.id, 'new', settings).context;
  const request = store.reserveRequest(other, 'ghidra.comments.set', {}).request;
  store.startRequest(request.id);
  assert.throws(() => store.completeSavedRequest(opened.context, request.id, 1, {state: 'stopped'}, {}), /different working context/);
  assert.equal(store.context(opened.context).generation, 1);
});
