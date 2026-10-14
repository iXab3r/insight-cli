import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { spawn, execFile, type ChildProcess } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, readdir, cp, realpath } from 'node:fs/promises';
import { join, delimiter, resolve, isAbsolute, sep } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CommandContext } from '@eyeauras/cli-factory';
import { assertIdentity, fail, key, object, text, version, type Batch, type Binding, type FindingRecord, type Identity, type Snapshot, type Target } from './model.js';
import { HttpBridge, decodeMcp } from './transport.js';
import type { Publisher } from './coordinator.js';

async function durable(path: string, value: unknown) {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(value)); await file.sync(); } finally { await file.close(); }
}
const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ESRCH') return false; throw e; } };
async function freePort(): Promise<number> {
  const server = createServer(); await new Promise<void>((ok, bad) => { server.once('error', bad); server.listen(0, '127.0.0.1', ok); });
  const address = server.address(); if (!address || typeof address === 'string') fail('launch', 'Could not allocate a worker endpoint.');
  await new Promise<void>(ok => server.close(() => ok())); return address.port;
}
interface ProcessRecord { binding: Binding; http: HttpBridge; child?: ChildProcess; client?: Client; transport?: StdioClientTransport }

export class GhidraRuntime implements Publisher {
  constructor(private directory: string, private context: CommandContext, private processes = new Map<string, ProcessRecord>()) {}
  fork(context: CommandContext) { return new GhidraRuntime(this.directory, context, this.processes); }
  private async launch(t: Target, label: string, role: Binding['role']): Promise<Binding> {
    assertIdentity(t, { ...t, profile: this.context.profile.name, server: String(this.context.profile.values.server) });
    const values = this.context.profile.values;
    const java = text(values.java), home = text(values.ghidraHome), jar = text(values.mcpJar), expected = text(values.mcpJarSha256).toLowerCase();
    if (![java, home, jar].every(isAbsolute)) fail('configuration', 'Java, Ghidra home and MCP jar must be absolute paths.');
    if (createHash('sha256').update(await readFile(jar)).digest('hex') !== expected) fail('binding', 'GhidraMCP jar SHA256 does not match the configured artifact.');
    const root = join(this.directory, 'processes', label);
    if (resolve(root).split(sep).some(p => p.startsWith('.'))) fail('configuration', 'Ghidra project AppData path contains a hidden component; use a supported OS AppData root.');
    await mkdir(root, { recursive: true, mode: 0o700 });
    const receipt = join(root, 'process.json');
    try { await readFile(receipt); fail('blocked', 'Process stage already exists; recover it instead of creating a new writer.'); }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
    const jars: string[] = [jar];
    const collect = async (folder: string): Promise<void> => { for (const item of await readdir(folder, { withFileTypes: true })) { const path = join(folder, item.name); if (item.isDirectory()) await collect(path); else if (item.isFile() && path.endsWith('.jar')) jars.push(path); } };
    await collect(join(home, 'Ghidra'));
    const port = await freePort();
    const url = new URL(t.server);
    const user = text(values[role === 'reader' ? 'readerUser' : 'publisherUser']);
    if (values.readerUser === values.publisherUser) fail('authorization', 'Reader and publisher must use distinct Ghidra Server accounts.');
    const password = await this.context.secrets.require(role === 'reader' ? 'readerPassword' : 'publisherPassword');
    const bridgeSecret = role === 'publisher' ? 'bridge-' + label : undefined;
    const bridgeToken = bridgeSecret ? randomUUID() + randomUUID() : undefined;
    if (bridgeSecret && bridgeToken) await this.context.secrets.set(bridgeSecret, bridgeToken);
    const log = await open(join(root, 'process.log'), 'a', 0o600);
    const child = spawn(java, ['-Xmx768m', '-Djava.awt.headless=true', '-Dghidra.home=' + home, '-Dapplication.name=GhidraMCP', '-Duser.home=' + root, '-Djava.io.tmpdir=' + root, '-cp', jars.join(delimiter), 'com.xebyte.headless.GhidraMCPHeadlessServer', '--bind', '127.0.0.1', '--port', String(port)], {
      cwd: root, detached: true, stdio: ['ignore', log.fd, log.fd], windowsHide: true,
      env: { PATH: this.context.environment.PATH ?? process.env.PATH, HOME: root, TMPDIR: root, XDG_RUNTIME_DIR: this.directory,
        GHIDRA_SERVER_HOST: url.hostname, GHIDRA_SERVER_PORT: url.port || '13100', GHIDRA_SERVER_USER: user, GHIDRA_SERVER_PASSWORD: password,
        GHIDRA_MCP_SHARED_PROJECT_DIR: root, GHIDRA_MCP_FILE_ROOT: this.directory, GHIDRA_MCP_ALLOW_SCRIPTS: '0', GHIDRA_MCP_PROJECT_FOLDER: t.programPath, ...(bridgeToken ? { GHIDRA_MCP_AUTH_TOKEN: bridgeToken } : {}) },
    });
    child.on('error', () => {}); child.unref(); await log.close();
    if (!child.pid) fail('launch', 'Could not start the owned Ghidra process.');
    const binding: Binding = { pid: child.pid, endpoint: `http://127.0.0.1:${port}`, projectDirectory: root, identity: t, version: 1, role, ...(bridgeSecret ? { bridgeSecret } : {}) };
    await durable(receipt, binding);
    const http = new HttpBridge(binding.endpoint, this.context.fetch, this.context.signal, bridgeToken);
    this.processes.set(root, { binding, http, child });
    const deadline = Date.now() + 60000;
    let ready = false;
    while (Date.now() < deadline && alive(child.pid) && !this.context.signal.aborted) {
      try { const info = await http.instance(); if (info.pid !== child.pid || info.tcp_port !== port) fail('binding', 'Endpoint belongs to another worker process.'); ready = true; break; }
      catch { await delay(100); }
    }
    if (!ready) fail('launch', 'Owned Ghidra process did not become ready; its stage is retained.');
    await http.call('/server/connect');
    const project = object(await http.call('/open_project', { path: t.server + '/' + t.repository }));
    if (project.shared !== true) fail('binding', 'Ghidra project is not shared.');
    const projectInfo = object(await http.call('/get_project_info'));
    if (projectInfo.project_server_bound !== true || projectInfo.server_repo !== t.repository) fail('binding', 'Ghidra project is not verified as server-bound.');
    if (project.repository !== t.repository) fail('binding', 'Opened repository differs from the requested target.');
    const opening = await this.probe(t, role);
    if (role === 'reader') {
      const opened = object(await http.call('/open_program', { path: t.programPath }));
      if (opened.path !== t.programPath || opened.read_only !== true) fail('authorization', 'Reader program did not open read-only.');
      const afterOpen = await this.probe(t, role);
      if (opening.version !== afterOpen.version) fail('binding', 'Published version changed while opening the reader snapshot.');
      binding.version = version(opening.version); binding.openingVersion = binding.version;
    }
    return binding;
  }
  async open(t: Target, batchId: string) { return this.launch(t, batchId, 'publisher'); }
  private async record(t: Target, b: Binding): Promise<ProcessRecord> {
    assertIdentity(b.identity, t);
    const root = resolve(b.projectDirectory);
    const saved = object(JSON.parse(await readFile(join(root, 'process.json'), 'utf8'))) as unknown as Binding;
    if (saved.pid !== b.pid || saved.endpoint !== b.endpoint || saved.role !== b.role || saved.bridgeSecret !== b.bridgeSecret || await realpath(root) !== root)
      fail('binding', 'Owned process receipt does not match the requested binding.');
    assertIdentity(saved.identity, t);
    if (b.role === 'publisher' && !b.bridgeSecret) fail('authorization', 'Publisher endpoint lacks a scoped authentication secret.');
    const bridgeToken = b.bridgeSecret ? await this.context.secrets.require(b.bridgeSecret) : undefined;
    const rec: ProcessRecord = { ...(this.processes.get(root) ?? { binding: b }), http: new HttpBridge(b.endpoint, this.context.fetch, this.context.signal, bridgeToken) };
    const info = await rec.http.instance();
    if (info.pid !== b.pid || info.tcp_port !== Number(new URL(b.endpoint).port)) fail('binding', 'Actual worker PID or endpoint changed.');
    const projectPath = text(info.project_path, 4096);
    if (!projectPath.startsWith(root + sep)) fail('binding', 'Actual worker project directory differs from its owned stage.');
    this.processes.set(root, rec); return rec;
  }
  private async boundIdentity(t: Target, rec: ProcessRecord): Promise<Identity> {
    const project = object(await rec.http.call('/get_project_info'));
    const url = new URL(t.server);
    if (project.project_server_bound !== true || project.server_repo !== t.repository || project.server_info !== url.hostname + ':' + (url.port || '13100') || project.server_connected !== true)
      fail('binding', 'Actual server/repository binding differs from the registered target.');
    const p = { program: t.programPath };
    const metadata = object(await rec.http.call('/get_metadata', p));
    const options = object(await rec.http.call('/get_program_options', { ...p, group: 'Program Information' }));
    if (!Array.isArray(options.options)) fail('malformed', 'Program options are missing.');
    const sha = options.options.filter(x => object(x).name === 'Executable SHA256');
    if (sha.length !== 1) fail('binding', 'Executable SHA256 is missing or ambiguous.');
    const actual = { ...t, binarySha256: text(object(sha[0]).value).toLowerCase(), language: text(metadata.language), compilerSpec: text(metadata.compiler), imageBase: text(metadata.base_address).toLowerCase() };
    const info = await rec.http.instance();
    if (!Array.isArray(info.programs) || !info.programs.some(x => object(x).path === t.programPath && object(x).open === true))
      fail('binding', 'The explicit program path is not open in the selected worker.');
    assertIdentity(actual, t); return actual;
  }
  private async latest(t: Target, rec: ProcessRecord): Promise<number> {
    const history = object(await rec.http.call('/server/version_history', { path: t.programPath }));
    if (!Array.isArray(history.versions) || history.versions.length !== history.count || !history.versions.length)
      fail('malformed', 'Server history is incomplete.');
    return Math.max(...history.versions.map(x => version(object(x).version)));
  }
  private async localVersion(t: Target, rec: ProcessRecord): Promise<number> {
    const r = object(await rec.http.call('/list_project_files', { folder: t.programPath.slice(0, t.programPath.lastIndexOf('/')) || '/' }));
    if (!Array.isArray(r.files)) fail('malformed', 'Project file inventory is missing.');
    const rows = r.files.filter(x => object(x).path === t.programPath);
    if (rows.length !== 1) fail('binding', 'Program path is absent or ambiguous in the project.');
    const row = object(rows[0]);
    if (row.is_versioned !== true) fail('binding', 'Program is not versioned.');
    return version(row.checkout_version ?? row.version);
  }
  async checkout(t: Target, b: Binding): Promise<Snapshot> {
    const rec = await this.record(t, b);
    const result = object(await rec.http.call('/server/version_control/checkout', { path: t.programPath, exclusive: true }));
    if (result.success !== true || result.status !== 'checked_out' || result.exclusive !== true || result.is_checked_out !== true || result.path !== t.programPath || result.repository !== t.repository)
      fail('checkout', 'Exclusive checkout was not fully verified.');
    await rec.http.call('/open_program', { path: t.programPath });
    const identity = await this.boundIdentity(t, rec);
    b.version = await this.localVersion(t, rec);
    if (b.version !== await this.latest(t, rec)) fail('binding', 'Checkout is not based on the latest published version.');
    return { identity, version: b.version, values: {} };
  }
  async read(t: Target, b: Binding, findings: FindingRecord[]): Promise<Snapshot> {
    const rec = await this.record(t, b); const identity = await this.boundIdentity(t, rec);
    const values: Record<string, string | null> = {};
    for (const f of findings) {
      const observed = object(await rec.http.call('/get_comment', { address: f.address, program: t.programPath }));
      if (typeof observed.address !== 'string' || observed.address.toLowerCase() !== f.address || !Object.hasOwn(observed, f.kind)) fail('partial', 'Comment readback omitted or changed its selector.');
      const value = observed[f.kind]; if (value !== null && typeof value !== 'string') fail('malformed', 'Comment value is malformed.');
      values[key(f)] = value as string | null;
    }
    const localVersion = await this.localVersion(t, rec);
    if (localVersion !== b.version) fail('binding', 'Worker baseline changed.');
    return { identity, version: localVersion, values };
  }
  async apply(t: Target, b: Binding, f: FindingRecord) {
    if (b.role !== 'publisher') fail('authorization', 'Only the coordinator publisher can write.');
    const rec = await this.record(t, b); await this.boundIdentity(t, rec);
    const r = object(await rec.http.call('/set_comment', { program: t.programPath, address: f.address, type: f.kind, comment: f.after }));
    if (r.status !== 'success') fail('partial', 'Ghidra did not acknowledge this comment operation.');
  }
  async save(t: Target, b: Binding) { const rec = await this.record(t, b); const r = object(await rec.http.call('/save_program', { program: t.programPath })); if (r.success !== true) fail('save', 'Ghidra did not acknowledge saving the local stage.'); }
  async checkIn(t: Target, b: Binding, batchId: string): Promise<number> {
    const rec = await this.record(t, b); await this.boundIdentity(t, rec);
    const r = object(await rec.http.call('/checkin_program', { path: t.programPath, comment: 'insight batch ' + batchId, keep_checked_out: false }));
    if (r.success !== true || r.status !== 'checked_in' || r.version_bumped !== true || r.is_checked_out !== false || r.keep_checked_out !== false || r.path !== t.programPath || r.repository !== t.repository || r.version_before !== b.version)
      fail('unknown', 'Check-in result did not establish publication and checkout release.');
    return version(r.version);
  }
  private async independent<T>(t: Target, action: (rec: ProcessRecord, b: Binding) => Promise<T>) {
    const b = await this.launch(t, 'verify-' + randomUUID(), 'reader');
    try { const rec = await this.record(t, b); await this.boundIdentity(t, rec); b.version = await this.localVersion(t, rec); return await action(rec, b); }
    finally { await this.stop(t, b); }
  }
  async published(t: Target, findings: FindingRecord[]) { return this.independent(t, (_r, b) => this.read(t, b, findings)); }
  private async probe(t: Target, role: Binding['role']) {
    const values = this.context.profile.values;
    const home = text(values.ghidraHome), jar = text(values.mcpJar), java = text(values.java);
    const jars = [jar];
    const collect = async (path: string): Promise<void> => { for (const item of await readdir(path, {withFileTypes:true})) { const child=join(path,item.name); if(item.isDirectory())await collect(child);else if(item.isFile()&&child.endsWith('.jar'))jars.push(child); } };
    await collect(join(home,'Ghidra'));
    const root=join(this.directory,'probes',randomUUID());await mkdir(root,{recursive:true,mode:0o700});
    const url=new URL(t.server);
    const password=await this.context.secrets.require(role==='reader'?'readerPassword':'publisherPassword');
    const script=fileURLToPath(new URL('../../references/InsightRepositoryProbe.java',import.meta.url));
    let stdout: string;
    try { ({stdout}=await promisify(execFile)(java,['-Djava.awt.headless=true','-Dghidra.home='+home,'-Duser.home='+root,'-Djava.io.tmpdir='+root,'-cp',jars.join(delimiter),'--source','21',script,t.repository,t.programPath,role], {
      cwd:root,timeout:30000,maxBuffer:262144,signal:this.context.signal,
      env:{PATH:process.env.PATH,HOME:root,TMPDIR:root,GHIDRA_SERVER_HOST:url.hostname,GHIDRA_SERVER_PORT:url.port||'13100',GHIDRA_SERVER_USER:text(values[role==='reader'?'readerUser':'publisherUser']),GHIDRA_SERVER_PASSWORD:password}
    })); } catch { fail('authorization','Authoritative repository probe failed; access and checkout state remain unverified.'); }
    let result: Record<string,unknown>;
    try { result=object(JSON.parse(stdout.trim())); } catch { fail('malformed','Authoritative repository probe returned malformed content.'); }
    if(result.repository!==t.repository||result.path!==t.programPath||!Array.isArray(result.checkouts)||typeof result.checkinActive!=='boolean'||!Array.isArray(result.versions))fail('binding','Authoritative repository probe has incomplete or wrong binding.');
    if(role==='reader'?result.permission!==0:![1,2].includes(Number(result.permission)))fail('authorization','Actual repository permission does not match the worker role.');
    version(result.version);
    return result;
  }
  async history(t: Target, batchId: string) {
    const result=await this.probe(t,'reader');
    return (result.versions as unknown[]).filter(x=>object(x).comment==='insight batch '+batchId).map(x=>version(object(x).version));
  }
  async released(t: Target) {
    const result=await this.probe(t,'reader');
    return (result.checkouts as unknown[]).length===0 && result.checkinActive===false;
  }
  async complete(t: Target, b: Binding) { if (alive(b.pid)) await this.stop(t, b); if (b.bridgeSecret) await this.context.secrets.delete(b.bridgeSecret); }
  async release(t: Target, b: Binding) {
    const rec = await this.record(t, b);
    await rec.http.call('/close_program', { name: t.programPath, save: true });
    const result = object(await rec.http.call('/server/version_control/undo_checkout', { path: t.programPath, keep: false }));
    if (result.success !== true || result.is_checked_out !== false || result.path !== t.programPath) fail('checkout', 'Checkout release was not verified.');
    await this.stop(t, b);
  }
  async abandon(t: Target, batch: Batch) {
    const receipt = join(this.directory, 'processes', batch.id, 'process.json');
    let binding: Binding;
    try { binding = JSON.parse(await readFile(receipt, 'utf8')); }
    catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT' && !batch.binding) return; throw e; }
    if (alive(binding.pid)) fail('busy', 'The staged publisher is still alive; stop it explicitly before abandoning.');
    assertIdentity(binding.identity, t);
    const backup = join(this.directory, 'backups', batch.id + '-' + randomUUID());
    await cp(binding.projectDirectory, backup, { recursive: true, errorOnExist: true });
    // Automatic offline checkout cancellation would need its actual checkout ID and
    // server quiescence proof. Preserve the backup and require explicit operator cleanup.
    if (!await this.released(t)) fail('checkout', 'A server checkout remains; the stage and backup are retained for explicit cleanup.');
  }
  async startReader(t: Target, label: string) {
    const b = await this.launch(t, 'reader-' + label + '-' + randomUUID(), 'reader');
    const rec = await this.record(t, b); await this.boundIdentity(t, rec); b.version = await this.localVersion(t, rec);
    const python = text(this.context.profile.values.python), bridgeDirectory = text(this.context.profile.values.bridgeDirectory);
    const transport = new StdioClientTransport({ command: python, args: ['-m', 'bridge_mcp_ghidra', '--no-lazy'], cwd: b.projectDirectory, stderr: 'pipe',
      env: { PATH: this.context.environment.PATH ?? process.env.PATH ?? '', HOME: b.projectDirectory, XDG_RUNTIME_DIR: this.directory, PYTHONPATH: bridgeDirectory, GHIDRA_MCP_URL: b.endpoint, GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS: '1' } });
    transport.stderr?.on('data', () => {});
    const client = new Client({ name: 'insight-ghidra-reader', version: '0.1.0' });
    await client.connect(transport);
    const result = object(decodeMcp(await client.callTool({ name: 'connect_instance', arguments: { project: 'endpoint-only-' + randomUUID() } })));
    if (result.connected !== true || result.url !== b.endpoint) { await client.close(); fail('binding', 'MCP bridge connected to a different endpoint.'); }
    if (!transport.pid) fail('binding', 'MCP bridge did not report its process identity.');
    b.bridgePid = transport.pid;
    await durable(join(b.projectDirectory, 'bridge.json'), { pid: transport.pid, endpoint: b.endpoint, workerPid: b.pid });
    rec.client = client; rec.transport = transport;
    return b;
  }
  async inspect(t: Target, b: Binding, functions: string) {
    if (b.role !== 'reader') fail('authorization', 'Inspection requires a reader worker.');
    const rec = await this.record(t, b); await this.boundIdentity(t, rec);
    if (!rec.client) fail('workerStopped', 'Reader bridge belongs to a prior owner; stop and restart the worker.');
    const refs = functions.split(','); if (!refs.length || refs.length > 8 || refs.some(s => !s)) fail('invalid', 'Inspect requires one to eight explicit function selectors.');
    const direct = object(await rec.http.call('/get_functions', { functions, fields: 'entry_point', include_call_context: false, program: t.programPath }));
    const directFunctions = object(direct.functions);
    const epoch = text(object(object(directFunctions[refs[0]!]).revision).epoch);
    if (b.readEpoch && b.readEpoch !== epoch) fail('binding', 'Reader snapshot reopened after its baseline was recorded.');
    const result = object(decodeMcp(await rec.client.callTool({ name: 'get_functions', arguments: { functions, fields: 'entry_point,decompiled_code,comments', include_call_context: false, program: t.programPath } })));
    const returned = object(result.functions);
    if (Object.keys(returned).length !== refs.length || refs.some(ref => !returned[ref] || object(returned[ref]).error)) fail('partial', 'MCP function result omitted or failed a requested selector.');
    for (const ref of refs) {
      const revision = object(object(returned[ref]).revision);
      if (revision.epoch !== epoch || revision.file_version !== undefined && revision.file_version !== -1 && revision.file_version !== b.version) fail('binding', 'Reader baseline or bridge routing changed.');
    }
    if (b.openingVersion !== b.version) fail('binding', 'Reader lacks a stable version proof at opening.');
    b.readEpoch = epoch;
    return { binding: b, functions: returned };
  }
  async stop(t: Target, b: Binding) {
    const rec = await this.record(t, b);
    await rec.client?.close();
    // Verify the actual receipt/PID/endpoint before signaling; never kill by port/name.
    process.kill(b.pid, 'SIGTERM');
    for (let i = 0; i < 100 && alive(b.pid); i++) await delay(50);
    if (alive(b.pid)) fail('busy', 'Owned Ghidra process did not stop; no forced takeover was attempted.');
    this.processes.delete(b.projectDirectory);
    if (b.bridgeSecret) await this.context.secrets.delete(b.bridgeSecret);
  }
  async dispose() {
    for (const rec of [...this.processes.values()]) {
      await rec.client?.close().catch(() => {});
      // Publisher stages survive owner disposal until their outcome is reconciled.
      if (rec.binding.role === 'reader' && alive(rec.binding.pid)) await this.fork({ ...this.context, signal: new AbortController().signal }).stop(rec.binding.identity as Target, rec.binding);
    }
  }
}
