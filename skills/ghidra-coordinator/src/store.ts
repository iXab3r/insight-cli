import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertIdentity, digest, fail, finding, identity, stable, type Batch, type Binding, type FindingRecord, type Identity, type State, type Target } from './model.js';

export class Store {
  static pending(directory: string): boolean {
    const path=join(directory,'coordinator.sqlite');if(!existsSync(path))return false;
    const db=new DatabaseSync(path,{readOnly:true});
    try { return Number(db.prepare("SELECT COUNT(*) AS count FROM findings WHERE state != 'published_verified'").get()?.count)>0; }
    finally { db.close(); }
  }
  private db: DatabaseSync;
  constructor(readonly directory: string, readonly profile: string, readonly server: string) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const path = join(directory, 'coordinator.sqlite');
    this.db = new DatabaseSync(path);
    chmodSync(path, 0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, lane TEXT NOT NULL UNIQUE, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, hash TEXT NOT NULL, target_id TEXT NOT NULL REFERENCES targets(id), state TEXT NOT NULL, batch_id TEXT, data TEXT NOT NULL, conflict TEXT);
      CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id), state TEXT NOT NULL, owner_pid INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE UNIQUE INDEX IF NOT EXISTS active_lane ON batches(target_id) WHERE state IN ('applying','staged','checking_in','publication_unknown','failed');
      CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS workers(id TEXT PRIMARY KEY, target_id TEXT NOT NULL, data TEXT NOT NULL);
      PRAGMA user_version=1;`);
  }
  close() { this.db.close(); }
  private transaction<T>(action: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = action(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  register(value: unknown): Target {
    const selected = identity(value);
    if (selected.profile !== this.profile || selected.server !== this.server) fail('binding', 'Target must match the selected profile and server.');
    const lane = digest([selected.profile, selected.server, selected.repository, selected.programPath]);
    const target: Target = { ...selected, id: 't-' + digest(selected).slice(0, 24), lane };
    return this.transaction(() => {
      const existing = this.db.prepare('SELECT data FROM targets WHERE lane=?').get(lane);
      if (existing) { const t = JSON.parse(String(existing.data)) as Target; assertIdentity(t, target); return t; }
      this.db.prepare('INSERT INTO targets VALUES(?,?,?)').run(target.id, lane, stable(target));
      return target;
    });
  }
  target(id: string): Target {
    const row = this.db.prepare('SELECT data FROM targets WHERE id=?').get(id);
    if (!row) fail('notFound', 'Target was not found in the selected profile.');
    const target = JSON.parse(String(row.data)) as Target;
    if (target.profile !== this.profile || target.server !== this.server) fail('binding', 'Registered target belongs to a different profile or server.');
    return target;
  }
  targets(): Target[] { return this.db.prepare('SELECT data FROM targets ORDER BY id LIMIT 100').all().map(r => this.target((JSON.parse(String(r.data)) as Target).id)); }
  submit(value: unknown): FindingRecord {
    const f = finding(value); assertIdentity(f.identity, this.target(f.targetId));
    return this.transaction(() => {
      const previous = this.db.prepare('SELECT id,hash FROM findings WHERE request_id=? OR id=?').all(f.requestId, f.findingId);
      if (previous.length) {
        if (previous.length !== 1 || previous[0]?.hash !== digest(f)) fail('idempotency', 'Request or finding ID was already used with different content.');
        return this.getFinding(String(previous[0].id));
      }
      const worker = this.worker(f.workerId);
      assertIdentity(worker.identity, f.identity);
      if (worker.role !== 'reader' || worker.version !== f.baselineVersion) fail('binding', 'Finding does not match its registered reader baseline.');
      if (f.resolves) {
        const previous = this.getFinding(f.resolves);
        if (previous.state !== 'conflict_pending' || previous.targetId !== f.targetId || previous.address !== f.address || previous.kind !== f.kind)
          fail('conflict', 'Resolution must reference a conflicting finding for the same scoped comment.');
      }
      this.db.prepare('INSERT INTO findings(id,request_id,hash,target_id,state,data) VALUES(?,?,?,?,?,?)').run(f.findingId, f.requestId, digest(f), f.targetId, 'queued', stable(f));
      return this.getFinding(f.findingId);
    });
  }
  getFinding(id: string): FindingRecord {
    const row = this.db.prepare('SELECT * FROM findings WHERE id=?').get(id);
    if (!row) fail('notFound', 'Finding was not found.');
    return { ...JSON.parse(String(row.data)), state: row.state, ...(row.batch_id ? { batchId: row.batch_id } : {}), ...(row.conflict ? { conflict: JSON.parse(String(row.conflict)) } : {}) };
  }
  findings(targetId?: string): FindingRecord[] {
    if (targetId) this.target(targetId);
    const rows = targetId ? this.db.prepare('SELECT id FROM findings WHERE target_id=? ORDER BY rowid LIMIT 100').all(targetId) : this.db.prepare('SELECT id FROM findings ORDER BY rowid LIMIT 100').all();
    return rows.map(r => this.getFinding(String(r.id)));
  }
  begin(targetId: string): Batch | undefined {
    this.target(targetId);
    return this.transaction(() => {
      const active = this.db.prepare("SELECT id FROM batches WHERE target_id=? AND state IN ('applying','staged','checking_in','publication_unknown','failed')").get(targetId);
      if (active) fail('blocked', 'Publication lane requires recovery before new integration.', this.batch(String(active.id)));
      const rows = this.db.prepare("SELECT id FROM findings WHERE target_id=? AND state='queued' ORDER BY rowid LIMIT 100").all(targetId);
      if (!rows.length) return undefined;
      const id = 'b-' + randomUUID();
      const batch: Batch = { id, targetId, state: 'applying', ownerPid: process.pid, findings: rows.map(r => this.getFinding(String(r.id))) };
      this.db.prepare('INSERT INTO batches VALUES(?,?,?,?,?)').run(id, targetId, batch.state, process.pid, stable({}));
      for (const row of rows) this.db.prepare("UPDATE findings SET state='applying',batch_id=? WHERE id=?").run(id, row.id!);
      this.event(id, 'applying', {});
      return this.batch(id);
    });
  }
  batch(id: string): Batch {
    const row = this.db.prepare('SELECT * FROM batches WHERE id=?').get(id);
    if (!row) fail('notFound', 'Publication batch was not found.');
    this.target(String(row.target_id));
    return { ...JSON.parse(String(row.data)), id: String(row.id), targetId: String(row.target_id), state: String(row.state) as State, ownerPid: Number(row.owner_pid), findings: this.db.prepare('SELECT id FROM findings WHERE batch_id=? ORDER BY rowid').all(id).map(r => this.getFinding(String(r.id))) };
  }
  batches(): Batch[] { return this.db.prepare('SELECT id FROM batches ORDER BY rowid DESC LIMIT 100').all().map(r => this.batch(String(r.id))); }
  update(id: string, state: State, patch: Partial<Omit<Batch, 'id' | 'targetId' | 'findings'>> = {}): Batch {
    return this.transaction(() => {
      const current = this.batch(id);
      const { findings: _findings, id: _id, targetId: _targetId, ...data } = { ...current, ...patch, state };
      this.db.prepare('UPDATE batches SET state=?,data=? WHERE id=?').run(state, stable(data), id);
      this.db.prepare('UPDATE findings SET state=? WHERE batch_id=?').run(state, id);
      this.event(id, state, patch);
      return this.batch(id);
    });
  }
  conflicts(id: string, conflicts: unknown): void {
    this.db.prepare('UPDATE findings SET conflict=? WHERE batch_id=?').run(stable(conflicts), id);
  }
  private event(id: string, state: State, data: unknown) { this.db.prepare('INSERT INTO events(batch_id,state,data) VALUES(?,?,?)').run(id, state, stable(data)); }
  events(id: string) { return this.db.prepare('SELECT seq,state,data FROM events WHERE batch_id=? ORDER BY seq').all(id).map(r => ({ seq: r.seq, state: r.state, data: JSON.parse(String(r.data)) })); }
  worker(id: string): Binding {
    const row = this.db.prepare('SELECT data,target_id FROM workers WHERE id=?').get(id);
    if (!row) fail('notFound', 'Worker was not found.');
    this.target(String(row.target_id));
    return JSON.parse(String(row.data));
  }
  putWorker(id: string, targetId: string, binding: Binding) {
    assertIdentity(binding.identity, this.target(targetId));
    if (this.db.prepare('SELECT id FROM workers WHERE id=?').get(id)) fail('workerExists', 'Worker ID is already registered.');
    this.db.prepare('INSERT INTO workers VALUES(?,?,?)').run(id, targetId, stable(binding));
  }
  updateReader(id: string, binding: Binding) {
    const previous = this.worker(id); assertIdentity(binding.identity, previous.identity);
    if (previous.pid !== binding.pid || previous.endpoint !== binding.endpoint || previous.version !== binding.version || previous.projectDirectory !== binding.projectDirectory || previous.role !== 'reader' || binding.role !== 'reader' || previous.readEpoch && previous.readEpoch !== binding.readEpoch) fail('binding', 'Reader update changed its immutable binding.');
    this.db.prepare('UPDATE workers SET data=? WHERE id=?').run(stable(binding), id);
  }
  workers() { return this.db.prepare('SELECT id,target_id,data FROM workers ORDER BY id LIMIT 100').all().map(r => ({ id: r.id, targetId: r.target_id, ...JSON.parse(String(r.data)) })); }
  removeWorker(id: string) { this.db.prepare('DELETE FROM workers WHERE id=?').run(id); }
}
