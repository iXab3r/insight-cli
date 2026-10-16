import { assertIdentity, fail, key, type Batch, type Binding, type FindingRecord, type Snapshot, type Target } from './model.js';
import { Store } from './store.js';

/** Ghidra operations are separately acknowledged calls. The journal, not a batch endpoint,
 * is the recovery boundary. Implementations must preserve staged project directories. */
export interface Publisher {
  open(target: Target, batchId: string): Promise<Binding>;
  checkout(target: Target, binding: Binding): Promise<Snapshot>;
  read(target: Target, binding: Binding, findings: FindingRecord[]): Promise<Snapshot>;
  apply(target: Target, binding: Binding, finding: FindingRecord): Promise<void>;
  save(target: Target, binding: Binding): Promise<void>;
  checkIn(target: Target, binding: Binding, batchId: string): Promise<number>;
  published(target: Target, findings: FindingRecord[]): Promise<Snapshot>;
  history(target: Target, batchId: string): Promise<number[]>;
  released(target: Target): Promise<boolean>;
  release(target: Target, binding: Binding): Promise<void>;
  complete(target: Target, binding: Binding): Promise<void>;
  /** Return only after every owned publisher process is stopped, staged copy backed up,
   * and any owned checkout safely released. This must refuse a live/unidentified writer. */
  abandon(target: Target, batch: Batch): Promise<void>;
}
export type Checkpoint = (phase: string, batch: Batch) => Promise<void>;
export class Coordinator {
  constructor(readonly store: Store, readonly publisher: Publisher, private checkpoint: Checkpoint = async () => {},
    private running = new Map<string, Promise<Batch | { state: 'empty'; targetId: string }>>()) {}
  async settled() { await Promise.allSettled([...this.running.values()]); }
  integrate(targetId: string) {
    const active = this.running.get(targetId);
    if (active) return active;
    const work = this.integrateOnce(targetId).finally(() => this.running.delete(targetId));
    this.running.set(targetId, work);
    return work;
  }
  private async mark(id: string, phase: string, patch = {}) {
    const batch = this.store.update(id, phase as Batch['state'], patch);
    await this.checkpoint(phase, batch);
    return batch;
  }
  private validate(snapshot: Snapshot, target: Target, findings: FindingRecord[], proposed: boolean) {
    assertIdentity(snapshot.identity, target);
    if (!Number.isSafeInteger(snapshot.version) || snapshot.version < 1) fail('malformed', 'Readback did not contain a valid version.');
    for (const finding of findings) {
      if (!Object.hasOwn(snapshot.values, key(finding))) fail('partial', 'Readback omitted a requested comment.');
      const actual = snapshot.values[key(finding)];
      if (actual !== null && typeof actual !== 'string') fail('malformed', 'Readback contained a malformed comment.');
      if (proposed && actual !== finding.after) fail('verification', 'Published readback differs from the proposal.');
    }
  }
  private async integrateOnce(targetId: string): Promise<Batch | { state: 'empty'; targetId: string }> {
    const target = this.store.target(targetId);
    let batch = this.store.begin(targetId);
    if (!batch) return { state: 'empty', targetId };
    try {
      await this.checkpoint('accepted', batch);
      const binding = await this.publisher.open(target, batch.id);
      assertIdentity(binding.identity, target);
      if (binding.role !== 'publisher' || !Number.isSafeInteger(binding.pid) || binding.pid <= 0) fail('binding', 'Publisher binding is invalid.');
      batch = await this.mark(batch.id, 'applying', { binding });
      const baseline = await this.publisher.checkout(target, binding);
      assertIdentity(baseline.identity, target);
      if (!Number.isSafeInteger(baseline.version) || baseline.version < 1) fail('malformed', 'Checkout did not report its baseline version.');
      batch = await this.mark(batch.id, 'applying', { baselineVersion: baseline.version, binding });
      const current = await this.publisher.read(target, binding, batch.findings);
      this.validate(current, target, batch.findings, false);
      if (current.version !== baseline.version) fail('binding', 'Local copy is not bound to the fresh checkout baseline.');
      const scopes = new Map<string, FindingRecord>();
      const conflicts: unknown[] = [];
      for (const f of batch.findings) {
        const peer = scopes.get(key(f));
        if (f.baselineVersion > baseline.version || current.values[key(f)] !== f.before ||
            peer && (peer.before !== f.before || peer.after !== f.after)) {
          conflicts.push({ findingId: f.findingId, peerFindingId: peer?.findingId, observed: current.values[key(f)], expected: f.before, proposed: f.after });
        }
        scopes.set(key(f), f);
      }
      if (conflicts.length) {
        this.store.conflicts(batch.id, conflicts);
        // No proposal has been applied; release must finish before unblocking the lane.
        await this.publisher.release(target, binding);
        batch = await this.mark(batch.id, 'conflict_pending', { detail: { conflicts } });
        fail('conflict', 'Comment proposals conflict with the current baseline or each other.', batch);
      }
      for (const f of scopes.values()) {
        await this.publisher.apply(target, binding, f);
        const observed = await this.publisher.read(target, binding, [f]);
        this.validate(observed, target, [f], true);
        await this.checkpoint('local_application', this.store.batch(batch.id));
      }
      const all = await this.publisher.read(target, binding, batch.findings);
      this.validate(all, target, batch.findings, true);
      await this.publisher.save(target, binding);
      batch = await this.mark(batch.id, 'staged');
      // Durable check-in intent precedes the remote request. A kill at this boundary is
      // deliberately uncertain even if the remote call had not started yet.
      batch = await this.mark(batch.id, 'checking_in');
      const version = await this.publisher.checkIn(target, binding, batch.id);
      if (!Number.isSafeInteger(version) || version <= baseline.version) fail('malformed', 'Check-in did not establish a newer server version.');
      batch = await this.mark(batch.id, 'publication_unknown', { publishedVersion: version });
      return await this.verify(target, batch);
    } catch (error) {
      const latest = this.store.batch(batch.id);
      if (!['conflict_pending', 'published_verified'].includes(latest.state)) {
        const uncertain = ['checking_in', 'publication_unknown'].includes(latest.state);
        const result = this.store.update(batch.id, uncertain ? 'publication_unknown' : 'failed', { detail: { phase: latest.state } });
        fail(uncertain ? 'unknown' : 'staged', uncertain ? 'Publication outcome is unresolved; reconcile this batch before any retry.' : 'Integration stopped; the journal and staged copy are retained.', result);
      }
      throw error;
    }
  }
  private async verify(target: Target, batch: Batch): Promise<Batch> {
    const versions = await this.publisher.history(target, batch.id);
    if (versions.length !== 1 || versions[0] !== batch.publishedVersion) fail('unknown', 'Server history does not uniquely establish this publication.');
    const actual = await this.publisher.published(target, batch.findings);
    this.validate(actual, target, batch.findings, true);
    if (actual.version !== batch.publishedVersion || !await this.publisher.released(target))
      fail('unknown', 'Independent readback or checkout release is unresolved.');
    await this.checkpoint('verification', batch);
    if (batch.binding) await this.publisher.complete(target, batch.binding);
    return this.mark(batch.id, 'published_verified');
  }
  async recover(batchId: string, abandon = false): Promise<Batch> {
    let batch = this.store.batch(batchId);
    const target = this.store.target(batch.targetId);
    if (this.running.has(batch.targetId)) fail('busy', 'The publication owner is still executing this lane.');
    if (['published_verified', 'conflict_pending'].includes(batch.state)) return batch;
    if (batch.ownerPid !== process.pid) {
      try { process.kill(batch.ownerPid, 0); fail('busy', 'The prior owner is still alive; recovery cannot take over.'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
    }
    const intent = this.store.events(batchId).some(e => e.state === 'checking_in');
    if (intent) {
      if (abandon) fail('unknown', 'An uncertain check-in cannot be abandoned or retried.');
      const versions = await this.publisher.history(target, batch.id);
      if (versions.length !== 1) fail('unknown', 'Server history is insufficient; this lane remains blocked.', batch);
      batch = this.store.update(batchId, 'publication_unknown', { publishedVersion: versions[0] });
      try { return await this.verify(target, batch); }
      catch { fail('unknown', 'Reconciliation could not verify every publication result; this lane remains blocked.', batch); }
    }
    if (!abandon) fail('staged', 'A pre-publication stage is retained; use explicit abandon after stopping its publisher.', batch);
    await this.publisher.abandon(target, batch);
    // Findings remain observable. A fresh request can explicitly resubmit from a verified
    // baseline; the original failed batch and stage are never overwritten or replayed.
    return this.store.update(batchId, 'conflict_pending', { detail: { abandoned: true, requiresNewProposals: true } });
  }
}
