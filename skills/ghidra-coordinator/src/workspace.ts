import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync, realpathSync } from 'node:fs';
import { basename, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Artifacts, type Artifact } from './artifacts.js';
import { digest, fail, id, stable, text, version } from './model.js';

export interface ResearchTarget {
  id: string; name: string; binarySha256: string; size: number; input: Artifact; createdAt: string;
}
export interface ResearchSession { id: string; createdAt: string }
export interface GhidraLoadSettings {
  autoAnalyze: boolean; language?: string; compilerSpec?: string; imageBase?: string;
}
export interface GhidraModel {
  target: string; settings: GhidraLoadSettings; state: 'opening' | 'ready' | 'unknown';
  sharedRevision?: number; sharedSnapshot?: Artifact;
}
export interface Scope { session: string; target: string }
export interface ScalarChange {
  address: string; field: 'function.name' | 'comment.eol' | 'comment.pre' | 'comment.post' | 'comment.plate' | 'comment.repeatable';
  original: string | null; local: string | null;
  dependency?:string;
  conflict?: {shared: string | null};
}
export interface GhidraContext extends Scope {
  /** Internal storage key, never a caller's backend selector. */
  id: string; tool: 'ghidra'; state: 'opening' | 'ready' | 'stopped' | 'needs_recovery'; generation: number;
  baseRevision?: number; baseSnapshot?: Artifact; workingSnapshot?: Artifact;
  viewEpoch?:number;
  scalars: ScalarChange[]; complexChanges: string[];
  debugger?:DebuggerState;
}
export interface SavedTrace {id:string;name:string;snapshot:Artifact;snap:string;modules:number;threads:number;connected:boolean;thread?:string}
export interface DebuggerState {traces:SavedTrace[];active?:string;connected:boolean}
export type RequestState = 'accepted' | 'running' | 'applied' | 'failed' | 'unknown';
export interface AdministrationRequest {id:string;operation:string;intent:unknown;state:RequestState;callerId?:string;result?:unknown;createdAt:string;updatedAt:string}
export interface ResearchRequest {
  id: string; callerId?: string; operation: string; intent: unknown; context: string;
  state: RequestState; result?: unknown; execution?:unknown; createdAt: string; updatedAt: string;
}
export interface Publication extends Scope {
  id:string;request:string;state:'preparing'|'commit_intent'|'unknown'|'verified'|'conflict';
  expectedRevision:number;snapshot:Artifact;generation:number;scalars:ScalarChange[];complex:boolean;
  complexChanges?:string[];
  publishedRevision?:number;detail?:unknown;
}
export interface OpenReservation {
  context: GhidraContext; request: ResearchRequest; replay: boolean;
}
type ContextPatch = Partial<Pick<GhidraContext,
  'state' | 'baseRevision' | 'baseSnapshot' | 'workingSnapshot' | 'viewEpoch' | 'scalars' | 'complexChanges' | 'debugger'>>;
const now = () => new Date().toISOString();
function loadSettings(value: GhidraLoadSettings): GhidraLoadSettings {
  if (typeof value.autoAnalyze !== 'boolean' || Object.keys(value).some(key =>
      !['autoAnalyze', 'language', 'compilerSpec', 'imageBase'].includes(key)))
    fail('invalid', 'Ghidra load settings are malformed.');
  const result: GhidraLoadSettings = {autoAnalyze: value.autoAnalyze};
  if (value.language !== undefined) result.language = text(value.language, 128);
  if (value.compilerSpec !== undefined) result.compilerSpec = text(value.compilerSpec, 128);
  if (value.imageBase !== undefined) {
    const address = text(value.imageBase, 128).toLowerCase().replace(/^0x/, '');
    if (!/^[a-f0-9]+$/.test(address)) fail('invalid', 'Image base must be hexadecimal.');
    result.imageBase = address.replace(/^0+(?=.)/, '');
  }
  return result;
}
function bounded(value: unknown): string {
  const result = stable(value);
  if (typeof result !== 'string' || Buffer.byteLength(result) > 1024 * 1024)
    fail('limit', 'Durable request or context exceeds 1 MiB.');
  return result;
}
function page(limit: number, offset: number) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(offset) || offset < 0)
    fail('invalid', 'Pagination requires a limit of 1–100 and a nonnegative offset.');
}

/** Profile root state, deliberately separate from the earlier coordinator.sqlite journals. */
export class Workspace {
  readonly directory: string;
  readonly artifacts: Artifacts;
  private readonly db: DatabaseSync;
  private namespace!: string;
  constructor(directory: string, readonly profile: string) {
    text(profile);
    mkdirSync(directory, {recursive: true, mode: 0o700});
    this.directory = realpathSync(directory);
    this.artifacts = new Artifacts(this.directory);
    const path = join(this.directory, 'workspace.sqlite');
    this.db = new DatabaseSync(path);
    chmodSync(path, 0o600);
    try {
      if(this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'").get()){
        const binding=this.db.prepare('SELECT value FROM metadata WHERE key=?').get('profile');
        if(binding&&binding.value!==profile)fail('binding','Workspace belongs to a different profile; restore its original profile.');
      }
      if (Number(this.db.prepare('PRAGMA user_version').get()?.user_version) > 3)
        fail('binding', 'Workspace schema is newer than this build; preserve it and use the matching build.');
      this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, sha TEXT NOT NULL UNIQUE, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ghidra_models(target TEXT PRIMARY KEY REFERENCES targets(id), data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS contexts(id TEXT PRIMARY KEY, session TEXT NOT NULL REFERENCES sessions(id),
          target TEXT NOT NULL REFERENCES ghidra_models(target), generation INTEGER NOT NULL, data TEXT NOT NULL,
          UNIQUE(session,target));
        CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, caller_id TEXT UNIQUE, hash TEXT NOT NULL,
          context TEXT NOT NULL REFERENCES contexts(id), state TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS publications(id TEXT PRIMARY KEY, target TEXT NOT NULL REFERENCES ghidra_models(target), state TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS administration_requests(id TEXT PRIMARY KEY,caller_id TEXT UNIQUE,hash TEXT NOT NULL,state TEXT NOT NULL,data TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS active_publication ON publications(target) WHERE state IN ('preparing','commit_intent','unknown');
        PRAGMA user_version=3;`);
      this.transaction(() => {
        const binding = this.db.prepare('SELECT value FROM metadata WHERE key=?').get('profile');
        if (binding && binding.value !== profile) fail('binding', 'Workspace belongs to a different profile; restore its original profile.');
        if (!binding) {
          this.db.prepare('INSERT INTO metadata VALUES(?,?)').run('profile', profile);
          this.db.prepare('INSERT INTO metadata VALUES(?,?)').run('namespace', randomUUID());
        }
        this.namespace = String(this.db.prepare('SELECT value FROM metadata WHERE key=?').get('namespace')!.value);
      });
    } catch (error) { this.db.close(); throw error; }
  }
  close() { this.db.close(); }
  private transaction<T>(action: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = action(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  private rememberArtifact(artifact: Artifact) {
    this.artifacts.path(artifact);
    const row = this.db.prepare('SELECT data FROM artifacts WHERE id=?').get(artifact.id);
    if (row && row.data !== stable(artifact)) fail('artifact', 'Artifact identity has inconsistent metadata.');
    this.db.prepare('INSERT OR IGNORE INTO artifacts VALUES(?,?)').run(artifact.id, stable(artifact));
  }
  private knownSnapshot(artifact: Artifact) {
    this.artifacts.path(artifact);
    if (artifact.kind !== 'snapshot' || this.db.prepare('SELECT data FROM artifacts WHERE id=?').get(artifact.id)?.data !== stable(artifact))
      fail('artifact', 'Context requires a captured immutable snapshot.');
  }
  async captureSnapshot(path: string): Promise<Artifact> {
    const artifact = await this.artifacts.capture(path, 'snapshot');
    this.rememberArtifact(artifact); return artifact;
  }
  async importTarget(path: string): Promise<ResearchTarget> {
    const name = text(basename(path), 512);
    const input = await this.artifacts.capture(path, 'input');
    return this.transaction(() => {
      this.rememberArtifact(input);
      const row = this.db.prepare('SELECT id FROM targets WHERE sha=?').get(input.sha256);
      if (row) return this.target(String(row.id));
      const target: ResearchTarget = {
        id: 't_' + digest([this.namespace, input.sha256]).slice(0, 32), name,
        binarySha256: input.sha256, size: input.size, input, createdAt: now(),
      };
      this.db.prepare('INSERT INTO targets VALUES(?,?,?)').run(target.id, input.sha256, stable(target));
      return target;
    });
  }
  target(target: string): ResearchTarget {
    const row = this.db.prepare('SELECT data FROM targets WHERE id=?').get(id(target));
    if (!row) fail('notFound', 'Target was not found in the selected profile.');
    return JSON.parse(String(row.data));
  }
  targets(limit = 100, offset = 0): ResearchTarget[] {
    page(limit, offset);
    return this.db.prepare('SELECT data FROM targets ORDER BY rowid LIMIT ? OFFSET ?').all(limit, offset).map(row => JSON.parse(String(row.data)));
  }
  session(session: string): ResearchSession {
    const row = this.db.prepare('SELECT data FROM sessions WHERE id=?').get(id(session));
    if (!row) fail('notFound', 'Session was not found in the selected profile.');
    return JSON.parse(String(row.data));
  }
  sessions(limit = 100, offset = 0): ResearchSession[] {
    page(limit, offset);
    return this.db.prepare('SELECT data FROM sessions ORDER BY rowid LIMIT ? OFFSET ?').all(limit, offset).map(row => JSON.parse(String(row.data)));
  }
  model(target: string): GhidraModel {
    this.target(target);
    const row = this.db.prepare('SELECT data FROM ghidra_models WHERE target=?').get(target);
    if (!row) fail('notFound', 'Target has no Ghidra model.');
    return JSON.parse(String(row.data));
  }
  context(scope: Scope): GhidraContext {
    this.session(scope.session); this.target(scope.target);
    const row = this.db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(scope.session, scope.target);
    if (!row) fail('notFound', 'No Ghidra context exists for this session and target; open it first.');
    return JSON.parse(String(row.data));
  }
  contexts(session: string, limit = 100, offset = 0): GhidraContext[] {
    this.session(session); page(limit, offset);
    return this.db.prepare('SELECT data FROM contexts WHERE session=? ORDER BY rowid LIMIT ? OFFSET ?').all(session, limit, offset).map(row => JSON.parse(String(row.data)));
  }
  private existingRequest(callerId: string | undefined, intentHash: string): ResearchRequest | undefined {
    if (callerId === undefined) return;
    if(this.db.prepare('SELECT id FROM administration_requests WHERE caller_id=?').get(id(callerId)))
      fail('idempotency','Request ID already identifies a profile administration operation.');
    const row = this.db.prepare('SELECT id,hash FROM requests WHERE caller_id=?').get(id(callerId));
    if (!row) return;
    if (row.hash !== intentHash) fail('idempotency', 'Request ID was already used with different effective input.');
    return this.request(String(row.id));
  }
  private insertRequest(context: string, operation: string, intent: unknown, callerId: string | undefined, hash: string): ResearchRequest {
    const request: ResearchRequest = {id: 'q_' + randomUUID(), operation: text(operation, 128), intent,
      context, state: 'accepted', ...(callerId === undefined ? {} : {callerId: id(callerId)}), createdAt: now(), updatedAt: now()};
    this.db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?)').run(request.id, callerId ?? null, hash, context, request.state, bounded(request));
    return request;
  }
  reserveOpen(target: string, session: string | 'new', settings: GhidraLoadSettings, callerId?: string, mode?: 'headless'|'gui'): OpenReservation {
    this.target(target); const normalized = loadSettings(settings);
    if (session !== 'new') this.session(session);
    if(mode!==undefined&&!['headless','gui'].includes(mode))fail('invalid','Requested tool mode is invalid.');
    const intent = {operation: 'ghidra.open', target, session, settings: normalized, ...(mode?{mode}:{})};
    const hash = digest(intent);
    return this.transaction(() => {
      const previous = this.existingRequest(callerId, hash);
      if (previous) {
        const row = this.db.prepare('SELECT data FROM contexts WHERE id=?').get(previous.context)!;
        return {context: JSON.parse(String(row.data)), request: previous, replay: true};
      }
      const row = this.db.prepare('SELECT data FROM ghidra_models WHERE target=?').get(target);
      if (row) {
        if (stable((JSON.parse(String(row.data)) as GhidraModel).settings) !== stable(normalized))
          fail('binding', 'Target already uses different Ghidra load settings.');
      } else {
        const model: GhidraModel = {target, settings: normalized, state: 'opening'};
        this.db.prepare('INSERT INTO ghidra_models VALUES(?,?)').run(target, stable(model));
      }
      if (session === 'new') {
        const selected: ResearchSession = {id: 's_' + randomUUID(), createdAt: now()};
        this.db.prepare('INSERT INTO sessions VALUES(?,?)').run(selected.id, stable(selected));
        session = selected.id;
      }
      const existing = this.db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(session, target);
      const context: GhidraContext = existing ? JSON.parse(String(existing.data)) : {
        id: 'c_' + randomUUID(), session, target, tool: 'ghidra', state: 'opening', generation: 0, scalars: [], complexChanges: [],
      };
      if (!existing) this.db.prepare('INSERT INTO contexts VALUES(?,?,?,?,?)').run(context.id, session, target, 0, stable(context));
      return {context, request: this.insertRequest(context.id, 'ghidra.open', intent, callerId, hash), replay: false};
    });
  }
  reserveRequest(scope: Scope, operation: string, parameters: unknown, callerId?: string): {request: ResearchRequest; replay: boolean} {
    const context = this.context(scope);
    const intent = {operation: text(operation, 128), session: scope.session, target: scope.target, parameters};
    bounded(intent); const hash = digest(intent);
    return this.transaction(() => {
      const previous = this.existingRequest(callerId, hash);
      return previous ? {request: previous, replay: true} : {request: this.insertRequest(context.id, operation, intent, callerId, hash), replay: false};
    });
  }
  request(request: string): ResearchRequest {
    const row = this.db.prepare('SELECT data FROM requests WHERE id=?').get(id(request));
    if (!row) fail('notFound', 'Request was not found in the selected profile.');
    return JSON.parse(String(row.data));
  }
  reserveAdministration(operation:string,parameters:unknown,callerId?:string):{request:AdministrationRequest;replay:boolean} {
    const intent={operation:text(operation,128),parameters},hash=digest(intent);bounded(intent);
    return this.transaction(()=>{
      if(callerId!==undefined) {
        id(callerId);if(this.db.prepare('SELECT id FROM requests WHERE caller_id=?').get(callerId))fail('idempotency','Request ID already identifies scoped research.');
        const row=this.db.prepare('SELECT id,hash FROM administration_requests WHERE caller_id=?').get(callerId);
        if(row){if(row.hash!==hash)fail('idempotency','Request ID was already used with different effective input.');return {request:this.administration(String(row.id)),replay:true};}
      }
      const request:AdministrationRequest={id:'a_'+randomUUID(),operation,intent,state:'accepted',...(callerId?{callerId}:{}),createdAt:now(),updatedAt:now()};
      this.db.prepare('INSERT INTO administration_requests VALUES(?,?,?,?,?)').run(request.id,callerId??null,hash,request.state,bounded(request));
      return {request,replay:false};
    });
  }
  administration(request:string):AdministrationRequest {
    const row=this.db.prepare('SELECT data FROM administration_requests WHERE id=?').get(id(request));
    if(!row)fail('notFound','Administration request was not found in this profile.');return JSON.parse(String(row.data));
  }
  unresolvedAdministration():AdministrationRequest[]{
    return this.db.prepare("SELECT data FROM administration_requests WHERE state IN ('running','unknown') ORDER BY rowid LIMIT 100")
      .all().map(row=>JSON.parse(String(row.data)));
  }
  unresolvedServer():AdministrationRequest[]{
    return this.db.prepare("SELECT data FROM administration_requests WHERE state IN ('running','unknown') AND json_extract(data,'$.operation') LIKE 'server.%' ORDER BY rowid LIMIT 100")
      .all().map(row=>JSON.parse(String(row.data)));
  }
  unresolvedProject(project:string):AdministrationRequest[]{
    return this.db.prepare("SELECT data FROM administration_requests WHERE state IN ('running','unknown') AND json_extract(data,'$.intent.parameters.project')=? ORDER BY rowid LIMIT 100")
      .all(project).map(row=>JSON.parse(String(row.data)));
  }
  administrationState(request:string,state:Exclude<RequestState,'accepted'>,result?:unknown) {
    return this.transaction(()=>{
      const previous=this.administration(request);
      if(previous.state==='applied'||previous.state==='failed'){
        if(previous.state!==state||stable(previous.result)!==stable(result))fail('idempotency','A completed administration outcome is immutable.');return previous;}
      if(state==='running'&&previous.state!=='accepted')fail('blocked','Administration operation already started; do not replay it.');
      const next={...previous,state,...(result===undefined?{}:{result}),updatedAt:now()};
      this.db.prepare('UPDATE administration_requests SET state=?,data=? WHERE id=?').run(state,bounded(next),request);return next;
    });
  }
  unresolved(scope: Scope): ResearchRequest[] {
    const context = this.context(scope);
    return this.db.prepare("SELECT data FROM requests WHERE context=? AND state IN ('running','unknown') ORDER BY rowid LIMIT 100")
      .all(context.id).map(row => JSON.parse(String(row.data)));
  }
  startRequest(request: string, execution?:unknown): ResearchRequest {
    return this.transaction(() => {
      const previous = this.request(request);
      if (previous.state !== 'accepted') fail('blocked', 'Request already started; reconcile its recorded outcome before continuing.');
      const next = {...previous, state: 'running' as const, ...(execution===undefined?{}:{execution}), updatedAt: now()};
      this.db.prepare('UPDATE requests SET state=?,data=? WHERE id=?').run(next.state, bounded(next), next.id);
      return next;
    });
  }
  recordRequest(request: string, state: 'applied' | 'failed' | 'unknown', result: unknown): ResearchRequest {
    return this.transaction(() => this.writeRequest(request, state, result));
  }
  private writeRequest(request: string, state: 'applied' | 'failed' | 'unknown', result: unknown): ResearchRequest {
    const previous = this.request(request);
    if (previous.state === 'applied' || previous.state === 'failed') {
      if (state !== previous.state || stable(result) !== stable(previous.result)) fail('idempotency', 'A completed request outcome is immutable.');
      return previous;
    }
    if (state === 'applied' && previous.state === 'accepted') fail('binding', 'Request must start before an effect can be acknowledged.');
    const next = {...previous, state, result, updatedAt: now()};
    this.db.prepare('UPDATE requests SET state=?,data=? WHERE id=?').run(next.state, bounded(next), next.id);
    return next;
  }
  establishModel(target: string, revision: number, snapshot: Artifact) {
    version(revision); this.knownSnapshot(snapshot);
    return this.transaction(() => {
      const model = this.model(target);
      if (model.state === 'ready') fail('binding', 'Ghidra model was already initialized; publication must verify its shared base.');
      const next: GhidraModel = {...model, state: 'ready', sharedRevision: revision, sharedSnapshot: snapshot};
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable(next), target);
      return next;
    });
  }
  beginModelInitialization(target: string) {
    return this.transaction(() => {
      const model = this.model(target);
      if (model.state !== 'opening') fail('blocked', 'Shared model setup already started; reconcile its persisted outcome.');
      const next: GhidraModel = {...model, state: 'unknown'};
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable(next), target);
      return next;
    });
  }
  observeShared(target:string,revision:number,snapshot:Artifact):GhidraModel {
    version(revision);this.knownSnapshot(snapshot);
    return this.transaction(()=>{
      const model=this.model(target);
      if(model.state!=='ready')fail('blocked','Shared model outcome requires reconciliation before accepting another baseline.');
      if(revision<(model.sharedRevision??1))fail('binding','Shared version history regressed.');
      const next={...model,sharedRevision:revision,sharedSnapshot:snapshot};
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable(next),target);return next;
    });
  }
  publication(publication:string):Publication {
    const row=this.db.prepare('SELECT data FROM publications WHERE id=?').get(id(publication));
    if(!row)fail('notFound','Publication was not found in this profile.');return JSON.parse(String(row.data));
  }
  activePublication(target:string):Publication|undefined {
    this.target(target);
    const row=this.db.prepare("SELECT data FROM publications WHERE target=? AND state IN ('preparing','commit_intent','unknown')").get(target);
    return row?JSON.parse(String(row.data)):undefined;
  }
  beginPublication(scope:Scope,request:string,expectedRevision:number,snapshot:Artifact):Publication {
    version(expectedRevision);this.knownSnapshot(snapshot);
    return this.transaction(()=>{
      const context=this.context(scope),intent=this.request(request),model=this.model(scope.target);
      if(intent.context!==context.id||intent.state!=='running')fail('binding','Publication does not match its running context request.');
      const active=this.activePublication(scope.target);
      if(active||model.state!=='ready')fail('blocked','Shared model has an unresolved publication; reconcile it before another merge.');
      const publication:Publication={...scope,id:request,request,state:'preparing',expectedRevision,snapshot,
        generation:context.generation,scalars:context.scalars,complex:context.complexChanges.length>0,complexChanges:context.complexChanges};
      this.db.prepare('INSERT INTO publications VALUES(?,?,?,?)').run(publication.id,scope.target,publication.state,bounded(publication));
      return publication;
    });
  }
  publicationIntent(publication:string):Publication {
    return this.transaction(()=>{
      const previous=this.publication(publication);
      if(previous.state!=='preparing')fail('blocked','Publication intent was already issued; verify its history instead of retrying.');
      const next={...previous,state:'commit_intent' as const};
      const model=this.model(previous.target);
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable({...model,state:'unknown'}),previous.target);
      this.db.prepare('UPDATE publications SET state=?,data=? WHERE id=?').run(next.state,bounded(next),next.id);return next;
    });
  }
  unknownPublication(publication:string,detail:unknown) {
    return this.transaction(()=>{
      const previous=this.publication(publication);
      if(!['commit_intent','unknown'].includes(previous.state))fail('binding','Uncertainty must retain an actual publication intent.');
      const next={...previous,state:'unknown' as const,detail};
      this.db.prepare('UPDATE publications SET state=?,data=? WHERE id=?').run(next.state,bounded(next),next.id);
      return next;
    });
  }
  finishPublication(publication:string,publishedRevision:number,result:unknown):Publication {
    version(publishedRevision);
    return this.transaction(()=>{
      const previous=this.publication(publication);
      if(!['commit_intent','unknown'].includes(previous.state)||publishedRevision!==previous.expectedRevision+1)
        fail('binding','Verified publication has an unexpected state or version.');
      const context=this.context(previous),model=this.model(previous.target);
      if(context.generation!==previous.generation)fail('binding','Private context changed during publication; preserve both saved versions.');
      this.writeContext(previous,previous.generation,{state:'ready',baseRevision:publishedRevision,baseSnapshot:previous.snapshot,
        workingSnapshot:previous.snapshot,viewEpoch:(context.viewEpoch??0)+1,scalars:[],complexChanges:[]});
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable({...model,state:'ready',sharedRevision:publishedRevision,sharedSnapshot:previous.snapshot}),previous.target);
      this.writeRequest(previous.request,'applied',result);
      const next={...previous,state:'verified' as const,publishedRevision};
      this.db.prepare('UPDATE publications SET state=?,data=? WHERE id=?').run(next.state,bounded(next),next.id);return next;
    });
  }
  rejectPublication(publication:string,result:unknown):Publication {
    return this.transaction(()=>{
      const previous=this.publication(publication);
      if(!['preparing','commit_intent'].includes(previous.state))fail('blocked','An uncertain publication cannot be abandoned without proof.');
      const model=this.model(previous.target),next={...previous,state:'conflict' as const,detail:result};
      this.db.prepare('UPDATE ghidra_models SET data=? WHERE target=?').run(stable({...model,state:'ready'}),previous.target);
      this.db.prepare('UPDATE publications SET state=?,data=? WHERE id=?').run(next.state,bounded(next),next.id);
      this.writeRequest(previous.request,'failed',result);return next;
    });
  }
  publishedSince(target:string,revision:number):Publication[] {
    this.target(target);version(revision);
    return this.db.prepare("SELECT data FROM publications WHERE target=? AND state='verified' ORDER BY rowid").all(target)
      .map(row=>JSON.parse(String(row.data)) as Publication).filter(item=>item.publishedRevision!>revision);
  }
  saveContext(scope: Scope, expectedGeneration: number, patch: ContextPatch): GhidraContext {
    return this.transaction(() => this.writeContext(scope, expectedGeneration, patch));
  }
  /** Snapshot and successful request acknowledgment enter the same durable transaction. */
  completeSavedRequest(scope: Scope, request: string, expectedGeneration: number, patch: ContextPatch, result: unknown) {
    return this.transaction(() => {
      const previous = this.context(scope), intent = this.request(request);
      if (intent.context !== previous.id) fail('binding', 'Saved operation belongs to a different working context.');
      if (intent.state === 'applied' || intent.state === 'failed') fail('idempotency', 'Completed request cannot change its working context.');
      const context = this.writeContext(scope, expectedGeneration, patch);
      const outcome = this.writeRequest(request, 'applied', result);
      return {context, request: outcome};
    });
  }
  private writeContext(scope: Scope, expectedGeneration: number, patch: ContextPatch): GhidraContext {
    if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 0) fail('invalid', 'Invalid context generation.');
    if (Object.keys(patch).some(key => !['state', 'baseRevision', 'baseSnapshot', 'workingSnapshot', 'viewEpoch', 'scalars', 'complexChanges','debugger'].includes(key)) ||
        patch.state !== undefined && !['opening', 'ready', 'stopped', 'needs_recovery'].includes(patch.state))
      fail('invalid', 'Invalid context state update.');
    if (patch.baseRevision !== undefined) version(patch.baseRevision);
    if(patch.viewEpoch!==undefined&&(!Number.isSafeInteger(patch.viewEpoch)||patch.viewEpoch<0))fail('invalid','View epoch must be a nonnegative integer.');
    if (patch.baseSnapshot) this.knownSnapshot(patch.baseSnapshot);
    if (patch.workingSnapshot) this.knownSnapshot(patch.workingSnapshot);
    if(patch.debugger){const state=patch.debugger;if(typeof state.connected!=='boolean'||!Array.isArray(state.traces)||state.traces.length>64)fail('invalid','Debugger trace state is malformed.');
      const ids=new Set<string>();for(const trace of state.traces){
        if(!/^trace_[a-f0-9-]{36}$/.test(trace.id)||ids.has(trace.id)||!/^\d+$/.test(trace.snap)||!Number.isSafeInteger(trace.modules)||trace.modules<0||!Number.isSafeInteger(trace.threads)||trace.threads<0||typeof trace.connected!=='boolean')fail('invalid','Saved trace identity or counts are malformed.');
        text(trace.name,512);this.knownSnapshot(trace.snapshot);ids.add(trace.id);
        if(trace.thread!==undefined&&!/^\d+$/.test(trace.thread))fail('invalid','Saved debugger thread is malformed.');
      }
      if(state.active!==undefined&&!ids.has(state.active))fail('invalid','Active trace must belong to the selected context.');
    }
    const previous = this.context(scope);
    if (previous.generation !== expectedGeneration) fail('binding', 'Context changed before its saved result could be recorded.');
    const next = {...previous, ...patch, generation: expectedGeneration + 1};
    if (next.state === 'ready' && (!next.baseRevision || !next.baseSnapshot || !next.workingSnapshot))
      fail('binding', 'A ready context requires durable private and base snapshots.');
    if (!Array.isArray(next.scalars) || !Array.isArray(next.complexChanges)) fail('invalid', 'Pending changes must be arrays.');
    for (const request of next.complexChanges) id(request);
    if (new Set(next.complexChanges).size !== next.complexChanges.length) fail('invalid', 'Complex change identities must be distinct.');
    const fields = new Set<string>();
    for (const change of next.scalars) {
      if (!/^(?:[A-Za-z0-9_]+:)?[a-f0-9]+$/.test(text(change.address, 128)) ||
          !['function.name', 'comment.eol', 'comment.pre', 'comment.post', 'comment.plate', 'comment.repeatable'].includes(change.field))
        fail('invalid', 'Scalar changes require a canonical address and a supported field.');
      for (const value of [change.original, change.local, ...(change.conflict ? [change.conflict.shared] : [])]) {
        if (value !== null && (typeof value !== 'string' || value.length > 16000 || value.includes('\0')))
          fail('invalid', 'Scalar values must be bounded strings or null.');
      }
      if (change.field === 'function.name' && (change.local === null || !change.local.length || change.local.length > 512))
        fail('invalid', 'Function name must be a nonempty bounded string.');
      const field = change.address + ':' + change.field;
      if(change.dependency!==undefined&&!/^[a-f0-9]{64}$/.test(change.dependency))fail('invalid','Scalar dependency fingerprint is malformed.');
      if (fields.has(field)) fail('invalid', 'Scalar field must have one original/local comparison.');
      fields.add(field);
    }
    this.db.prepare('UPDATE contexts SET generation=?,data=? WHERE id=?').run(next.generation, bounded(next), next.id);
    return next;
  }
}
