import { createHash } from 'node:crypto';
import { CliError } from '@eyeauras/cli-factory';

export type State = 'queued' | 'applying' | 'staged' | 'checking_in' | 'publication_unknown' | 'published_verified' | 'conflict_pending' | 'failed';
export interface Identity {
  profile: string; server: string; repository: string; programPath: string;
  binarySha256: string; language: string; compilerSpec: string; imageBase: string;
}
export interface Target extends Identity { id: string; lane: string }
export type CommentKind = 'eol' | 'pre' | 'post' | 'plate' | 'repeatable';
export interface Finding {
  requestId: string; findingId: string; targetId: string; identity: Identity;
  workerId: string; baselineVersion: number; address: string; kind: CommentKind;
  before: string | null; after: string; evidence: string; resolves?: string;
}
export interface FindingRecord extends Finding { state: State; batchId?: string; conflict?: unknown }
export interface Binding {
  pid: number; endpoint: string; projectDirectory: string; identity: Identity;
  version: number; role: 'reader' | 'publisher'; bridgeSecret?: string; bridgePid?: number; readEpoch?: string; openingVersion?: number;
}
export interface Batch {
  id: string; targetId: string; state: State; ownerPid: number;
  binding?: Binding; baselineVersion?: number; publishedVersion?: number;
  findings: FindingRecord[]; detail?: unknown;
}
export interface Snapshot { identity: Identity; version: number; values: Record<string, string | null> }
export const key = (f: Pick<Finding, 'address' | 'kind'>) => `${f.address}:${f.kind}`;
export const stable = (value: unknown): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
export const digest = (value: unknown) => createHash('sha256').update(stable(value)).digest('hex');
export function fail(code: string, message: string, result?: unknown): never {
  throw new CliError(message, { code: `coordinator.${code}`, ...(result === undefined ? {} : { result }) });
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid', 'Expected a JSON object.');
  return value as Record<string, unknown>;
}
export function text(value: unknown, max = 512): string {
  if (typeof value !== 'string' || !value.length || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value))
    fail('invalid', 'Expected a bounded non-empty string.');
  return value;
}
export function id(value: unknown): string {
  const result = text(value, 128);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(result)) fail('invalid', 'ID must use letters, digits, dot, underscore or hyphen.');
  return result;
}
export function version(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) fail('invalid', 'Version must be a positive integer.');
  return value;
}
export function identity(value: unknown): Identity {
  const o = object(value);
  const result: Identity = {
    profile: text(o.profile), server: text(o.server), repository: text(o.repository),
    programPath: text(o.programPath), binarySha256: text(o.binarySha256).toLowerCase(),
    language: text(o.language), compilerSpec: text(o.compilerSpec), imageBase: text(o.imageBase).toLowerCase(),
  };
  if (!/^ghidra:\/\/[^/]+$/.test(result.server) || /[@?#]/.test(result.server)) fail('invalid', 'Server must be a ghidra://host:port origin without credentials.');
  if (/[\\/]/.test(result.repository) || result.repository.startsWith('.')) fail('invalid', 'Repository name must be a single non-hidden component.');
  if (!result.programPath.startsWith('/') || result.programPath.split('/').slice(1).some(p => !p || p.startsWith('.')))
    fail('invalid', 'Program path must be absolute with non-hidden components.');
  if (!/^[a-f0-9]{64}$/.test(result.binarySha256) || !/^[a-f0-9]+$/.test(result.imageBase)) fail('invalid', 'SHA256 or image base is malformed.');
  return result;
}
export function assertIdentity(actual: Identity, expected: Identity): void {
  if (stable(identity(actual)) !== stable(identity(expected))) fail('binding', 'Program, binary or connection identity does not match.');
}
export function finding(value: unknown): Finding {
  const o = object(value);
  const kind = text(o.kind) as CommentKind;
  if (!['eol', 'pre', 'post', 'plate', 'repeatable'].includes(kind)) fail('invalid', 'Only scoped comment operations are supported.');
  const address = text(o.address).toLowerCase();
  if (!/^(?:[a-z0-9_]+:)?[a-f0-9]+$/.test(address)) fail('invalid', 'An explicit hexadecimal address is required.');
  const comment = (v: unknown): string | null => v === null ? null : typeof v === 'string' && v.length <= 16000 && !v.includes('\0') ? v : fail('invalid', 'Comment must be a string or null.');
  return {
    requestId: id(o.requestId), findingId: id(o.findingId), targetId: id(o.targetId),
    identity: identity(o.identity), workerId: id(o.workerId), baselineVersion: version(o.baselineVersion),
    address, kind, before: comment(o.before), after: text(o.after,16000), evidence: text(o.evidence, 4000),
    ...(o.resolves === undefined ? {} : { resolves: id(o.resolves) }),
  };
}
