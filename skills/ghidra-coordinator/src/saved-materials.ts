import { command, CliError, Permission, type CommandDefinition } from '@eyeauras/cli-factory';
import { createHash, randomUUID } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, opendir, realpath, rename, rm } from 'node:fs/promises';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';

export interface SavedMaterials {
  state: 'saved'; path: string; kind: 'file' | 'directory'; files: number; bytes: number; sha256: string;
}
interface Entry { path: string; kind: 'file' | 'directory'; stamp: string; size: number }
interface ManifestEntry { path: string; kind: 'file' | 'directory'; bytes?: number; sha256?: string }
const maximumEntries = 100_000, maximumDepth = 128;
function fail(code: string, message: string): never { throw new CliError(message, {code: 'artifacts.' + code}); }
function check(signal?: AbortSignal) { if (signal?.aborted) fail('cancelled', 'Saving materials was cancelled; no snapshot was published.'); }
function inside(parent: string, child: string) {
  const value = relative(parent, child); return value === '' || (!isAbsolute(value) && value !== '..' && !value.startsWith('..' + sep));
}
function stamp(info: BigIntStats) { return [info.dev, info.ino, info.mode, info.size, info.mtimeNs, info.ctimeNs].join(':'); }
async function syncDirectory(path: string) {
  if (process.platform === 'win32') return;
  const handle = await open(path, constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function inventory(source: string, signal?: AbortSignal): Promise<Entry[]> {
  const entries: Entry[] = [];
  async function visit(path: string, name: string, depth: number) {
    check(signal);
    if (depth > maximumDepth || entries.length >= maximumEntries)
      fail('limit', 'Materials exceed the traversal bound of 100000 entries or 128 directory levels; save a smaller selection.');
    const info = await lstat(path, {bigint: true});
    if (!info.isFile() && !info.isDirectory()) fail('unsupported', 'Materials must contain only ordinary files and directories; symbolic links and special files are unsupported.');
    if (info.size > BigInt(Number.MAX_SAFE_INTEGER)) fail('limit', 'A materials entry exceeds the supported size counter.');
    entries.push({path: name, kind: info.isFile() ? 'file' : 'directory', stamp: stamp(info), size: Number(info.size)});
    if (info.isDirectory()) {
      // Sorting by code unit keeps manifest digests independent of locale and enumeration order.
      const names: string[] = [];
      for await (const child of await opendir(path)) {
        check(signal);
        if (names.length + entries.length >= maximumEntries)
          fail('limit', 'Materials exceed the traversal bound of 100000 entries; save a smaller selection.');
        names.push(child.name);
      }
      names.sort();
      for (const child of names) await visit(join(path, child), name ? name + '/' + child : child, depth + 1);
      if (stamp(await lstat(path, {bigint: true})) !== stamp(info)) fail('changed', 'Source changed while saving; save a stable file or directory.');
    }
  }
  await visit(source, '', 0); return entries;
}
async function verifyParents(source: string, entry: Entry, entries: Map<string, Entry>) {
  let parent = entry.path ? entry.path.split('/').slice(0, -1).join('/') : undefined;
  while (parent !== undefined) {
    const expected = entries.get(parent)!;
    if (stamp(await lstat(parent ? join(source, parent) : source, {bigint: true})) !== expected.stamp)
      fail('changed', 'Source directory changed while saving; no snapshot was published.');
    parent = parent ? parent.split('/').slice(0, -1).join('/') : undefined;
  }
}

/** Copy user materials without initializing Ghidra, targets, sessions or Workspace. */
export async function saveMaterials(appDataDirectory: string, source: string, signal?: AbortSignal): Promise<SavedMaterials> {
  let stage: string | undefined, published: string | undefined;
  try {
    check(signal);
    const sourcePath = resolve(source);
    // Reject a symbolic source itself before resolving its parents (e.g. macOS /tmp).
    const info = await lstat(sourcePath, {bigint: true});
    if (!info.isFile() && !info.isDirectory()) fail('unsupported', 'Save an ordinary file or directory; symbolic links and special files are unsupported.');
    const canonicalSource = await realpath(sourcePath);
    await mkdir(appDataDirectory, {recursive: true, mode: 0o700});
    const appData = await realpath(appDataDirectory), storage = join(appData, 'materials');
    if (info.isDirectory() && inside(canonicalSource, storage))
      fail('recursive', 'Source contains the materials storage; choose a source outside its storage ancestry.');
    await mkdir(storage, {recursive: true, mode: 0o700});
    if ((await lstat(storage)).isSymbolicLink() || await realpath(storage) !== storage)
      fail('storage', 'Materials storage must be an ordinary profile-owned directory.');
    const entries = await inventory(canonicalSource, signal), byPath = new Map(entries.map(entry => [entry.path, entry]));
    if (entries[0]!.stamp !== stamp(info)) fail('changed', 'Source changed while preparing its snapshot; save a stable file or directory.');
    const identity = randomUUID(), candidate = join(storage, '.pending-' + identity);
    const final = join(storage, identity), content = join(candidate, 'content');
    await mkdir(candidate, {mode: 0o700}); stage = candidate;
    await mkdir(content, {mode: 0o700});
    const name = basename(canonicalSource) || 'root', output = join(content, name);
    const manifest: ManifestEntry[] = [], directories: string[] = [stage, content];
    let files = 0, bytes = 0, fileDigest: string | undefined;
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (const entry of entries) {
      check(signal); await verifyParents(canonicalSource, entry, byPath);
      const inputPath = entry.path ? join(canonicalSource, entry.path) : canonicalSource;
      const outputPath = entry.path ? join(output, entry.path) : output;
      if (entry.kind === 'directory') {
        await mkdir(outputPath, {mode: 0o700}); directories.push(outputPath);
        manifest.push({path: entry.path, kind: 'directory'}); continue;
      }
      // NONBLOCK avoids a hang if a regular source is exchanged for a FIFO before open.
      const input = await open(inputPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const before = await input.stat({bigint: true});
        if (!before.isFile() || stamp(before) !== entry.stamp) fail('changed', 'Source file changed while saving; no snapshot was published.');
        const destination = await open(outputPath, 'wx', 0o600), hash = createHash('sha256');
        let copied = 0;
        try {
          while (true) {
            check(signal);
            const {bytesRead} = await input.read(buffer, 0, buffer.length, copied);
            if (!bytesRead) break;
            copied += bytesRead;
            if (copied > entry.size) fail('changed', 'Source file grew while saving; no snapshot was published.');
            const chunk = buffer.subarray(0, bytesRead); hash.update(chunk);
            await destination.writeFile(chunk);
          }
          if (copied !== entry.size || stamp(await input.stat({bigint: true})) !== entry.stamp ||
              stamp(await lstat(inputPath, {bigint: true})) !== entry.stamp)
            fail('changed', 'Source file changed while saving; no snapshot was published.');
          await destination.sync();
        } finally { await destination.close(); }
        const sha256 = hash.digest('hex'); manifest.push({path: entry.path, kind: 'file', bytes: copied, sha256});
        fileDigest = sha256; files++; bytes += copied;
        if (!Number.isSafeInteger(bytes)) fail('limit', 'Materials exceed the supported size counter.');
      } finally { await input.close(); }
    }
    // Detect edits to earlier files and directory membership changes during the entire capture.
    const after = await inventory(canonicalSource, signal);
    if (JSON.stringify(after) !== JSON.stringify(entries) || await realpath(sourcePath) !== canonicalSource ||
        stamp(await lstat(sourcePath, {bigint: true})) !== stamp(info))
      fail('changed', 'Source changed while saving; no snapshot was published.');
    const manifestBytes = JSON.stringify({version: 1, entries: manifest}) + '\n';
    const metadata = await open(join(stage, 'manifest.json'), 'wx', 0o600);
    try { await metadata.writeFile(manifestBytes); await metadata.sync(); } finally { await metadata.close(); }
    for (const directory of directories.reverse()) await syncDirectory(directory);
    check(signal);
    await rename(stage, final); published = final; stage = undefined;
    await syncDirectory(storage);
    return {state: 'saved', path: join(final, 'content', name), kind: entries[0]!.kind, files, bytes,
      sha256: entries[0]!.kind === 'file' ? fileDigest! : createHash('sha256').update(manifestBytes).digest('hex')};
  } catch (error) {
    let cleanupFailed = false;
    if (stage) await rm(stage, {recursive: true, force: true}).catch(() => { cleanupFailed = true; });
    // A directory-sync failure is not acknowledged as a durable save.
    if (published) await rm(published, {recursive: true, force: true}).catch(() => { cleanupFailed = true; });
    if (error instanceof CliError) {
      if (cleanupFailed) throw new CliError(error.message + ' Some owned temporary files could not be removed; preserve the profile for cleanup.', {code: error.code});
      throw error;
    }
    const code = (error as NodeJS.ErrnoException).code;
    fail('save', `Could not save materials${code && /^[A-Z0-9_]+$/.test(code) ? ' (' + code + ')' : ''}; no complete snapshot was acknowledged.${cleanupFailed ? ' Some owned temporary files could not be removed; preserve the profile for cleanup.' : ''}`);
  }
}

export function artifactsCommands(): CommandDefinition[] {
  return [command('artifacts', 'Retain ordinary research files independently of analysis tools', [
    command('save <path>', 'Save a complete independent copy of a file or directory in this profile',
      ({args}, context) => {
        if (typeof args.path !== 'string' || !args.path || args.path.includes('\0')) fail('invalid', 'Provide one file or directory path.');
        return saveMaterials(context.appArguments.AppDataDirectory, resolve(context.cwd, args.path), context.signal);
      }, {permission: Permission.Update}),
  ])];
}
