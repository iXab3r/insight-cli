import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, mkdir, link, unlink, realpath, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fail } from './model.js';

export type ArtifactKind = 'input' | 'snapshot';
export interface Artifact {
  id: string;
  kind: ArtifactKind;
  sha256: string;
  size: number;
}
const maximumBytes = 4 * 1024 * 1024 * 1024;

/** Immutable, content-addressed copies of the bytes actually consumed by the facade. */
export class Artifacts {
  constructor(readonly directory: string) {}

  path(value: Artifact): string {
    if (!['input', 'snapshot'].includes(value.kind) || !/^[a-f0-9]{64}$/.test(value.sha256) ||
        value.id !== `${value.kind}:${value.sha256}` || !Number.isSafeInteger(value.size) ||
        value.size < 1 || value.size > maximumBytes) fail('artifact', 'Saved artifact reference is malformed.');
    return join(this.directory, 'artifacts', `${value.sha256}.${value.kind === 'snapshot' ? 'gzf' : 'bin'}`);
  }

  private async ownedDirectory(): Promise<string> {
    const directory = join(this.directory, 'artifacts');
    await mkdir(directory, {recursive: true, mode: 0o700});
    if ((await lstat(directory)).isSymbolicLink() || await realpath(directory) !== resolve(directory))
      fail('artifact', 'Artifact directory must remain inside its owned profile storage.');
    return directory;
  }

  private async syncDirectory(directory: string) {
    // Directory fsync is unavailable on Windows. The file itself is synced on all platforms.
    if (process.platform === 'win32') return;
    const handle = await open(directory, constants.O_RDONLY);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  async verify(value: Artifact): Promise<string> {
    await this.ownedDirectory();
    const path = this.path(value);
    if ((await lstat(path)).isSymbolicLink()) fail('artifact', 'Saved artifact cannot be replaced by a symbolic link.');
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size !== value.size) fail('artifact', 'Saved artifact size or type changed.');
      const hash = createHash('sha256');
      let size = 0;
      for await (const chunk of handle.createReadStream({autoClose: false})) {
        size += chunk.length; hash.update(chunk);
        if (size > value.size) fail('artifact', 'Saved artifact grew during verification.');
      }
      if (size !== value.size || hash.digest('hex') !== value.sha256)
        fail('artifact', 'Saved artifact contents changed; its original copy is required.');
      return path;
    } finally { await handle.close(); }
  }

  async capture(source: string, kind: ArtifactKind): Promise<Artifact> {
    if (!['input', 'snapshot'].includes(kind)) fail('artifact', 'Unsupported artifact kind.');
    const directory = await this.ownedDirectory();
    const temporary = join(directory, 'pending-' + randomUUID());
    const input = await open(source, constants.O_RDONLY);
    let output;
    try {
      const info = await input.stat({bigint: true});
      if (!info.isFile() || info.size < 1n || info.size > BigInt(maximumBytes))
        fail('limit', 'Input must be a nonempty regular file of at most 4 GiB.');
      output = await open(temporary, 'wx', 0o600);
      const hash = createHash('sha256');
      let size = 0;
      for await (const chunk of input.createReadStream({autoClose: false})) {
        size += chunk.length;
        if (size > maximumBytes) fail('limit', 'Input exceeds 4 GiB.');
        hash.update(chunk);
        await output.writeFile(chunk);
      }
      const after = await input.stat({bigint: true});
      if (BigInt(size) !== info.size || after.size !== info.size || after.mtimeNs !== info.mtimeNs ||
          after.ctimeNs !== info.ctimeNs)
        fail('inputChanged', 'Input changed while being copied; retry against a stable file.');
      const sha256 = hash.digest('hex');
      const result: Artifact = {id: `${kind}:${sha256}`, kind, sha256, size};
      await output.chmod(0o400);
      await output.sync(); await output.close(); output = undefined;
      // Link publishes without replacing a previous artifact, including a concurrent capture.
      try { await link(temporary, this.path(result)); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      await this.verify(result);
      await this.syncDirectory(directory);
      return result;
    } finally {
      await input.close();
      await output?.close();
      await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  }
}
