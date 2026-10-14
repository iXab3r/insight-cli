import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile, readdir, mkdir, open, rename, rm, realpath, stat } from 'node:fs/promises';
import { basename, delimiter, dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fail, stable, text } from './model.js';

export interface NativeInputs {
  java: string; ghidraHome: string; mcpJar: string; jars: string[]; classpath: string;
  ghidraVersion: string; fingerprint: string;
}
export const pinnedMcpJar = '7084e2fda16dc779dd05398e48821ff3f9ace4d32757ea143b257b39689e5fbd';
const run = promisify(execFile);
export async function moduleJars(home: string): Promise<string[]> {
  const jars: string[] = [];
  async function collect(folder: string): Promise<void> {
    for (const entry of (await readdir(folder, {withFileTypes: true})).sort((a,b) => a.name.localeCompare(b.name))) {
      const path = join(folder, entry.name);
      if (entry.isDirectory() && entry.name !== 'data') await collect(path);
      else if (entry.isFile() && entry.name.endsWith('.jar') && basename(folder) === 'lib') jars.push(path);
    }
  }
  await collect(join(home, 'Ghidra'));
  return jars;
}
async function sha(path: string): Promise<string> {
  const handle = await open(path, 'r');
  try {
    if (!(await handle.stat()).isFile()) fail('configuration', 'Native runtime input must be a regular file.');
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({autoClose: false})) hash.update(chunk);
    return hash.digest('hex');
  } finally { await handle.close(); }
}
export async function nativeInputs(values: Record<string, unknown>): Promise<NativeInputs> {
  const requested = [text(values.java, 4096), text(values.ghidraHome, 4096), text(values.mcpJar, 4096)];
  if (!requested.every(isAbsolute)) fail('configuration', 'Configure absolute Java, Ghidra home and GhidraMCP jar paths.');
  const [java, ghidraHome, mcpJar] = await Promise.all(requested.map(path => realpath(path))) as [string,string,string];
  const jarHash = await sha(mcpJar);
  if (jarHash !== pinnedMcpJar || values.mcpJarSha256 !== undefined && String(values.mcpJarSha256).toLowerCase() !== jarHash)
    fail('binding', 'GhidraMCP artifact differs from the pinned, verified runtime.');
  const properties = await readFile(join(ghidraHome, 'Ghidra', 'application.properties'), 'utf8');
  const ghidraVersion = /^application.version=(.+)$/m.exec(properties)?.[1]?.trim();
  if (ghidraVersion !== '12.1.2') fail('configuration', 'This build requires the verified Ghidra 12.1.2 runtime.');
  let jdk;
  try { jdk = await run(java, ['--version'], {timeout: 10000, maxBuffer: 16384}); }
  catch { fail('configuration', 'Configured Java executable could not be verified.'); }
  if (!/^(?:openjdk|java) 21(?:[.\s-]|$)/m.test(jdk.stdout + '\n' + jdk.stderr))
    fail('configuration', 'A Java 21 JDK is required.');
  for (const program of ['javac', 'keytool']) if (!(await stat(join(dirname(java), program + (process.platform === 'win32' ? '.exe' : '')))).isFile())
    fail('configuration', 'Java must come from a JDK with javac and keytool.');
  const jars = [mcpJar, ...await moduleJars(ghidraHome)];
  const hashes: string[] = [];
  // Sequential streaming keeps peak memory independent of the installation's total size.
  for (const path of [java, ...jars]) hashes.push(await sha(path));
  const fingerprint = createHash('sha256').update(stable({ghidraVersion, hashes})).digest('hex');
  return {java, ghidraHome, mcpJar, jars, classpath: jars.join(delimiter), ghidraVersion, fingerprint};
}

/** Compile packaged helper sources against the selected installation, never an author checkout. */
export async function nativeHelpers(directory: string, inputs: NativeInputs): Promise<string> {
  const sources = fileURLToPath(new URL('../../references/native/', import.meta.url));
  const names = [...(await readdir(sources)).filter(name => name.endsWith('.java')), '../InsightRepositoryProbe.java'].sort();
  if (!names.length) fail('configuration', 'Installed package omitted its native helper sources.');
  const hashes = [];
  for (const name of names) hashes.push(await sha(join(sources, name)));
  const key = createHash('sha256').update(stable([inputs.fingerprint, names, hashes])).digest('hex');
  const parent = join(directory, 'native-helpers'); await mkdir(parent, {recursive: true, mode: 0o700});
  const classes = join(parent, key);
  try { if (await readFile(join(classes, 'complete'), 'utf8') === key) return classes; }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const temporary = join(parent, 'compiling-' + randomUUID()); await mkdir(temporary, {mode: 0o700});
  try {
    await run(join(dirname(inputs.java), 'javac' + (process.platform === 'win32' ? '.exe' : '')),
      ['-proc:none', '-cp', inputs.classpath, '-d', temporary, ...names.map(name => join(sources, name))],
      {timeout: 60000, maxBuffer: 262144});
    const complete = await open(join(temporary, 'complete'), 'wx', 0o600);
    try { await complete.writeFile(key); await complete.sync(); } finally { await complete.close(); }
    try { await rename(temporary, classes); }
    catch (error) {
      if (!['EEXIST', 'ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code ?? '') || await readFile(join(classes, 'complete'), 'utf8') !== key) throw error;
    }
    return classes;
  } catch (error) {
    await writeFile(join(parent, 'compilation-' + key + '.log'), String((error as {stderr?:string}).stderr ?? 'Native compilation failed'), {mode:0o600});
    fail('configuration', 'Native helper compilation failed against the configured runtime; diagnostics remain in owned profile storage.');
  }
  finally { await rm(temporary, {recursive: true, force: true}); }
}
