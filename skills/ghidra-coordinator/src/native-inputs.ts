import {timingSpan} from '@eyeauras/cli-factory';
import {runTool,type RunContext} from './tool-runtime/run.js';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile, readdir, mkdir, open, rename, rm, realpath, stat } from 'node:fs/promises';
import { basename, delimiter, dirname, isAbsolute, join,relative,sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fail, stable, text } from './model.js';
import {managedExtensions,extensionJvmArguments} from './extensions.js';
import {runtimeValues,runtimeSelection} from './runtime-selection.js';

export interface NativeInputs {
  java: string; ghidraHome: string; mcpJar: string; jars: string[]; classpath: string;
  ghidraVersion: string; fingerprint: string;
  debuggerWheels:string[];
  extensionRoots?:string[];serverClasspath?:string;
}
export const pinnedMcpJar = '7084e2fda16dc779dd05398e48821ff3f9ace4d32757ea143b257b39689e5fbd';
export const packagedMcpJar=fileURLToPath(new URL('../../runtime/GhidraMCP-7.0.0.jar',import.meta.url));
/** Ghidra has its own cache/settings overrides in addition to Java's home/tmp properties. */
export const nativeJvmDirectories=(root:string)=>['-Duser.home='+root,'-Djava.io.tmpdir='+root,
  '-Dapplication.cachedir='+join(root,'cache'),'-Dapplication.settingsdir='+join(root,'settings'),'-Dapplication.tempdir='+root];
const run = promisify(execFile);
export async function moduleJars(home: string): Promise<string[]> {
  const jars: string[] = [];
  async function collect(folder: string): Promise<void> {
    for (const entry of (await readdir(folder, {withFileTypes: true})).sort((a,b) => a.name<b.name?-1:a.name>b.name?1:0)) {
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
export interface NativeRuntimeFile {name:string;path:string}
/** Installed native code/data, excluding documentation and isolated generated caches. */
export async function nativeRuntimeFiles(ghidraHome:string,java:string):Promise<NativeRuntimeFile[]> {
  const files:NativeRuntimeFile[]=[],jdkHome=dirname(dirname(java)),suffix=process.platform==='win32'?'.exe':'';
  const named=(prefix:string,base:string,path:string)=>({name:prefix+'/'+relative(base,path).split(sep).join('/'),path});
  for(const path of [java,...['javac','keytool'].map(name=>join(dirname(java),name+suffix))])if(!(await stat(path)).isFile())fail('configuration','The configured JDK tool is not a regular file.');
  async function walk(path:string,base:string,prefix:string,selected:boolean,ancestors=new Set<string>()){
    const real=await realpath(path);if(ancestors.has(real))fail('configuration','Native runtime directories contain a cycle.');
    const parents=new Set(ancestors);parents.add(real);
    for(const entry of (await readdir(path,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
      if(['__pycache__','.DS_Store'].includes(entry.name)||prefix==='jdk'&&entry.name==='src.zip')continue;
      const item=join(path,entry.name),kind=entry.isSymbolicLink()?await stat(item):entry;
      if(kind.isDirectory())await walk(item,base,prefix,selected||['data','os','pypkg','ghidra_scripts'].includes(entry.name),parents);
      else if(kind.isFile()&&(selected||entry.name==='Module.manifest'||entry.name==='application.properties'||entry.name.endsWith('.jar')&&basename(path)==='lib'))files.push(named(prefix,base,item));
    }
  }
  await walk(join(ghidraHome,'Ghidra'),ghidraHome,'ghidra',false);
  for(const directory of ['bin','lib','conf'])await walk(join(jdkHome,directory),jdkHome,'jdk',true);
  files.push(named('jdk',jdkHome,join(jdkHome,'release')));
  if(!(await stat(join(jdkHome,'lib','modules'))).isFile())fail('configuration','The configured JDK omitted its runtime modules.');
  return files.sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
}
export async function nativeRuntimeFingerprint(ghidraVersion:string,files:NativeRuntimeFile[]):Promise<string>{return timingSpan('runtime.hash',async()=>{
  const hashes=[];for(const file of files)hashes.push({name:file.name,sha256:await sha(file.path)});
  return createHash('sha256').update(stable({schema:2,ghidraVersion,hashes})).digest('hex');
});}
export async function nativeInputs(values: Record<string, unknown>,directory?:string,c?:RunContext): Promise<NativeInputs> {return timingSpan('runtime.verify',async()=>{
  if(directory)values=runtimeValues(dirname(directory),values);
  if(!values.java||!values.ghidraHome)fail('configuration','Ghidra is not installed. Run insight-cli ghidra install, or supply external runtime paths.');
  const requested = [text(values.java, 4096), text(values.ghidraHome, 4096), text(values.mcpJar??packagedMcpJar, 4096)];
  if (!requested.every(isAbsolute)) fail('configuration', 'Configure absolute Java, Ghidra home and GhidraMCP jar paths.');
  const [java, ghidraHome, mcpJar] = await Promise.all(requested.map(path => realpath(path))) as [string,string,string];
  const jarHash = await sha(mcpJar);
  if (jarHash !== pinnedMcpJar || values.mcpJarSha256 !== undefined && String(values.mcpJarSha256).toLowerCase() !== jarHash)
    fail('binding', 'GhidraMCP artifact differs from the pinned, verified runtime.');
  const properties = await readFile(join(ghidraHome, 'Ghidra', 'application.properties'), 'utf8');
  const ghidraVersion = /^application.version=(.+)$/m.exec(properties)?.[1]?.trim();
  if (ghidraVersion !== '12.1.2') fail('configuration', 'This build requires the verified Ghidra 12.1.2 runtime.');
  let jdk;
  try { jdk = c?await runTool(c,{tool:'ghidra',role:'java-version',executable:java,arguments:['--version'],timeoutMs:10000,maxOutputBytes:16384}):await run(java,['--version'],{timeout:10000,maxBuffer:16384}); }
  catch { fail('configuration', 'Configured Java executable could not be verified.'); }
  if (!/^(?:openjdk|java) 21(?:[.\s-]|$)/m.test(jdk.stdout + '\n' + jdk.stderr))
    fail('configuration', 'A Java 21 JDK is required.');
  for (const program of ['javac', 'keytool']) if (!(await stat(join(dirname(java), program + (process.platform === 'win32' ? '.exe' : '')))).isFile())
    fail('configuration', 'Java must come from a JDK with javac and keytool.');
  const modules=await managedExtensions(directory);
  const extraJars=modules.flatMap(m=>m.files.filter(f=>/^lib\/[^/]+\.jar$/.test(f.name)).map(f=>join(m.root,f.name)));
  const baseJars=[mcpJar,...await moduleJars(ghidraHome)],jars=[...baseJars,...extraJars];
  const debug=join(ghidraHome,'Ghidra','Debug'),debuggerWheels=[
    join(debug,'Debugger-rmi-trace/pypkg/dist/protobuf-6.31.0-py3-none-any.whl'),
    join(debug,'Debugger-rmi-trace/pypkg/dist/ghidratrace-12.1-py3-none-any.whl'),
    join(debug,'Debugger-agent-lldb/pypkg/dist/ghidralldb-12.1-py3-none-any.whl')];
  const files=await nativeRuntimeFiles(ghidraHome,java);
  const baseFingerprint=await nativeRuntimeFingerprint(ghidraVersion,[...files,{name:'bridge/GhidraMCP-7.0.0.jar',path:mcpJar}]);
  if(directory){const selected=runtimeSelection(dirname(directory));if(selected&&selected.fingerprint!==baseFingerprint)fail('binding','Selected runtime inputs differ from their installation receipt; reinstall or restore the verified files.');}
  for(const module of modules)for(const file of module.files)files.push({name:'extension/'+module.name+'/'+file.name,path:join(module.root,file.name)});
  // Logical names bind locations without embedding the author's installation path.
  files.push({name:'bridge/GhidraMCP-7.0.0.jar',path:mcpJar});
  const fingerprint=modules.length?await nativeRuntimeFingerprint(ghidraVersion,files):baseFingerprint;
  return {java, ghidraHome, mcpJar, jars, classpath: jars.join(delimiter), ghidraVersion, fingerprint,debuggerWheels,extensionRoots:modules.map(m=>m.root),serverClasspath:baseJars.join(delimiter)};
});}

/** Compile packaged helper sources against the selected installation, never an author checkout. */
export async function nativeHelpers(directory: string, inputs: NativeInputs,c?:RunContext): Promise<string> {return timingSpan('runtime.helpers',async()=>{
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
    const executable=join(dirname(inputs.java),'javac'+(process.platform==='win32'?'.exe':'')),args=['-proc:none','-cp',inputs.classpath,'-d',temporary,...names.map(name=>join(sources,name))];
    if(c)await runTool(c,{tool:'ghidra',role:'compile-helpers',installation:inputs.fingerprint,executable,arguments:args,timeoutMs:60000,maxOutputBytes:262144});
    else await run(executable,args,{timeout:60000,maxBuffer:262144});
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
});}

export const nativeExtensionArguments=(inputs:NativeInputs)=>extensionJvmArguments(inputs.extensionRoots??[]);
