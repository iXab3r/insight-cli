import type { CommandContext } from '@eyeauras/cli-factory';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { readFile, mkdir, open, rename, readdir, stat, chmod, realpath } from 'node:fs/promises';
import { delimiter, dirname, join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { fail, object, stable, text, digest } from './model.js';
import { nativeHelpers, type NativeInputs } from './native-inputs.js';
import {parseDomainJson} from './json.js';

export interface ServerBinding {
  mode: 'local' | 'external'; origin: string; repository: string;
  readerUser: string; publisherUser: string;
  readerSecret: string; publisherSecret: string;
}
interface LocalServer extends ServerBinding {
  mode: 'local'; instance: string; port: number; identityPort: number;
  keySecret: string; tokenSecret: string; phase: 'seeded' | 'initialized' | 'running' | 'stopped'; pid?: number;
}
const live = (pid: number) => {
  try { process.kill(pid, 0); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; }
};
async function durable(path: string, value: unknown) {
  const temporary = path + '.new-' + randomUUID(), handle = await open(temporary, 'wx', 0o600);
  try { await handle.writeFile(stable(value)); await handle.sync(); } finally { await handle.close(); }
  await rename(temporary, path);
  if (process.platform !== 'win32') {
    const directory = await open(dirname(path), 'r'); try { await directory.sync(); } finally { await directory.close(); }
  }
}
async function ports(count: number): Promise<number> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const base = 20000 + Math.floor(Math.random() * 30000), held: ReturnType<typeof createServer>[] = [];
    try {
      for (let index = 0; index < count; index++) {
        const listener = createServer(); held.push(listener);
        await new Promise<void>((resolve,reject) => { listener.once('error',reject); listener.listen(base + index, '127.0.0.1', resolve); });
      }
      return base;
    } catch { /* Collision is retried before any resource or process is published. */ }
    finally { await Promise.all(held.filter(listener => listener.listening).map(listener => new Promise<void>(resolve => listener.close(() => resolve())))); }
  }
  fail('launch', 'Could not reserve loopback ports for the owned server.');
}

/** Own local startup; external profiles connect without taking ownership of their server. */
export class GhidraServer {
  constructor(readonly directory: string, private readonly inputs: NativeInputs, private readonly c: CommandContext,
    private readonly state: {initializing?: Promise<ServerBinding>; child?: ChildProcess} = {}) {}
  fork(c: CommandContext) {return new GhidraServer(this.directory,this.inputs,c,this.state);}
  private root() { return join(this.directory, 'server'); }
  private async run(label: string, main: string, args: string[], environment: Record<string,string> = {}, input?: string, acceptedCodes=[0]): Promise<Record<string,unknown>> {
    const root = join(this.root(), 'calls', label + '-' + randomUUID()); await mkdir(root, {recursive:true,mode:0o700});
    const classes = await nativeHelpers(this.directory, this.inputs);
    const log = await open(join(root, 'diagnostic.log'), 'a', 0o600);
    const child = spawn(this.inputs.java, ['-Djava.awt.headless=true', '-Dghidra.home=' + this.inputs.ghidraHome,
      '-Duser.home=' + root, '-Djava.io.tmpdir=' + root, '-cp', classes + delimiter + this.inputs.classpath, main, ...args],
      {cwd:root,windowsHide:true,env:{PATH:this.c.environment.PATH ?? process.env.PATH,HOME:root,TMPDIR:root,...environment},stdio:['pipe','pipe',log.fd]});
    const exited = new Promise<number|null>((resolve,reject) => { child.once('error',reject); child.once('exit',resolve); });
    exited.catch(()=>{});
    await log.close();
    let output = '', overflow = false;
    child.stdout!.on('data', chunk => { if (!overflow) output += chunk.toString(); if (Buffer.byteLength(output) > 1024 * 1024) { overflow = true; child.kill('SIGTERM'); } });
    const abort = () => child.kill('SIGTERM'); this.c.signal.addEventListener('abort', abort, {once:true});
    const timer = setTimeout(abort, 120000);
    const force = setTimeout(()=>{if(child.exitCode===null && child.signalCode===null)child.kill('SIGKILL');},125000);
    try {
      child.stdin!.on('error',()=>{}); child.stdin!.end(input);
      if (this.c.signal.aborted) abort();
      const code = await exited;
      if (code===null||!acceptedCodes.includes(code)||overflow) fail('authorization', 'Native server operation could not be verified; its owned diagnostic stage is retained.');
      let result;
      try { result = object(parseDomainJson(output)); } catch { fail('malformed', 'Native server operation returned malformed content.'); }
      if (result.error || result.state === 'failed') fail('authorization', 'Native server operation did not establish its outcome.');
      return result;
    } finally { clearTimeout(timer); clearTimeout(force); this.c.signal.removeEventListener('abort',abort); }
  }
  async credentials(binding: ServerBinding, role: 'reader' | 'publisher'): Promise<Record<string,string>> {
    const url = new URL(binding.origin);
    return {GHIDRA_SERVER_HOST:url.hostname,GHIDRA_SERVER_PORT:url.port || '13100',
      GHIDRA_SERVER_USER:role === 'reader' ? binding.readerUser : binding.publisherUser,
      GHIDRA_SERVER_PASSWORD:await this.c.secrets.require(role === 'reader' ? binding.readerSecret : binding.publisherSecret)};
  }
  async fields(snapshot:string,selectors:string) {
    return this.run('snapshot-fields','InsightSnapshotFields',[snapshot,selectors]);
  }
  async inspect(snapshot:string,request:string) {return this.run('snapshot-inspect','InsightSnapshotInspect',[snapshot,request]);}
  async project(operation:string,parameters:Record<string,unknown>) {
    const requestId=text(parameters.request_id,128);if(!/^(?:a|read)_[a-zA-Z0-9-]+$/.test(requestId))fail('binding','Invalid internal project request identity.');
    const parent=join(this.directory,'project-calls');await mkdir(parent,{recursive:true,mode:0o700});
    if(await realpath(parent)!==resolve(parent))fail('binding','Project call container moved outside owned storage.');
    const root=join(parent,requestId);await mkdir(root,{mode:0o700});
    const request=join(root,'request.json');await durable(request,{...parameters,operation});
    return this.run('project-files','InsightProjectFiles',[request]);
  }
  async projectOutcome(requestId:string,expected:Record<string,unknown>) {
    if(!/^a_[a-zA-Z0-9-]+$/.test(requestId))fail('binding','Invalid retained project request identity.');
    const root=join(this.directory,'project-calls',requestId);
    try{
      if(await realpath(root)!==resolve(root))fail('binding','Retained project call moved outside owned storage.');
      const raw=await readFile(join(root,'request.json'),'utf8'),request=object(parseDomainJson(raw)),journal=object(parseDomainJson(await readFile(join(root,'result.json'),'utf8')));
      if(journal.schema!==1||journal.request!==requestId||journal.hash!==createHash('sha256').update(raw).digest('hex')||
        Object.entries(expected).some(([key,value])=>stable(request[key])!==stable(value)))fail('binding','Project completion journal differs from the retained request.');
      return object(journal.result);
    }catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
  }
  async administration(operation:string,parameters:Record<string,unknown>) {
    const connection=join(this.root(),'connection.json');
    if(operation==='status') {
      try{if(object(JSON.parse(await readFile(connection,'utf8'))).enabled===false)
        return {connected:false,mode:this.c.profile.values.server?'external':'local',state:'disconnected'};}
      catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    }
    if(operation==='connect'){await mkdir(this.root(),{recursive:true,mode:0o700});await durable(connection,{enabled:true});}
    if(operation==='disconnect') {
      await this.stop();await mkdir(this.root(),{recursive:true,mode:0o700});await durable(connection,{enabled:false});
      return {connected:false,mode:this.c.profile.values.server?'external':'local'};
    }
    if(operation==='status'&&!this.c.profile.values.server) {
      let local:LocalServer;try{local=JSON.parse(await readFile(join(this.root(),'local.json'),'utf8'));}
      catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return {connected:false,mode:'local',state:'not_started'};throw error;}
      if(!local.pid||!live(local.pid))return {connected:false,mode:'local',repository:local.repository};
      await this.identity(local);await this.authority(local);return {connected:true,mode:'local',repository:local.repository};
    }
    const binding=await this.ensure();
    if(operation==='connect'||operation==='status')return {connected:true,mode:binding.mode,repository:binding.repository};
    if(operation==='set_permissions'&&parameters.repository===binding.repository&&
      (parameters.user===binding.readerUser&&parameters.access!==0||parameters.user===binding.publisherUser&&![1,2].includes(Number(parameters.access))))
      fail('authorization','Canonical reader/publisher authority cannot be changed by repository administration.');
    const root=join(this.root(),'administration',randomUUID());await mkdir(root,{recursive:true,mode:0o700});
    const request=join(root,'request.json');await durable(request,{operation,...parameters,protected_repository:binding.repository});
    return this.run('administration','InsightServerAdministration',[request],await this.credentials(binding,'publisher'));
  }
  async programStatus(binding:ServerBinding,path:string) {
    return this.run('program-status','InsightRepositoryProbe',[binding.repository,path,'reader'],await this.credentials(binding,'reader'));
  }
  async publish(binding:ServerBinding,path:string,snapshot:string,expected:number,request:string,journal:string,sourceSha:string) {
    return this.run('publish','db.InsightSnapshotPublisher',[binding.repository,path,snapshot,String(expected),'insight merge '+request,journal,sourceSha],
      await this.credentials(binding,'publisher'),undefined,[0,2]);
  }
  async recoverPublication(binding:ServerBinding,path:string,snapshot:string,expected:number,request:string,journal:string,sourceSha:string) {
    return this.run('recover-publication','db.InsightPublicationRecovery',[binding.repository,path,snapshot,String(expected),'insight merge '+request,journal,sourceSha],
      {...await this.credentials(binding,'reader'),INSIGHT_PUBLISHER_USER:binding.publisherUser,
        INSIGHT_PUBLISHER_PASSWORD:await this.c.secrets.require(binding.publisherSecret)});
  }
  private async authority(binding: ServerBinding) {
    for (const role of ['reader','publisher'] as const) {
      const result = await this.run('verify-' + role, 'InsightServerProbe', [binding.repository,role], await this.credentials(binding,role));
      if (result.repository !== binding.repository || result.role !== role || (role === 'reader' ? result.permission !== 0 : ![1,2].includes(Number(result.permission))))
        fail('authorization', 'Actual repository permissions do not match the selected server profile.');
    }
  }
  async ensure(): Promise<ServerBinding> {
    try{if(object(JSON.parse(await readFile(join(this.root(),'connection.json'),'utf8'))).enabled===false)
      fail('blocked','Configured server is disconnected; use ghidra server connect before shared operations.');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    if (!this.state.initializing) this.state.initializing = this.initialize().catch(error => { this.state.initializing = undefined; throw error; });
    const binding=await this.state.initializing;
    if(binding.mode==='local') {
      const local=binding as LocalServer;
      if(local.pid&&!live(local.pid)){this.state.initializing=undefined;return this.ensure();}
      await this.identity(local);
    }
    return binding;
  }
  private async initialize(): Promise<ServerBinding> {
    const root = this.root(); await mkdir(root, {recursive:true,mode:0o700});
    const values = this.c.profile.values;
    const mode = values.server ? 'external' : 'local';
    const effective = mode === 'external' ? {mode,origin:text(values.server),repository:text(values.repository),
      readerUser:text(values.readerUser),publisherUser:text(values.publisherUser)} : {mode};
    if (mode === 'external' && (!/^ghidra:\/\/[^/?#@]+$/.test(text(values.server)) || /[\\/]/.test(text(values.repository)) ||
        text(values.repository).startsWith('.') || values.readerUser === values.publisherUser))
      fail('configuration', 'External server requires an origin, repository and distinct reader/publisher accounts.');
    const configuration = digest(effective), configured = join(root,'configuration.json');
    try {
      if (object(JSON.parse(await readFile(configured,'utf8'))).hash !== configuration)
        fail('binding', 'Server profile changed while its durable workspace remains; restore the original binding.');
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; await durable(configured,{hash:configuration}); }
    if (mode === 'external') {
      const origin = text(values.server), repository = text(values.repository), readerUser = text(values.readerUser), publisherUser = text(values.publisherUser);
      if (!/^ghidra:\/\/[^/?#@]+$/.test(origin) || new URL(origin).protocol !== 'ghidra:' || /[\\/]/.test(repository) || repository.startsWith('.') || readerUser === publisherUser)
        fail('configuration', 'External server requires an origin, repository and distinct reader/publisher accounts.');
      const binding: ServerBinding = {mode,origin,repository,readerUser,publisherUser,readerSecret:'readerPassword',publisherSecret:'publisherPassword'};
      await this.authority(binding); return binding;
    }
    const saved = join(root,'local.json'), data = join(root,'data');
    let local: LocalServer;
    try { local = JSON.parse(await readFile(saved,'utf8')); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await mkdir(data,{recursive:true,mode:0o700});
      if ((await readdir(data)).length) fail('binding', 'Unidentified server storage exists; it cannot be adopted.');
      const instance = 'server_' + randomUUID(), base = await ports(4);
      local = {mode:'local',instance,port:base,identityPort:base+3,origin:`ghidra://127.0.0.1:${base}`,
        repository:'insight_' + randomUUID().replaceAll('-',''),readerUser:'reader',publisherUser:'publisher',
        readerSecret:instance + '-readerPassword',publisherSecret:instance + '-publisherPassword',
        keySecret:instance + '-keystorePassword',tokenSecret:instance + '-identityToken',phase:'seeded'};
      await durable(saved,local);
    }
    if (local.mode !== 'local' || !/^server_[a-f0-9-]{36}$/.test(local.instance) || local.origin !== `ghidra://127.0.0.1:${local.port}` ||
        local.identityPort !== local.port+3 || !local.repository.startsWith('insight_') || local.readerUser !== 'reader' || local.publisherUser !== 'publisher')
      fail('binding','Owned local server receipt is inconsistent.');
    for (const key of [local.readerSecret,local.publisherSecret,local.keySecret,local.tokenSecret]) {
      if (!key.startsWith(local.instance + '-')) fail('binding','Owned local server secret reference is inconsistent.');
      if (!await this.c.secrets.get(key)) {
        if (local.phase !== 'seeded') fail('credentials','Owned local server credentials are missing; retain its storage and restore its credential store.');
        await this.c.secrets.set(key,randomBytes(32).toString('hex'));
      }
    }
    if (local.pid && live(local.pid)) {
      await this.identity(local); await this.authority(local); return local;
    }
    // A prior owner may have died after spawn and before recording its PID.
    if (!local.pid && await this.identity(local).then(() => true, () => false)) {
      const identity = await this.identity(local); local.pid = Number(identity.pid); local.phase = 'running';
      await durable(saved,local); await this.authority(local); return local;
    }
    const initialized = await this.run('initialize','ghidra.server.InsightServerInit',[data,local.repository,local.publisherUser,local.readerUser],{
      INSIGHT_PUBLISHER_PASSWORD:await this.c.secrets.require(local.publisherSecret),INSIGHT_READER_PASSWORD:await this.c.secrets.require(local.readerSecret)});
    if (initialized.state !== 'ready' || initialized.repository !== local.repository || initialized.readerReadOnly !== true || initialized.publisherAdmin !== true)
      fail('authorization','Owned local server initialization did not establish its permission boundary.');
    local.phase = 'initialized'; delete local.pid; await durable(saved,local);
    const keystore = join(root,'owned-cert.p12');
    try { await stat(keystore); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // keytool gets the random password through its documented environment input, never argv.
      await this.run('certificate','InsightKeytool',[keystore],{INSIGHT_KEYSTORE_PASSWORD:await this.c.secrets.require(local.keySecret)});
      await chmod(keystore,0o600);
    }
    const classes = await nativeHelpers(this.directory,this.inputs);
    const processRoot = join(root,'processes',randomUUID()); await mkdir(processRoot,{recursive:true,mode:0o700});
    const log = await open(join(processRoot,'runtime.log'),'a',0o600);
    const child = spawn(this.inputs.java,['-Djava.awt.headless=true','-Dghidra.home='+this.inputs.ghidraHome,
      '-Duser.home='+processRoot,'-Djava.io.tmpdir='+processRoot,'-cp',classes+delimiter+this.inputs.classpath,
      'InsightServerMain',data,String(local.port),String(local.identityPort),local.instance,keystore],
      {cwd:processRoot,detached:true,windowsHide:true,env:{PATH:this.c.environment.PATH??process.env.PATH,HOME:processRoot,TMPDIR:processRoot,
        INSIGHT_KEYSTORE_PASSWORD:await this.c.secrets.require(local.keySecret),INSIGHT_SERVER_TOKEN:await this.c.secrets.require(local.tokenSecret)},stdio:['ignore',log.fd,log.fd]});
    child.on('error',()=>{}); child.unref(); await log.close();
    if (!child.pid) fail('launch','Owned local Ghidra server could not be started.');
    this.state.child = child; local.pid = child.pid; local.phase = 'running'; await durable(saved,local);
    try {
      const deadline = Date.now()+60000;
      while (Date.now()<deadline && child.exitCode===null && child.signalCode===null && !this.c.signal.aborted) {
        try { await this.identity(local); await this.authority(local); return local; }
        catch { await delay(100); }
      }
      fail('launch','Owned local Ghidra server did not become ready; its storage and diagnostic stage are retained.');
    } catch (error) {
      // Only this newly-created child handle can be cleaned without a ready identity probe.
      if (child.exitCode===null && child.signalCode===null) child.kill('SIGTERM');
      for(let i=0;i<100 && child.exitCode===null && child.signalCode===null;i++) await delay(50);
      throw error;
    }
  }
  private async identity(local: LocalServer): Promise<Record<string,unknown>> {
    const token = await this.c.secrets.require(local.tokenSecret);
    const response = await this.c.fetch(`http://127.0.0.1:${local.identityPort}/identity`,{redirect:'error',
      signal:AbortSignal.timeout(1000),headers:{Authorization:'Bearer '+token}});
    if (!response.ok || Number(response.headers.get('content-length')) > 4096) fail('binding','Owned server identity was not verified.');
    const reader = response.body?.getReader(); if (!reader) fail('binding','Owned server identity has no body.');
    const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) {
        const next = await reader.read(); if (next.done) break;
        size += next.value.byteLength; if (size > 4096) fail('binding','Owned server identity exceeded its bound.');
        chunks.push(next.value);
      }
    } finally { await reader.cancel().catch(()=>{}); }
    const value = Buffer.concat(chunks).toString('utf8');
    const result = object(JSON.parse(value));
    if (result.instance !== local.instance || result.port !== local.port || !Number.isSafeInteger(result.pid) || Number(result.pid)<1 ||
        local.pid !== undefined && result.pid !== local.pid) fail('binding','Server endpoint no longer belongs to the recorded owned process.');
    return result;
  }
  async stop() {
    let local: LocalServer;
    try { local = JSON.parse(await readFile(join(this.root(),'local.json'),'utf8')); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
    if (!local.pid) return;
    if (live(local.pid)) {
      await this.identity(local); process.kill(local.pid,'SIGTERM');
      for(let i=0;i<100 && live(local.pid);i++) await delay(50);
      if(live(local.pid)) fail('busy','Owned server did not stop; its receipt is retained.');
    }
    local.phase='stopped'; delete local.pid; await durable(join(this.root(),'local.json'),local); this.state.child=undefined; this.state.initializing=undefined;
  }
}
