// Historical publication fixture only. The shipped executable uses cli.ts.
import { command, createCli, Permission, CliError, type CliDefinition, type CliRuntime, type CommandContext, type IAppArguments } from '@eyeauras/cli-factory';
import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './store.js';
import { Coordinator, type Publisher } from './coordinator.js';
import { GhidraRuntime } from './ghidra.js';
import { id, text, fail, type Batch } from './model.js';

interface ProfileOwner {
  store: Store; runtime: GhidraRuntime;
  tasks: Map<string, Promise<Batch | {state:'empty';targetId:string}>>;
}
export interface Options { runtime?: CliRuntime; publisher?: (context: CommandContext) => Publisher }
class Owner {
  profiles = new Map<string, ProfileOwner>();
  constructor(private options: Options) {}
  selected(c: CommandContext) {
    const path = c.appArguments.AppDataDirectory;
    let profile = this.profiles.get(path);
    if (!profile) {
      const root = join(path, 'ghidra');
      profile = { store: new Store(root, c.profile.name, text(c.profile.values.server)), runtime: new GhidraRuntime(root, c), tasks: new Map() };
      this.profiles.set(path, profile);
    }
    if (profile.store.server !== c.profile.values.server) fail('binding', 'Profile server changed while durable work remains; restore its original binding before recovery.');
    const runtime = profile.runtime.fork(c);
    return { ...profile, ghidra: runtime, coordinator: new Coordinator(profile.store, this.options.publisher?.(c) ?? runtime, undefined, profile.tasks) };
  }
  async invalidateProfile(app: IAppArguments) {
    const profile = this.profiles.get(app.AppDataDirectory);
    if (Store.pending(join(app.AppDataDirectory,'ghidra'))) fail('blocked', 'Profile contains unverified findings; its journal must be preserved.');
    if (!profile) return;
    if (profile.tasks.size || profile.store.batches().some(b => !['published_verified', 'conflict_pending'].includes(b.state)))
      fail('blocked', 'Profile has unresolved publication work; its AppData must be preserved.');
    await profile.runtime.dispose(); profile.store.close(); this.profiles.delete(app.AppDataDirectory);
  }
  async dispose() {
    for (const profile of this.profiles.values()) {
      await Promise.allSettled([...profile.tasks.values()]);
      await profile.runtime.dispose(); profile.store.close();
    }
    this.profiles.clear();
  }
}
async function jsonFile(c: CommandContext, path: unknown) {
  const absolute = resolve(c.cwd, text(path, 4096));
  const info = await stat(absolute);
  if (!info.isFile() || info.size > 65536) fail('limit', 'Proposal must be a regular file of at most 64 KiB.');
  try {
    const content = await readFile(absolute);
    if (content.length > 65536) fail('limit', 'Proposal file exceeds 64 KiB.');
    return JSON.parse(content.toString('utf8'));
  }
  catch { fail('invalid', 'File must contain valid JSON.'); }
}
const fileOption = [{ flags: '--file <path>', description: 'Read the JSON proposal file', required: true }];
const fields = [
  ['server','--server <origin>','Select the Ghidra Server origin'],
  ['readerUser','--reader-user <user>','Select the read-only server account'],
  ['publisherUser','--publisher-user <user>','Select the publisher server account'],
  ['java','--java <path>','Locate Java 21'],
  ['ghidraHome','--ghidra-home <path>','Locate the matching Ghidra installation'],
  ['mcpJar','--mcp-jar <path>','Locate the GhidraMCP jar'],
  ['mcpJarSha256','--mcp-jar-sha256 <sha>','Verify the GhidraMCP artifact hash'],
  ['python','--python <path>','Locate the bridge Python executable'],
  ['bridgeDirectory','--bridge-directory <path>','Locate the pinned Python bridge module'],
];

export function createDefinition(options: Options = {}): CliDefinition {
  const owner = new Owner(options);
  return {
    name: 'insight-ghidra', applicationId: 'insight-ghidra', version: '0.1.0',
    description: 'Coordinate Ghidra readers and scoped comment publication',
    permissions: {}, resources: [owner], ...(options.runtime ? {runtime:options.runtime} : {}),
    profile: { fields: fields.map(([name,flags,description]) => ({name:name!,flags:flags!,description:description!,...(name==='server'?{required:true,normalize:(value:unknown)=>{const server=text(value);if(!/^ghidra:\/\/[^/?#@]+$/.test(server))fail('invalid','Server must be a ghidra://host:port origin.');return server;}}:{} )})) },
    auth: {
      loginOptions: [{flags:'--role <role>',description:'Select reader or publisher credentials',defaultValue:'reader'}, {flags:'--password-stdin',description:'Read the password from stdin'}],
      async login(c, o) {
        const role = text(o.role); if (!['reader','publisher'].includes(role)) fail('invalid','Role must be reader or publisher.');
        if (!o.passwordStdin || !c.stdinAvailable) fail('credentials','Supply --password-stdin for the selected role.');
        let candidate = ''; for await (const chunk of c.io.input) { candidate += chunk.toString(); if (candidate.length > 4096) fail('limit','Password input exceeds 4096 characters.'); }
        candidate = candidate.replace(/\r?\n$/, ''); if (!candidate || /[\r\n\0]/.test(candidate)) fail('credentials','Password must be one non-empty line.');
        await c.secrets.set(role+'Password',candidate);
        return {authenticated:true,identity:{role,user:c.profile.values[role+'User'],validation:'stored; server checked at worker startup'}};
      },
      async status(c) { const reader=Boolean(await c.secrets.get('readerPassword')), publisher=Boolean(await c.secrets.get('publisherPassword')); return {authenticated:reader,identity:{readerStored:reader,publisherStored:publisher}}; },
      async logout(c) { await c.secrets.delete('readerPassword'); await c.secrets.delete('publisherPassword'); },
    },
    builtins: [command('skill','Locate the installed workflow skill',()=>({version:'0.1.0',path:fileURLToPath(new URL('../../SKILL.md',import.meta.url))}))],
    commands: [
      command('targets','Select versioned programs',[
        command('register','Register a complete program identity',async ({options:o},c)=>owner.selected(c).store.register(await jsonFile(c,o.file)),{permission:Permission.Update,options:fileOption}),
        command('list','List registered program identities',(_i,c)=>owner.selected(c).store.targets(),{permission:Permission.ReadOnly}),
        command('show <target>','Show a registered program identity',({args},c)=>owner.selected(c).store.target(id(args.target)),{permission:Permission.ReadOnly}),
      ]),
      command('workers','Manage independent reader processes',[
        command('start <target> <worker>','Start a reader and dedicated bridge',async({args},c)=>{
          const selected=owner.selected(c), target=selected.store.target(id(args.target)), worker=id(args.worker);
          if (selected.store.workers().some(w=>w.id===worker)) fail('workerExists','Worker ID is already registered.');
          const binding=await selected.ghidra.startReader(target,worker);
          try { selected.store.putWorker(worker,target.id,binding); }
          catch (error) { await selected.ghidra.stop(target,binding); throw error; }
          return {id:worker,targetId:target.id,...binding};
        },{permission:Permission.Update}),
        command('list','List registered reader bindings',(_i,c)=>owner.selected(c).store.workers(),{permission:Permission.ReadOnly}),
        command('stop <worker>','Stop an owned reader process',async({args},c)=>{
          const selected=owner.selected(c), worker=id(args.worker), binding=selected.store.worker(worker);
          await selected.ghidra.stop(binding.identity as never,binding);selected.store.removeWorker(worker);return {id:worker,state:'stopped'};
        },{permission:Permission.Update}),
      ]),
      command('inspect <worker>','Read selected functions from a worker',async({args,options:o},c)=>{
        const selected=owner.selected(c), binding=selected.store.worker(id(args.worker));
        const result = await selected.ghidra.inspect(binding.identity as never,binding,text(o.functions));
        selected.store.updateReader(id(args.worker),result.binding);
        return result;
      },{permission:Permission.ReadOnly,options:[{flags:'--functions <selectors>',description:'Select up to eight function references',required:true}]}),
      command('findings','Journal scoped comment proposals',[
        command('submit','Persist an idempotent finding proposal',async({options:o},c)=>owner.selected(c).store.submit(await jsonFile(c,o.file)),{permission:Permission.Update,options:fileOption}),
        command('list','List durable findings',({options:o},c)=>owner.selected(c).store.findings(o.target? id(o.target):undefined),{permission:Permission.ReadOnly,options:[{flags:'--target <id>',description:'Filter by registered target'}]}),
        command('show <finding>','Show a finding and its outcome',({args},c)=>owner.selected(c).store.getFinding(id(args.finding)),{permission:Permission.ReadOnly}),
      ]),
      command('integrate <target>','Publish queued comments for one program',({args},c)=>owner.selected(c).coordinator.integrate(id(args.target)),{permission:Permission.Update}),
      command('status','Show durable publication state',(_i,c)=>{const selected=owner.selected(c);return {ownerPid:process.pid,profile:c.profile.name,targets:selected.store.targets(),workers:selected.store.workers(),batches:selected.store.batches()};},{permission:Permission.ReadOnly}),
      command('recover <batch>','Reconcile an interrupted publication batch',({args,options:o},c)=>owner.selected(c).coordinator.recover(id(args.batch),Boolean(o.abandonStaged)),{permission:Permission.Update,options:[{flags:'--abandon-staged',description:'Abandon a stopped pre-publication stage'}]}),
    ],
  };
}
export const createInsightCli = (options: Options = {}) => createCli(createDefinition(options));
