import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {fail} from '../model.js';
import type {ToolProcessHooks} from './commands.js';

export interface ToolArtifact {
  name:string; url:string; sha256:string; size?:number; format:'zip'|'tgz'; root:string; license:string;
  delivery?:{kind:'vendor-direct';publisher:string;termsUrl:string;reason:string};
}
export interface ToolComponent {
  id:string; version:string; artifacts:ToolArtifact[]; dependencies?:string[];
}
export interface ToolInstallation {
  schema:1; tool:string; id:string; mode:'managed'|'external'; root:string;
  executable:string; fingerprint:string; selectedAt:string; uninstalledAt?:string;
  components:Record<string,string>;
}
export interface ToolProcess {
  schema:1; id:string; tool:string; role:string; installation:string;
  state:'starting'|'running'|'exited'|'failed'|'unverified'; executable:string;
  pid?:number; identity?:string; session?:string; target?:string; createdAt:string;
  endedAt?:string; exitCode?:number|null; signal?:string|null; elapsedMs?:number;
}
export interface ToolLifecycle {
  download(options:Record<string,unknown>,context:CommandContext):Promise<unknown>;
  install(options:Record<string,unknown>,context:CommandContext):Promise<unknown>;
  uninstall(options:Record<string,unknown>,context:CommandContext):Promise<unknown>;
  doctor(options:Record<string,unknown>,context:CommandContext):Promise<unknown>;
  status?(options:Record<string,unknown>,context:CommandContext):Promise<unknown>;
}
export interface ToolDefinition {
  id:string; description:string; components:ToolComponent[]; lifecycle:ToolLifecycle;
  vendorDirect?:boolean;
  installOptions?:NonNullable<CommandDefinition['options']>;
  commands?:CommandDefinition[];
  processes?:ToolProcessHooks;
}
/** Definitions are data/hooks. Factory remains the only parser, permission and output owner. */
export function defineTool(value:ToolDefinition):ToolDefinition {
  if(!/^[a-z][a-z0-9-]*$/.test(value.id))fail('invalid','Invalid tool name.');
  const components=new Map(value.components.map(item=>[item.id,item]));
  if(components.size!==value.components.length)fail('invalid','Duplicate tool component.');
  const done=new Set<string>(),pending=new Set<string>();
  function visit(id:string){
    const component=components.get(id);if(!component)fail('invalid','Unknown tool dependency.');
    if(pending.has(id))fail('invalid','Cyclic tool dependency.');if(done.has(id))return;
    pending.add(id);for(const dependency of component.dependencies??[])visit(dependency);
    pending.delete(id);done.add(id);
    for(const artifact of component.artifacts){
      if(!/^[a-f0-9]{64}$/.test(artifact.sha256)||new URL(artifact.url).protocol!=='https:')fail('invalid','Tool artifact requires HTTPS and a pinned SHA256.');
    }
  }
  for(const id of components.keys())visit(id);
  return value;
}
export function lifecycleCommands(tool:ToolDefinition):CommandDefinition[]{
  const offline={flags:'--offline',description:'Use verified local archives and cache without network access'};
  const vendor=tool.vendorDirect?[{flags:'--vendor-direct',description:'Explicitly acquire pinned non-redistributable bytes from the named vendor'}]:[];
  const source=[...vendor,{flags:'--archive <path>',description:'Install from a local tool archive'},
    {flags:'--archive-sha256 <sha256>',description:'Expected SHA256 of the local tool archive'},
    {flags:'--executable <path>',description:'Use an external executable; its files are never deleted'},offline];
  const leaf=(name:keyof ToolLifecycle,description:string,permission:string,options:CommandDefinition['options'])=>
    command(name,description,({options:o},c)=>tool.lifecycle[name]!(o,c),{permission,options});
  return [
    leaf('download','Download the pinned tool and required runtime components',Permission.Update,[offline,...vendor]),
    leaf('install','Prepare, verify and select the tool installation',Permission.Update,tool.installOptions??source),
    leaf('uninstall','Remove owned software while preserving research and external files','Destructive',[
      {flags:'--purge-cache',description:'Also remove owned downloaded archives'}]),
    leaf('doctor','Run bounded probes of the selected tool',Permission.Update,[]),
    ...(tool.lifecycle.status?[leaf('status','Inspect installation and process state without launching the tool',Permission.ReadOnly,[])]:[]),
  ];
}
