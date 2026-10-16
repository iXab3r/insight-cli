import {runtimeSelection} from './runtime-selection.js';
import type {CommandContext} from '@eyeauras/cli-factory';
import {join,resolve,sep} from 'node:path';
import {readFile,readdir,realpath} from 'node:fs/promises';
import {serverIdentity,stopLocalServer} from './server.js';
import {HttpBridge} from './transport.js';
import {registerExistingProcess,type ProcessRecord} from './tool-runtime/supervisor.js';
import type {ToolProcessHooks} from './tool-runtime/commands.js';
import {fail} from './model.js';
import type {Scope,Workspace} from './workspace.js';
async function ownedPath(c:CommandContext,path:unknown){
 if(typeof path!=='string'||!resolve(path).startsWith(resolve(c.appArguments.AppDataDirectory)+sep)||await realpath(path)!==resolve(path))fail('binding','Tool resource moved outside this profile.');return path;
}
export async function verifyGhidraProcess(r:ProcessRecord,c:CommandContext):Promise<boolean|undefined>{
 try{
  if(r.metadata?.serverDirectory){const directory=await ownedPath(c,r.metadata.serverDirectory),local=JSON.parse(await readFile(join(directory,'server/local.json'),'utf8'));return Number((await serverIdentity(local,c)).pid)===r.pid;}
  if(r.metadata?.debuggerReceipt){const path=await ownedPath(c,r.metadata.debuggerReceipt),row=JSON.parse(await readFile(path,'utf8')),root=await ownedPath(c,r.metadata.contextRoot),binding=JSON.parse(await readFile(join(root,'process.json'),'utf8'));
   if(row.root!==root||row.ownerToken!==binding.tokenSecret||row.guiPid!==binding.pid||!Number.isSafeInteger(row.identityPort)||row.identityPort<1||row.identityPort>65535)return false;
   const token=await c.secrets.require(binding.tokenSecret),response=await c.fetch('http://127.0.0.1:'+row.identityPort+'/identity',{redirect:'error',signal:AbortSignal.timeout(1000),headers:{Authorization:'Bearer '+token}});
   const body=await response.text();if(!response.ok||body.length>4096)return false;const info=JSON.parse(body);return info.id===row.id&&info.pid===row.supervisorPid&&(r.role==='debugger'?info.childPid===r.pid:info.pid===r.pid);
  }
  if(r.metadata?.contextRoot){const root=await ownedPath(c,r.metadata.contextRoot),binding=JSON.parse(await readFile(join(root,'process.json'),'utf8'));
   if(binding.root!==root||binding.pid!==r.pid||binding.runtimeFingerprint!==r.installation||binding.target!==r.target)return false;
   const token=await c.secrets.require(binding.tokenSecret),info=await new HttpBridge(binding.endpoint,c.fetch,undefined,token,1500).instance();
   return info.pid===r.pid&&info.tcp_port===Number(new URL(binding.endpoint).port)&&String(info.project_path??'').startsWith(root+sep);
  }
  return undefined;
 }catch{return false;}
}
export function ghidraProcessHooks(workspace:(c:CommandContext)=>Workspace,close:(scope:Scope,c:CommandContext)=>Promise<unknown>):ToolProcessHooks{
 return {
  verify:verifyGhidraProcess,
  async discover(c){
   const directory=c.appArguments.AppDataDirectory,executable=runtimeSelection(directory)?.java??String(c.profile.values.java??'unverified-legacy-executable');
   async function walk(path:string,depth=0):Promise<void>{
    if(depth>6)return;let entries;try{entries=await readdir(path,{withFileTypes:true});}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return;throw e;}
    for(const entry of entries){const at=join(path,entry.name);if(entry.isDirectory())await walk(at,depth+1);else if(entry.name==='process.json'){
     const b=JSON.parse(await readFile(at,'utf8'));if(b.toolProcessId||!b.pid)continue;
     let session:string|undefined;if(b.context)session=workspace(c).contextById(b.context).session;
     try{await registerExistingProcess(directory,{tool:'ghidra',role:b.mode==='gui'?'gui':b.kind,installation:b.runtimeFingerprint,target:b.target,session,metadata:{contextRoot:b.root}},executable,b.pid,r=>verifyGhidraProcess(r,c));}catch{}
    }}
   }
   await walk(join(directory,'workspace/ghidra-native'));
   try{const b=JSON.parse(await readFile(join(directory,'workspace/server/local.json'),'utf8'));
    if(!b.toolProcessId&&b.pid)await registerExistingProcess(directory,{tool:'ghidra',role:'server',installation:'legacy',metadata:{serverDirectory:join(directory,'workspace')}},executable,b.pid,r=>verifyGhidraProcess(r,c));
   }catch{}
  },
  async stop(r,c){
   if(r.metadata?.contextRoot){if(!r.session||!r.target)fail('busy','Internal Ghidra task is active; finish it before stopping its process.');await close({session:r.session,target:r.target},c);}
   else if(r.role==='server'){
    const {runtimeProcesses}=await import('./runtime-manager.js');if((await runtimeProcesses(c.appArguments.AppDataDirectory)).some(p=>p.kind!=='server'))fail('busy','Close Ghidra contexts before stopping their server.');
    await stopLocalServer(await ownedPath(c,r.metadata?.serverDirectory),c);
   }
  },
  async beforeKill(r,c){
   // Save debugger traces and terminate the inferior through the existing authenticated GUI
   // protocol. A generic signal to LLDB cannot establish that its debuggee has exited.
   if(r.role==='gui'&&r.session&&r.target){
    const scope={session:r.session,target:r.target},w=workspace(c),context=w.context(scope);
    const debuggerActive=context.debugger?.connected||context.debugger?.traces.some(t=>t.connected)||w.unresolved(scope).some(q=>(q.execution as {kind?:string}|undefined)?.kind==='debugger');
    if(debuggerActive)await close(scope,c);
   }
   if(r.role.startsWith('debugger'))fail('blocked','Close the owning GUI context to verify debugger and inferior cleanup.');
  },
 };
}
