/** Private Python-capable LLDB dependency. The public application remains `ghidra`. */
import type {CommandContext} from '@eyeauras/cli-factory';
import {join} from 'node:path';
import {release} from 'node:os';
import {ToolInstaller,type ToolLaunch} from './tool-runtime/installer.js';
import {catalogArtifact} from './tool-runtime/catalog.js';
import {runTool} from './tool-runtime/run.js';
import {fail} from './model.js';

export const managedGhidraDebugger=()=>process.platform==='darwin'&&process.arch==='arm64'&&Number(release().split('.')[0])>=24;
export function ghidraDebuggerLaunch(root:string):ToolLaunch{
 const python=join(root,'python@3.15/3.15.0/Frameworks/Python.framework/Versions/3.15');
 return {executable:join(root,'bin/lldb'),arguments:[],environment:{PYTHONHOME:python,PYTHONPATH:join(root,'lldb/23.1.3_1/lib/python3.15/site-packages'),LLDB_PYTHON_LIBRARY:join(python,'Python'),LLDB_DEBUGSERVER_PATH:join(root,'bin/debugserver'),PYTHONNOUSERSITE:'1',PYTHONDONTWRITEBYTECODE:'1'}};
}
export function ghidraDebuggerInstaller(c:CommandContext){return new ToolInstaller(c,{
 id:'ghidra-debugger',primary:'lldb',components:()=>{
  if(!managedGhidraDebugger())fail('unsupported','The managed Ghidra LLDB/Python backend requires macOS 15+ ARM64.');
  return {lldb:catalogArtifact('0f9e88490490fb2f487ad6f02d7aea774629a2839a10497fdcbaad9c6481c839')};
 },launch:roots=>ghidraDebuggerLaunch(roots.lldb!),probe:async launch=>{
  const result=await runTool(c,{tool:'ghidra-debugger',role:'doctor',executable:launch.executable,arguments:['--no-lldbinit','--batch','-o','script import lldb,sys; print("INSIGHT_LLDB_PYTHON_OK",lldb.SBDebugger.GetVersionString(),sys.version_info[:2])'],environment:{...launch.environment,PATH:'/usr/bin:/bin'},timeoutMs:30000,maxOutputBytes:65536,nativeDeadline:true});
  if(!result.stdout.includes('INSIGHT_LLDB_PYTHON_OK lldb version 23.1.3 (3, 15)'))fail('configuration','The managed debugger must load LLDB 23.1.3 and its own Python 3.15.');
  return {version:'23.1.3',python:'3.15',backend:'managed-lldb',hostHomebrewRequired:false};
 }
});}
export async function prepareGhidraDebugger(c:CommandContext,o:Record<string,unknown>={}){
 const installer=ghidraDebuggerInstaller(c);
 if(o.archive||(await installer.status()).state!=='installed')await installer.install(o);
 return installer.selected();
}
