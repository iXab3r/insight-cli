// The upstream Core loader uses an ANSI import. Correct only an owned copy of its pinned GPL engine.
import type {CommandContext} from '@eyeauras/cli-factory';
import {join,dirname} from 'node:path';import {fileURLToPath} from 'node:url';import {mkdir,copyFile,rename,lstat} from 'node:fs/promises';import {constants} from 'node:fs';import {randomUUID} from 'node:crypto';
import {atomicWrite,readJson} from './tool-runtime/store.js';import {fileSha256,archiveName} from './tool-runtime/archives.js';import {runTool} from './tool-runtime/run.js';import {fail} from './model.js';
export const dnspyNative=fileURLToPath(new URL('../../runtime/native/dnspy-extension/',import.meta.url));
const engine='dnSpy.Debugger.DotNet.CorDebug.x.dll',original='13e0c4ea5396d071cdc7e31f0e5e9036c51da734a00b27d9d3dfeda9fa5b722f';
export async function prepareDnspy(root:string,c:CommandContext){
 const input=join(root,'bin',engine);if(await fileSha256(input)!==original)fail('binding','The pinned dnSpy Core engine differs before local Unicode preparation.');
 const directory=join(c.appArguments.AppDataDirectory,'runtime/dnspy/preparation',randomUUID()),extension=join(directory,'extension');await mkdir(extension,{recursive:true,mode:0o700});await copyFile(join(dnspyNative,'Insight.DnSpy.x.dll'),join(extension,'Insight.DnSpy.x.dll'),constants.COPYFILE_EXCL);
 const nonce=randomUUID(),plan=join(directory,'plan.json'),result=join(directory,'result.json'),output=join(directory,engine);await atomicWrite(plan,{Schema:1,Nonce:nonce,Mode:'patch-engine',Input:input,Output:output,BuildKey:join(dnspyNative,'upstream-public-build.snk'),Result:result});
 await runTool(c,{tool:'dnspy',role:'prepare-unicode-loader',executable:join(root,'dnSpy.exe'),arguments:['--multiple','--no-activate','--settings-file',join(directory,'settings.xml'),'--extension-directory',extension,'--insight-plan:'+plan],nativeDeadline:true,timeoutMs:60000,maxOutputBytes:65536});
 const receipt=await readJson<{schema:number;nonce:string;data:{state:string;mode:string;beforeSha256:string;afterSha256:string;unicodeLoader:boolean;strongNameIdentityPreserved:boolean}}>(result);
 if(receipt?.schema!==1||receipt.nonce!==nonce||receipt.data?.state!=='completed'||receipt.data.mode!=='patch-engine'||receipt.data.beforeSha256!==original||!receipt.data.unicodeLoader||!receipt.data.strongNameIdentityPreserved||await fileSha256(output)!==receipt.data.afterSha256)fail('binding','Owned dnSpy Unicode-loader preparation was not verified.',{diagnostics:directory});
 // The one-shot process has exited and the native Job has closed before replacing any mapped engine.
 await rename(output,input);await atomicWrite(join(root,'insight-unicode-loader.json'),receipt.data);
}
export async function prepareExternalDnspy(executable:string,stage:string,c:CommandContext){
 const manifest=await readJson<{schema:number;files:{path:string;size:number;sha256:string}[]}>(join(dnspyNative,'vendor-files.json'));if(manifest?.schema!==1||manifest.files.length!==867)fail('binding','Pinned dnSpy file inventory is missing.');const originalRoot=dirname(executable),owned=join(stage,'execution');
 for(const entry of manifest.files){archiveName(entry.path);const source=join(originalRoot,entry.path),destination=join(owned,entry.path),info=await lstat(source);if(!info.isFile()||info.size!==entry.size||await fileSha256(source)!==entry.sha256)fail('binding','External dnSpy component differs from the pinned vendor bundle.',{component:entry.path});await mkdir(dirname(destination),{recursive:true,mode:0o700});await copyFile(source,destination,constants.COPYFILE_EXCL);if(await fileSha256(destination)!==entry.sha256)fail('binding','Copied dnSpy component differs from the pinned vendor bundle.');}
 await prepareDnspy(owned,c);return {executable:join(owned,'dnSpy.exe'),arguments:[],environment:{}};
}
