import {fileURLToPath} from 'node:url';
import {join,isAbsolute} from 'node:path';
import {CliError} from '@eyeauras/cli-factory';
import {fileSha256} from './archives.js';
import {atomicWrite,readJson} from './store.js';
import {processIdentity} from './identity.js';
/** Stock Windows PowerShell loads the packaged first-party Job Object executor; no runtime compiler. */
export async function windowsJobLaunch(root:string,nonce:string,executable:string,args:string[],cwd:string,timeoutMs:number){
 if(process.platform!=='win32'||!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>600000)throw new CliError('Owned Windows job deadline must be 1–600 seconds.',{code:'tool.configuration'});
 const native=fileURLToPath(new URL('../../../runtime/native/windows-job/',import.meta.url));
 const proof=await readJson<{sha256:string;launcherSha256:string}>(join(native,'provenance.json'));
 if(!proof||await fileSha256(join(native,'Insight.WindowsJob.dll'))!==proof.sha256||await fileSha256(join(native,'windows-job.ps1'))!==proof.launcherSha256)throw new CliError('Packaged Windows job differs from its reviewed build.',{code:'tool.binding'});
 const identity=await processIdentity(process.pid),system=process.env.SystemRoot??process.env.WINDIR;
 if(!identity?.strong||!/^\d+$/.test(identity.birth)||!system||!isAbsolute(system))throw new CliError('Windows owner birth identity or system directory is unavailable.',{code:'tool.process.unverified'});
 const specification=join(root,'job-specification.json');await atomicWrite(specification,{schema:1,nonce,executable,arguments:args,cwd,timeoutMs,ownerPid:process.pid,ownerBirthTicks:identity.birth});
 return {executable:join(system,'System32/WindowsPowerShell/v1.0/powershell.exe'),arguments:['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',join(native,'windows-job.ps1'),'-Specification',specification]};
}
export async function windowsJobResult(root:string,nonce:string,launcherPid:number){
 const result=await readJson<{schema:number;nonce:string;launcherPid:number;phase:string;childExitCode:number;childPid:number;childBirthTicks:string}>(join(root,'job-result.json'));
 const started=await readJson<{schema:number;nonce:string;launcherPid:number;childPid:number;childBirthTicks:string;phase:string}>(join(root,'job-started.json'));
 if(!result||!started||result.schema!==1||started.schema!==1||result.nonce!==nonce||started.nonce!==nonce||result.launcherPid!==launcherPid||started.launcherPid!==launcherPid||!['completed','timeout','owner_lost'].includes(result.phase)||!Number.isSafeInteger(result.childExitCode)||result.childExitCode<0||result.childExitCode>0xffffffff||!Number.isSafeInteger(result.childPid)||result.childPid<1||result.childPid!==started.childPid||!/^\d+$/.test(result.childBirthTicks)||result.childBirthTicks!==started.childBirthTicks||started.phase!=='assigned_suspended')throw new CliError('Owned Windows job result is missing or unverified; no successful outcome was assumed.',{code:'tool.process.unverified'});
 return result;
}
