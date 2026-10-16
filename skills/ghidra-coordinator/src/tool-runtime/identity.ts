import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
function unavailable(pid:number):ProcessIdentity|undefined {try{process.kill(pid,0);}catch(e){if((e as NodeJS.ErrnoException).code==='ESRCH')return;}return {birth:'unavailable',strong:false};}
export interface ProcessIdentity {birth:string;strong:boolean;group?:number}
export async function processIdentity(pid:number):Promise<ProcessIdentity|undefined>{
 if(!Number.isSafeInteger(pid)||pid<1)return;
 try{
  if(process.platform==='linux'){
   const raw=await readFile('/proc/'+pid+'/stat','utf8'),parts=raw.slice(raw.lastIndexOf(')')+2).split(' ');
   if(parts[0]==='Z')return;
   return {birth:(await readFile('/proc/sys/kernel/random/boot_id','utf8')).trim()+':'+parts[19],strong:true,group:Number(parts[2])};
  }
  if(process.platform==='darwin'){
   const r=await exec('/bin/ps',['-p',String(pid),'-o','stat=','-o','pgid=','-o','lstart='],{env:{PATH:'/usr/bin:/bin',LC_ALL:'C',TZ:'UTC'},timeout:3000,maxBuffer:4096});
   const match=r.stdout.trim().match(/^(\S+)\s+(\d+)\s+(.+)$/);if(!match)return unavailable(pid);if(match[1]!.startsWith('Z'))return;
   // ps birth time is second-resolution; recovered macOS processes additionally need a tool identity hook.
   return {birth:match[3]!,strong:false,group:Number(match[2])};
  }
  if(process.platform==='win32'){
   const script='$p=Get-Process -Id '+pid+' -ErrorAction SilentlyContinue;if($p){$p.StartTime.ToUniversalTime().Ticks.ToString()}';
   const r=await exec('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,timeout:5000,maxBuffer:4096});
   return r.stdout.trim()?{birth:r.stdout.trim(),strong:true}:unavailable(pid);
  }
  try{process.kill(pid,0);return {birth:'unverified',strong:false};}catch{return;}
 }catch(error){
  if(['ENOENT','EACCES','EPERM'].includes((error as NodeJS.ErrnoException).code??'')||(error as {code?:number}).code===1)return unavailable(pid);
  throw error;
 }
}
