import {readFile,realpath} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const exec=promisify(execFile);
/** Independent kernel observation; no request enters the possibly wedged JVM. */
export async function nativeProcessProof(pid:number,executable:string,cwd:string,token:string):Promise<boolean>{
 if(process.platform!=='darwin'||!Number.isSafeInteger(pid)||pid<1)return false;
 try{
  const base=new URL('../../../runtime/native/',import.meta.url),path=fileURLToPath(new URL('process-identity-darwin-'+process.arch,base));
  const provenance=JSON.parse(await readFile(new URL('process-identity.provenance.json',base),'utf8'));
  if(provenance.platform!=='darwin'||provenance.architecture!==process.arch||createHash('sha256').update(await readFile(path)).digest('hex')!==provenance.sha256)return false;
  const result=await exec(path,[String(pid)],{timeout:3000,maxBuffer:16384,env:{PATH:'/usr/bin:/bin'}}),row=JSON.parse(result.stdout);
  if(row.pid!==pid||row.uid!==process.geteuid?.()||!Number.isSafeInteger(row.birthSeconds)||row.birthSeconds<=0||!Number.isSafeInteger(row.birthMicroseconds)||row.birthMicroseconds<0||row.birthMicroseconds>=1000000||typeof row.tokenSha256!=='string'||!/^[a-f0-9]{64}$/.test(row.tokenSha256))return false;
  if(await realpath(row.executable)!==await realpath(executable)||await realpath(row.root)!==await realpath(cwd))return false;
  return timingSafeEqual(Buffer.from(row.tokenSha256,'hex'),createHash('sha256').update(token).digest());
 }catch{return false;}
}
