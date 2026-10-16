import {createHash,randomUUID} from 'node:crypto';
import {createReadStream,createWriteStream} from 'node:fs';
import {mkdir,open,rename,rm,stat,chmod} from 'node:fs/promises';
import {dirname,join,resolve,posix} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import * as tar from 'tar';
import * as zip from 'yauzl';
import {fail} from './model.js';
import type {RuntimeArtifact} from './runtime-catalog.js';
export async function fileSha256(path:string){const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return hash.digest('hex');}
export function archiveName(name:string){
 if(!name||name.includes('\\')||name.includes('\0')||name.startsWith('/')||/^[a-zA-Z]:/.test(name)||name.split('/').includes('..'))fail('invalid','Runtime archive contains an unsafe path.');
 return name.replace(/^(\.\/)+/,'');
}
export async function extractArchive(file:string,destination:string,format:'tgz'|'zip'){
 await mkdir(destination,{recursive:true,mode:0o700});let count=0,bytes=0;
 const bound=(name:string,size:number)=>{archiveName(name);if(++count>100000||!Number.isSafeInteger(size)||size<0||(bytes+=size)>8*1024**3)fail('limit','Runtime archive exceeds extraction bounds.');};
 if(format==='tgz'){
  let unsafe:unknown;
  await tar.t({file,strict:true,filter:(path,entry)=>{try{
   if(!('type' in entry))fail('invalid','Unsupported runtime archive metadata.');
   bound(path,entry.size);if(!['File','Directory','SymbolicLink','Link','OldFile','ContiguousFile'].includes(entry.type))fail('invalid','Unsupported runtime archive entry.');
   if(entry.type==='SymbolicLink'||entry.type==='Link'){
    const target=entry.linkpath;if(typeof target!=='string')fail('invalid','Runtime archive link omitted its target.');if(target.startsWith('/')||target.includes('\\')||/^[a-zA-Z]:/.test(target))fail('invalid','Runtime archive link escapes extraction storage.');
    const joined=posix.normalize(entry.type==='Link'?target:posix.join(posix.dirname(path),target));archiveName(joined);
   }return true;
  }catch(error){unsafe??=error;return false;}}});
  if(unsafe)throw unsafe;
  await tar.x({file,cwd:destination,strict:true,preserveOwner:false,noChmod:false});return;
 }
 const archive=await new Promise<zip.ZipFile>((ok,bad)=>zip.open(file,{lazyEntries:true,strictFileNames:true},(e,z)=>e?bad(e):ok(z!)));
 await new Promise<void>((ok,bad)=>{
  const failed=(e:unknown)=>{archive.close();bad(e);};archive.on('error',failed);archive.on('end',ok);
  archive.on('entry',(entry:zip.Entry)=>{void(async()=>{
   bound(entry.fileName,entry.uncompressedSize);const mode=entry.externalFileAttributes>>>16,type=mode&0o170000;
   if(type&&type!==0o100000&&type!==0o040000)fail('invalid','Runtime zip may contain only files and directories.');
   const path=join(destination,entry.fileName);if(entry.fileName.endsWith('/'))await mkdir(path,{recursive:true,mode:0o700});
   else{await mkdir(dirname(path),{recursive:true,mode:0o700});const stream=await new Promise<Readable>((ok,bad)=>archive.openReadStream(entry,(e,s)=>e?bad(e):ok(s!)));await pipeline(stream,createWriteStream(path,{flags:'wx',mode:mode&0o111?0o755:0o644}));}
   archive.readEntry();
  })().catch(failed);});archive.readEntry();
 });
}
export async function cacheArtifact(artifact:RuntimeArtifact,cache:string,fetcher:typeof fetch,signal:AbortSignal,offline=false){
 await mkdir(cache,{recursive:true,mode:0o700});const path=join(cache,artifact.sha256+'.'+artifact.format);
 try{if((await stat(path)).isFile()&&await fileSha256(path)===artifact.sha256)return path;fail('binding','Cached runtime archive failed its SHA256 check; remove the corrupt cache entry before retrying.');}
 catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 if(offline)fail('configuration','Required runtime archive is not cached; run ghidra download before using --offline.',{artifact:artifact.name,sha256:artifact.sha256});
 const temporary=path+'.partial-'+randomUUID();
 try{
  let headers:Record<string,string>={};
  if(artifact.url.startsWith('https://ghcr.io/v2/homebrew/core/ghidra/')){
   const response=await fetcher('https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/ghidra:pull',{signal,redirect:'error'});
   if(!response.ok)fail('download','Anonymous runtime registry authorization failed.');
   const value=await response.json() as {token?:string};if(!value.token||value.token.length>8192)fail('download','Invalid anonymous runtime registry token.');headers={Authorization:'Bearer '+value.token};
  }
  const response=await fetcher(artifact.url,{signal,headers});if(!response.ok||!response.body)fail('download','Pinned runtime download failed.',{artifact:artifact.name,status:response.status});
  let size=0;const hash=createHash('sha256'),handle=await open(temporary,'wx',0o600);
  try{for await(const chunk of response.body as unknown as AsyncIterable<Uint8Array>){if((size+=chunk.byteLength)>2*1024**3)fail('limit','Runtime download exceeds two GiB.');hash.update(chunk);await handle.writeFile(chunk);}await handle.sync();}finally{await handle.close();}
  if(hash.digest('hex')!==artifact.sha256)fail('binding','Downloaded runtime archive failed its pinned SHA256 check.');
  await rename(temporary,path);return path;
 }finally{await rm(temporary,{force:true});}
}
