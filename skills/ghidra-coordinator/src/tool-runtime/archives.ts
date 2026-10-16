import {createHash,randomUUID} from 'node:crypto';
import {createReadStream,createWriteStream,constants} from 'node:fs';
import {mkdir,open,rename,rm,stat,chmod,lstat} from 'node:fs/promises';
import {dirname,join,resolve,posix} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import * as tar from 'tar';
import * as zip from 'yauzl';
import {fail} from '../model.js';
import type {ToolArtifact} from './definition.js';
export async function fileSha256(path:string,signal?:AbortSignal){const hash=createHash('sha256');for await(const chunk of createReadStream(path,{signal}))hash.update(chunk);return hash.digest('hex');}
export function archiveName(name:string){
 if(!name||name.includes('\\')||name.includes('\0')||name.startsWith('/')||/^[a-zA-Z]:/.test(name)||name.split('/').includes('..'))fail('invalid','Runtime archive contains an unsafe path.');
 return name.replace(/^(\.\/)+/,'');
}
export async function extractArchive(file:string,destination:string,format:'tgz'|'zip',signal?:AbortSignal){
 signal?.throwIfAborted();
 await mkdir(destination,{recursive:true,mode:0o700});let count=0,bytes=0;
 const bound=(name:string,size:number)=>{archiveName(name);if(++count>100000||!Number.isSafeInteger(size)||size<0||(bytes+=size)>8*1024**3)fail('limit','Runtime archive exceeds extraction bounds.');};
 if(format==='tgz'){
  let unsafe:unknown;
  await readTar(file,tar.t({strict:true,filter:(path,entry)=>{try{
   if(!('type' in entry))fail('invalid','Unsupported runtime archive metadata.');
   bound(path,entry.size);if(!['File','Directory','SymbolicLink','Link','OldFile','ContiguousFile'].includes(entry.type))fail('invalid','Unsupported runtime archive entry.');
   if(entry.type==='SymbolicLink'||entry.type==='Link'){
    const target=entry.linkpath;if(typeof target!=='string')fail('invalid','Runtime archive link omitted its target.');if(target.startsWith('/')||target.includes('\\')||/^[a-zA-Z]:/.test(target))fail('invalid','Runtime archive link escapes extraction storage.');
    const joined=posix.normalize(entry.type==='Link'?target:posix.join(posix.dirname(path),target));archiveName(joined);
   }return true;
  }catch(error){unsafe??=error;return false;}}}),'end',signal);
  if(unsafe)throw unsafe;
  await readTar(file,tar.x({cwd:destination,strict:true,preserveOwner:false,noChmod:false}),'close',signal);return;
 }
 const archive=await new Promise<zip.ZipFile>((ok,bad)=>zip.open(file,{lazyEntries:true,strictFileNames:true},(e,z)=>e?bad(e):ok(z!)));
 await new Promise<void>((ok,bad)=>{
  const failed=(e:unknown)=>{archive.close();bad(e);};archive.on('error',failed);archive.on('end',ok);
  archive.on('entry',(entry:zip.Entry)=>{void(async()=>{
   signal?.throwIfAborted();bound(entry.fileName,entry.uncompressedSize);const mode=entry.externalFileAttributes>>>16,type=mode&0o170000;
   if(type&&type!==0o100000&&type!==0o040000)fail('invalid','Runtime zip may contain only files and directories.');
   const path=join(destination,entry.fileName);if(entry.fileName.endsWith('/'))await mkdir(path,{recursive:true,mode:0o700});
   else{await mkdir(dirname(path),{recursive:true,mode:0o700});const stream=await new Promise<Readable>((ok,bad)=>archive.openReadStream(entry,(e,s)=>e?bad(e):ok(s!)));await pipeline(stream,createWriteStream(path,{flags:'wx',mode:mode&0o111?0o755:0o644}),{signal});}
   archive.readEntry();
  })().catch(failed);});archive.readEntry();
 });
}
export async function cacheArtifact(artifact:ToolArtifact,cache:string,fetcher:typeof fetch,signal:AbortSignal,offline=false){
 signal.throwIfAborted();await mkdir(cache,{recursive:true,mode:0o700});const path=join(cache,artifact.sha256+'.'+artifact.format);
 try{const cached=await lstat(path);if(cached.isFile()&&(artifact.size===undefined||cached.size===artifact.size)&&await fileSha256(path,signal)===artifact.sha256)return path;fail('binding','Cached runtime archive failed its SHA256 check; remove the corrupt cache entry before retrying.');}
 catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 if(offline)fail('configuration','Required runtime archive is not cached; run the tool download command before using --offline.',{artifact:artifact.name,sha256:artifact.sha256});
 const temporary=path+'.partial-'+randomUUID();
 try{
  const response=await fetcher(artifact.url,{signal,cache:'no-store'});if(!response.ok||!response.body)fail('download','Pinned runtime download failed.',{artifact:artifact.name,status:response.status});
  let size=0;const hash=createHash('sha256'),handle=await open(temporary,'wx',0o600);
  try{for await(const chunk of response.body as unknown as AsyncIterable<Uint8Array>){signal.throwIfAborted();if((size+=chunk.byteLength)>(artifact.size??2*1024**3))fail('limit','Runtime download exceeds two GiB.');hash.update(chunk);await handle.writeFile(chunk);}await handle.sync();}finally{await handle.close();}
  if(artifact.size!==undefined&&size!==artifact.size)fail('binding','Downloaded runtime archive has an unexpected size.');
  if(hash.digest('hex')!==artifact.sha256)fail('binding','Downloaded runtime archive failed its pinned SHA256 check.');
  await rename(temporary,path);return path;
 }finally{await rm(temporary,{force:true});}
}

/** tar streams expose their own abort instead of Node's AbortSignal option. */
async function readTar(file:string,parser:tar.Parser,event:'end'|'close',signal?:AbortSignal){
 signal?.throwIfAborted();
 const input=createReadStream(file,{signal});
 await new Promise<void>((ok,bad)=>{
  let settled=false;
  const failed=(error:Error)=>{if(settled)return;settled=true;input.unpipe();input.destroy();parser.abort(error);bad(error);};
  parser.on('error',failed);input.on('error',failed);
  parser.once(event,()=>{if(!settled){settled=true;ok();}});
  input.pipe(parser as unknown as NodeJS.WritableStream);
 });
}
/** Consume local input once; extraction never races later edits to the caller's archive. */
export async function consumeArchive(path:string,cache:string,artifact:ToolArtifact,checksum?:string,signal?:AbortSignal){
 const {realpath,stat}=await import('node:fs/promises');
 const source=await realpath(path),input=await open(source,constants.O_RDONLY|(constants.O_NOFOLLOW??0)),temporary=join(cache,'local.partial-'+randomUUID());
 try{
  const metadata=await input.stat();if(!metadata.isFile()||metadata.size>2*1024**3)fail('invalid','Local runtime archive must be a regular file below two GiB.');
  await mkdir(cache,{recursive:true,mode:0o700});
  let size=0;const file=await open(temporary,'wx',0o600),hash=createHash('sha256');
  try{for await(const b of input.createReadStream({signal,autoClose:false})){size+=b.length;if(size>2*1024**3)fail('limit','Local archive grew beyond two GiB.');hash.update(b);await file.writeFile(b);}await file.sync();}finally{await file.close();}
  const sha256=hash.digest('hex');if(checksum!==undefined&&checksum.toLowerCase()!==sha256)fail('binding','Local runtime archive differs from its expected SHA256.');
  const handle=await open(temporary,'r'),magic=Buffer.alloc(2);try{await handle.read(magic,0,2,0);}finally{await handle.close();}
  const format=magic.toString('hex')==='504b'?'zip':'tgz',owned=join(cache,sha256+'.'+format);
  try{if(await fileSha256(owned)!==sha256)fail('binding','Existing local-archive cache is corrupt.');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;await rename(temporary,owned);}
  return {path:owned,artifact:{...artifact,sha256,size,format} as ToolArtifact};
 }finally{await input.close();await rm(temporary,{force:true});}
}
