import assert from 'node:assert/strict';
import {createReadStream,createWriteStream} from 'node:fs';
import {mkdir,readFile,readdir,lstat,realpath,open,rename,unlink,link} from 'node:fs/promises';
import {join,relative,resolve,dirname,basename,sep} from 'node:path';
import {homedir} from 'node:os';
import {createHash,randomUUID} from 'node:crypto';
import {createGzip,createGunzip} from 'node:zlib';
import {Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {DatabaseSync} from 'node:sqlite';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),allowed=['workspace/ghidra-native','workspace/server/data'];
async function durable(path,value){await mkdir(dirname(path),{recursive:true,mode:0o700});const temporary=path+'.new-'+randomUUID(),f=await open(temporary,'wx',0o600);try{await f.writeFile(JSON.stringify(value,null,2)+'\n');await f.sync();}finally{await f.close();}await rename(temporary,path);const d=await open(dirname(path),'r');try{await d.sync();}finally{await d.close();}}
async function files(root){const s=await lstat(root);assert.ok(s.isDirectory()&&!s.isSymbolicLink(),'Storage housekeeping refuses linked paths');const a=[];for(const e of await readdir(root,{withFileTypes:true})){const p=join(root,e.name);assert.ok(!e.isSymbolicLink(),'Storage housekeeping refuses linked paths');if(e.isDirectory())a.push(...await files(p));else if(e.isFile())a.push(p);}return a;}
async function digest(stream){const h=createHash('sha256');for await(const chunk of stream)h.update(chunk);return h.digest('hex');}
async function unchanged(path,before){const after=await lstat(path,{bigint:true});assert.equal(after.ino,before.ino);assert.equal(after.size,before.size);assert.equal(after.mtimeNs,before.mtimeNs);}
/** Completed disposable backing files only. Immutable artifacts/journals remain in place. */
export async function archivePayloads(root,destination,{minimum=4*1024**2,roots=allowed}={}){
 assert.ok(roots.every(p=>[...allowed,'owned.rep'].includes(p)));root=await realpath(resolve(root));await mkdir(destination,{recursive:true,mode:0o700});const indexPath=join(destination,'index.json');
 let index;try{index=JSON.parse(await readFile(indexPath,'utf8'));assert.equal(index.root,root);}catch(e){if(e.code!=='ENOENT')throw e;index={schema:1,root,files:[]};}
 for(const directory of roots){let list;try{list=await files(join(root,directory));}catch(e){if(e.code==='ENOENT')continue;throw e;}
  for(const source of list){if(!source.endsWith('.gbf'))continue;const before=await lstat(source,{bigint:true});assert.ok(before.isFile()&&!before.isSymbolicLink());if(before.size<BigInt(minimum))continue;
   const name=relative(root,source),archive=join(destination,name+'.gz');await mkdir(dirname(archive),{recursive:true,mode:0o700});const h=createHash('sha256'),temporary=archive+'.new-'+randomUUID();
   try{await pipeline(createReadStream(source),new Transform({transform(chunk,encoding,done){h.update(chunk);done(null,chunk);}}),createGzip({level:1}),createWriteStream(temporary,{flags:'wx',mode:0o600}));
    const sha256=h.digest('hex');assert.equal(await digest(createReadStream(temporary).pipe(createGunzip())),sha256,'Compressed backing bytes differ');await unchanged(source,before);
    const fd=await open(temporary,'r');try{await fd.sync();}finally{await fd.close();}await rename(temporary,archive);const parent=await open(dirname(archive),'r');try{await parent.sync();}finally{await parent.close();}
    const item={path:name,archive:relative(destination,archive),sha256,size:Number(before.size),mode:Number(before.mode)&0o777,mtimeNs:before.mtimeNs.toString()};
    const prior=index.files.findIndex(f=>f.path===name);if(prior<0)index.files.push(item);else index.files[prior]=item;
    await durable(indexPath,index);await unchanged(source,before);await unlink(source);
   }finally{await unlink(temporary).catch(e=>{if(e.code!=='ENOENT')throw e;});}
  }
 }
 return {archivedFiles:index.files.length,retainedLogicalBytes:index.files.reduce((n,f)=>n+f.size,0),index:indexPath};
}
export async function restorePayloads(indexPath){const index=JSON.parse(await readFile(indexPath,'utf8')),root=await realpath(index.root);assert.equal(root,index.root);
 for(const f of index.files){assert.ok([...allowed,'owned.rep'].some(p=>f.path.startsWith(p+'/'))&&!f.path.split('/').includes('..'));const target=resolve(root,f.path),archive=resolve(dirname(indexPath),f.archive);assert.ok(archive.startsWith(resolve(dirname(indexPath))+sep));assert.equal(await realpath(dirname(target)),dirname(target));
  const temporary=target+'.restore-'+randomUUID();try{await pipeline(createReadStream(archive),createGunzip(),createWriteStream(temporary,{flags:'wx',mode:f.mode}));assert.equal(await digest(createReadStream(temporary)),f.sha256);const fd=await open(temporary,'r');try{await fd.sync();}finally{await fd.close();}await link(temporary,target);}finally{await unlink(temporary).catch(e=>{if(e.code!=='ENOENT')throw e;});}
 }
}
export async function verifyReceiptNotLive(receipt,{probe=pid=>process.kill(pid,0),inspect=async pid=>(await exec('/bin/ps',['-p',String(pid),'-o','args='])).stdout}={}){
 assert.ok(Number.isSafeInteger(receipt.pid)&&receipt.pid>0);assert.ok(typeof receipt.root==='string'&&receipt.root.length>0);
 try{probe(receipt.pid);}catch(e){if(e.code==='ESRCH')return;if(e.code!=='EPERM')throw e;}
 // PID reuse can point at another user's process; EPERM alone proves neither identity nor absence.
 let args;try{args=await inspect(receipt.pid);}catch(e){if(e.code===1)return;throw e;}
 assert.ok(typeof args==='string'&&args.trim().length>0,'Cannot establish the recorded process identity');
 assert.ok(!args.includes(receipt.root),'An owned native backing store is still live');
}
export async function verifyClosedProfile(root){assert.equal(await realpath(root),root);
 const db=new DatabaseSync(join(root,'workspace/workspace.sqlite'),{readOnly:true});try{
  const contexts=db.prepare('SELECT data FROM contexts').all().map(r=>JSON.parse(r.data));assert.ok(contexts.every(c=>c.state==='stopped'),'A private context is not closed');
  for(const sha of new Set(contexts.map(c=>c.workingSnapshot?.sha256))){assert.match(sha??'',/^[a-f0-9]{64}$/);assert.equal(await digest(createReadStream(join(root,'workspace/artifacts',sha+'.gzf'))),sha,'Retained private snapshot does not verify');}
  for(const [table,states]of [['requests',"'running','unknown'"],['publications',"'preparing','commit_intent','unknown'"],['administration_requests',"'running','unknown'"]])assert.equal(db.prepare(`SELECT count(*) AS n FROM ${table} WHERE state IN (${states})`).get().n,0,'Unresolved recovery evidence must remain usable');
 }finally{db.close();}
 const local=JSON.parse(await readFile(join(root,'workspace/server/local.json'),'utf8'));assert.equal(local.phase,'stopped');assert.equal(local.pid,undefined);
 const native=join(root,'workspace/ghidra-native');for(const path of(await files(native)).filter(p=>p.endsWith('/process.json'))){const receipt=JSON.parse(await readFile(path,'utf8'));assert.ok(receipt.root.startsWith(native+sep));await verifyReceiptNotLive(receipt);}
}
export async function archiveClosedProfile(o,profile){
 assert.ok(profile.startsWith('perf66-'+o.label+'-'));assert.equal(basename(profile),profile);
 const root=join(homedir(),'Library/Application Support/insight-cli',profile);await verifyClosedProfile(root);
 return archivePayloads(root,join(o.root,'closed-fixtures',profile));
}
