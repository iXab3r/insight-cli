import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {cp, mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {x as extractTar} from 'tar';
import {writePackageBuildManifest} from '@eyeauras/cli-factory-ipc/build';
import {runNpm} from './npm-command.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const factoryNames=['@eyeauras/cli-factory','@eyeauras/cli-factory-ipc'];

// npm ci installs only the current platform. A published bundle must also contain
// keyring's optional binaries for the other platforms supported by Factory.
async function platformPackages(lock){
 const keyring=await json(join(root,'node_modules/@napi-rs/keyring/package.json'));
 return Object.entries(keyring.optionalDependencies).map(([name,version])=>{
  const path='node_modules/'+name,entry=lock.packages[path];
  assert.ok(entry?.optional&&entry.os&&entry.cpu,'Missing locked platform package: '+name);
  assert.equal(entry.version,version);
  assert.ok(entry.resolved.startsWith('https://registry.npmjs.org/'));
  return {path,...entry};
 });
}

async function platformArchives(lock,directory,offline){
 const archives=[];
 for(const record of await platformPackages(lock)){
  const result=await runNpm(['pack',record.resolved,'--ignore-scripts','--json','--pack-destination',directory,...(offline?['--offline']:[])],{cwd:directory,maxBuffer:1024*1024});
  const packed=JSON.parse(result.stdout)[0],archive=join(directory,packed.filename);
  assert.equal('sha512-'+createHash('sha512').update(await readFile(archive)).digest('base64'),record.integrity,'Platform archive integrity: '+record.path);
  archives.push({path:record.path,archive});
 }
 return archives;
}

/** Explicit acquisition step; subsequent packaging uses only the npm cache. */
export async function cacheFactoryPlatforms(){
 const work=await mkdtemp(join(tmpdir(),'insight-factory-cache-'));
 try{await platformArchives(await json(join(root,'package-lock.json')),work,false);}
 finally{await rm(work,{recursive:true,force:true});}
}

/** Pack a standalone staging tree: npm omits hoisted bundles when packing a workspace. */
export async function packCli(destination){
 destination=resolve(destination);await mkdir(destination,{recursive:true});
 const work=await mkdtemp(join(tmpdir(),'insight-pack-'));
 try{
  const source=join(root,'skills/ghidra-coordinator'),stage=join(work,'package'),downloads=join(work,'downloads');
  await mkdir(stage);await mkdir(downloads);
  const pkg=await json(join(source,'package.json')),lock=await json(join(root,'package-lock.json'));
  for(const file of ['package.json',...pkg.files])await cp(join(source,file),join(stage,file),{recursive:true});
  pkg.bundleDependencies=factoryNames;
  for(const [index,name] of factoryNames.entries()){
   const proof=await json(join(root,'vendor',index===0?'factory-core-fcb793f.json':'provenance.json'));
   assert.equal(proof.package,name);assert.equal(pkg.dependencies[name],proof.url);
   assert.equal(lock.packages['node_modules/'+name].resolved,proof.url);
   const bytes=await readFile(join(root,'vendor',proof.file));
   assert.equal(createHash('sha256').update(bytes).digest('hex'),proof.sha256);
   assert.equal('sha512-'+createHash('sha512').update(bytes).digest('base64'),lock.packages['node_modules/'+name].integrity);
   pkg.dependencies[name]=proof.version;
  }
  await writeFile(join(stage,'package.json'),JSON.stringify(pkg,null,2)+'\n');
  lock.name=pkg.name;lock.version=pkg.version;lock.packages['']=pkg;
  for(const [name,item] of Object.entries(lock.packages))if(item.link||name.startsWith('skills/'))delete lock.packages[name];
  await writeFile(join(stage,'package-lock.json'),JSON.stringify(lock,null,2)+'\n');
  await runNpm(['ci','--offline','--ignore-scripts','--omit=dev','--no-audit','--no-fund'],{cwd:stage,timeout:60000,maxBuffer:1024*1024});
  for(const {path,archive} of await platformArchives(lock,downloads,true)){
   await mkdir(join(stage,path),{recursive:true});
   await extractTar({file:archive,cwd:join(stage,path),strip:1});
  }
  // Invalidate npm's install-tree cache after adding the other platform payloads.
  await rm(join(stage,'node_modules/.package-lock.json'),{force:true});
  await writePackageBuildManifest(stage);
  const result=await runNpm(['pack','--ignore-scripts','--json','--pack-destination',destination],{cwd:stage,timeout:60000,maxBuffer:8*1024*1024});
  const packed=JSON.parse(result.stdout)[0];
  for(const name of factoryNames)assert.ok(packed.bundled.includes(name),'Missing Factory bundle: '+name);
  for(const {path} of await platformPackages(lock))assert.ok(packed.bundled.includes(path.slice('node_modules/'.length)),'Missing portable native bundle: '+path);
  return {packed,manifest:pkg};
 }finally{await rm(work,{recursive:true,force:true});}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.argv[2],'--cache');
 await cacheFactoryPlatforms();
 console.log('Factory platform archives verified and cached.');
}
