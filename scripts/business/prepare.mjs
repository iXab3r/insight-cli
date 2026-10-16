import assert from 'node:assert/strict';
import {readFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {cpus,totalmem,release} from 'node:os';
import {exec,save,PublicCli} from './public-cli.mjs';
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
// Read the PE export table independently of Ghidra to establish address ground truth.
export function exportsOf(bytes){
 const pe=bytes.readUInt32LE(0x3c),count=bytes.readUInt16LE(pe+6),optional=pe+24,size=bytes.readUInt16LE(pe+20),base=Number(bytes.readBigUInt64LE(optional+24));
 assert.equal(bytes.readUInt16LE(optional),0x20b);const sections=[];
 for(let i=0;i<count;i++){const p=optional+size+i*40;sections.push({rva:bytes.readUInt32LE(p+12),size:Math.max(bytes.readUInt32LE(p+8),bytes.readUInt32LE(p+16)),raw:bytes.readUInt32LE(p+20)});}
 const offset=rva=>{const s=sections.find(s=>rva>=s.rva&&rva<s.rva+s.size);assert.ok(s);return s.raw+rva-s.rva;};
 const table=offset(bytes.readUInt32LE(optional+112)),names=bytes.readUInt32LE(table+24),functions=offset(bytes.readUInt32LE(table+28)),strings=offset(bytes.readUInt32LE(table+32)),ordinals=offset(bytes.readUInt32LE(table+36)),out={};
 for(let i=0;i<names;i++){const p=offset(bytes.readUInt32LE(strings+i*4)),end=bytes.indexOf(0,p),name=bytes.subarray(p,end).toString('ascii');out[name]='0x'+(base+bytes.readUInt32LE(functions+bytes.readUInt16LE(ordinals+i*2)*4)).toString(16);}
 return out;
}
export async function prepare(root,directory){
 assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');assert.ok(!process.env.CI);
 const env=key=>{assert.ok(process.env[key],'Missing '+key);return process.env[key];};
 const java=env('INSIGHT_JAVA'),ghidra=env('INSIGHT_GHIDRA_HOME'),clang=env('INSIGHT_CLANG'),lld=env('INSIGHT_LLD');
 const result=await exec(process.execPath,[join(root,'scripts/test-package.mjs'),'--keep-installed'],{cwd:root,timeout:300000,maxBuffer:8*1024*1024});
 await readFile(join(root,'tests/acceptance/fixtures/research.c'));await save(join(directory,'package-result.json'),{stdout:result.stdout,stderr:result.stderr});
 const installed=result.stdout.match(/^Retained owned installed package: (.+)$/m)?.[1];assert.ok(installed);
 const cli=join(installed,'node_modules/@ixab3r/insight-cli/dist/src/bin.js'),artifact=join(installed,'artifacts/ixab3r-insight-cli-0.1.0.tgz'),inputs=[];
 for(const version of [1,2]){const folder=join(directory,'build-'+version);await mkdir(folder);const object=join(folder,'client.obj'),path=join(folder,'client.exe');
  await exec(clang,['--target=x86_64-pc-windows-msvc','-O1','-fno-builtin','-DVERSION='+version,'-c',join(root,'tests/acceptance/fixtures/research.c'),'-o',object]);
  await exec(lld,['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/out:'+path,object]);const bytes=await readFile(path);inputs.push({version,path,sha256:sha(bytes),exports:exportsOf(bytes)});
 }
 assert.equal(inputs[0].exports.case1,inputs[1].exports.case1);assert.notEqual(inputs[0].sha256,inputs[1].sha256);
 const manifest={schema:1,root,directory,cli,artifact,artifactSha256:sha(await readFile(artifact)),java,ghidra,clang,lld,inputs,profile:'business-'+randomUUID(),runtime:{
  java:(await exec(java,['-version'])).stderr.split('\n').filter(l=>/^(openjdk version|java version|OpenJDK|Java\(TM\))/.test(l)).join('\n'),ghidraProperties:(await readFile(join(ghidra,'Ghidra/application.properties'),'utf8')).split('\n').filter(l=>/^application\.(version|release.name|build.date)=/.test(l)),
  clang:(await exec(clang,['--version'])).stdout.split('\n')[0],lld:(await exec(lld,['--version'])).stdout.trim(),cpu:cpus()[0]?.model,logicalCpus:cpus().length,memoryBytes:totalmem(),osRelease:release()}};
 const client=new PublicCli(manifest,join(directory,'setup'));const owner=await client.call(['ipc-server','status'],{global:true});assert.equal(owner.running,false,'Stop unrelated work on the ordinary insight-cli owner before running business acceptance');await client.setup();
 await save(join(directory,'manifest.json'),manifest);return manifest;
}
