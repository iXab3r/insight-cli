import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,readdir,realpath} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {cpus,loadavg,release,totalmem} from 'node:os';
import {hash} from './public.mjs';
const exec=promisify(execFile);
export async function identity(o){
 const run=async(command,args)=>(await exec(command,args)).stdout.trim();
 const packageIdentity=async bin=>{const root=resolve(dirname(bin),'../..'),pkg=JSON.parse(await readFile(join(root,'package.json'),'utf8')),build=JSON.parse(await readFile(join(root,'.cli-package-build.json'),'utf8'));return {version:pkg.version,entrySha256:hash(await readFile(bin)),build,dependencies:pkg.dependencies};};
 const bridge=await realpath(o.bridge);assert.equal(await realpath(await run('git',['-C',bridge,'rev-parse','--show-toplevel'])),bridge,'Bridge identity must use its actual Git root');
 const runner={};for(const name of(await readdir('scripts/performance')).filter(n=>n.endsWith('.mjs')).sort())runner[name]=hash(await readFile(join('scripts/performance',name)));
 const java=await exec(o.java,['-version']);
 return {schema:1,startedAt:new Date().toISOString(),source:await run('git',['rev-parse','HEAD']),sourceDiffSha256:hash(await run('git',['diff','HEAD'])),runner,baseline:await packageIdentity(o.baseline),candidate:await packageIdentity(o.candidate),bridge:{commit:await run('git',['-C',bridge,'rev-parse','HEAD']),status:await run('git',['-C',bridge,'status','--porcelain']),python:(await exec(o.python,['--version'])).stdout.trim()},jars:{parity:hash(await readFile(o['parity-jar'])),versionFactor:hash(await readFile(o['stock-jar']))},ghidraProperties:await readFile(join(o.ghidra,'Ghidra/application.properties'),'utf8'),java:java.stderr.trim(),host:{platform:process.platform,arch:process.arch,node:process.version,cpus:cpus().length,cpu:cpus()[0].model,memory:totalmem(),os:release(),load:loadavg()},limitations:['External host work is not stopped. Per-request load is retained; an occupied host is not isolated native performance acceptance.','OS file caches are not flushed. Version phases are serial; CLI/RPC request order alternates within each read round.']};
}
