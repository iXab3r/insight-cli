// Reproducible additive patch of the pinned Ghidra bridge; never modifies Factory.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {readFile,writeFile,mkdtemp,readdir,rm} from 'node:fs/promises';
import {join,resolve,dirname,delimiter} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const {values:o}=parseArgs({options:{input:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},output:{type:'string'},receipt:{type:'string'}}});
for(const key of ['input','java','ghidra-home','output','receipt'])assert.ok(o[key],key);
const root=fileURLToPath(new URL('../',import.meta.url)),sha=async p=>createHash('sha256').update(await readFile(p)).digest('hex'),exec=promisify(execFile);
const original='7084e2fda16dc779dd05398e48821ff3f9ace4d32757ea143b257b39689e5fbd';assert.equal(await sha(o.input),original,'Only the pinned unmodified bridge is admitted');
const jars=[];async function walk(folder){for(const item of await readdir(folder,{withFileTypes:true})){const path=join(folder,item.name);if(item.isDirectory())await walk(path);else if(item.name.endsWith('.jar')&&folder.endsWith('/lib'))jars.push(path);}}
await walk(join(o['ghidra-home'],'Ghidra'));jars.sort();const asm=jars.find(p=>p.endsWith('/asm-9.7.1.jar'));assert.ok(asm,'Pinned Ghidra ASM is required');
const helper='skills/ghidra-coordinator/references/native/InsightResearchView.java',patcher='scripts/native/InstallResearchView.java',temp=await mkdtemp(join(tmpdir(),'iv-build-'));
try{
 const java=resolve(o.java),javac=join(dirname(java),process.platform==='win32'?'javac.exe':'javac');
 await exec(javac,['-proc:none','-g:none','-cp',[resolve(o.input),...jars].join(delimiter),'-d',temp,join(root,helper),join(root,patcher)],{maxBuffer:262144,timeout:60000});
 await exec(java,['-cp',[temp,asm].join(delimiter),'InstallResearchView',resolve(o.input),temp,resolve(o.output)],{maxBuffer:262144,timeout:60000});
 const version=await exec(java,['--version']);
 await writeFile(o.receipt,JSON.stringify({schema:1,upstreamSha256:original,upstreamGitArtifact:'6e4bfc9:skills/ghidra-coordinator/runtime/GhidraMCP-7.0.0.jar',sha256:await sha(o.output),inputs:{[helper]:await sha(join(root,helper)),[patcher]:await sha(join(root,patcher)),'scripts/build-research-view-bridge.mjs':await sha(fileURLToPath(import.meta.url))},asm:{version:'9.7.1',sha256:await sha(asm)},jdk:version.stdout.trim(),change:'Add one annotated ReadOnly research-view service to the pinned AnnotationScanner constructor; all other class bytes unchanged except ZIP container metadata',endpoint:'/insight/research-view/v1'},null,2)+'\n');
 console.log('Prepared research-view bridge',await sha(o.output));
}finally{await rm(temp,{recursive:true,force:true});}
