// Public installed CLI: offline dependency delivery, real probes, drift and removal.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,archive,worker,ghidra,java]=process.argv.slice(2),f=await createPublicFixture(packageRoot,directory),inputSha256=digest(await readFile(worker));
let scope,restored,complete=false;
try{
 await f.call(['permissions','grant','Destructive']);
 const installed=await f.call(['ghidra','install','--executable',ghidra,'--java',java,'--debugger-archive',archive,'--offline']);assert.equal(installed.debugger.backend,'managed-lldb');
 const status=await f.call(['ghidra','status']),runtime=status.capabilities.debugger.runtime;assert.equal(runtime.mode,'managed');assert.equal(runtime.state,'installed');assert.equal(runtime.lastProbe.hostHomebrewRequired,false);
 const checked=await f.call(['ghidra','doctor']);assert.equal(checked.debugger.backend,'managed-lldb');assert.equal(checked.debugger.state,'verified');
 const marker=join(dirname(dirname(runtime.executable)),'RUNTIME-MANIFEST.json'),bytes=await readFile(marker);restored={marker,bytes};
 await writeFile(marker,Buffer.concat([bytes,Buffer.from(' ')]));assert.notEqual((await f.call(['ghidra','doctor'],{allowFailure:true})).code,0,'Modified debugger inputs must not pass doctor');await writeFile(marker,bytes);restored=undefined;
 scope=await f.call(['ghidra','open',worker,'--session','new']);const selected=['--session',scope.session,'--target',scope.target];
 assert.notEqual((await f.call(['ghidra','uninstall'],{allowFailure:true})).code,0,'Live Ghidra context must reserve its dependency');assert.equal((await f.call(['ghidra','status'])).capabilities.debugger.runtime.state,'installed');
 const report=join(f.project,'runtime-evidence.json');await writeFile(report,JSON.stringify({inputSha256,backend:checked.debugger.backend,installation:installed.debugger.installation,checks:checked.debugger.checks},null,2)+'\n');const saved=await f.call(['artifacts','save',report]);
 await f.call(['ghidra','close',...selected]);scope=undefined;await f.call(['ghidra','server','stop']);await f.call(['ghidra','uninstall']);assert.equal((await f.call(['ghidra','status'])).capabilities.debugger.runtime.state,'not_ready');await assert.rejects(stat(runtime.executable),e=>e.code==='ENOENT');
 assert.equal(await readFile(saved.path,'utf8'),await readFile(report,'utf8'));assert.equal(digest(await readFile(worker)),inputSha256);await stat(ghidra);await stat(java);assert.equal((await f.call(['ghidra','status'])).processes.length,0);await f.cleanup();complete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Installed public Ghidra CLI managed LLDB/Python runtime lifecycle; independent model acceptance is separate',inputSha256,checks:{offlineArchiveInstalled:true,actualPrivatePythonProbed:true,changedRuntimeRejected:true,activeContextBlocksRemoval:true,ownedDependencyRemoved:true,externalGhidraAndJavaPreserved:true,savedEvidenceRetained:true,originalInputUnchanged:true,ownedProcessesStopped:true},build:JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8')),cleanupComplete:true},null,2)+'\n');console.log('Ghidra managed debugger runtime native public CLI PASS');
}finally{
 if(restored)await writeFile(restored.marker,restored.bytes);
 if(!complete){if(scope)try{await f.call(['ghidra','close','--session',scope.session,'--target',scope.target]);}catch{}try{await f.call(['ghidra','server','stop']);}catch{}await f.cleanup();}
}
