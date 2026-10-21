import {writePackageBuildManifest} from '@eyeauras/cli-factory-ipc/build';
import {prepareToolbox} from './prepare-toolbox.mjs';
import {chmod,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const native='runtime/native/';
const sha=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
const bridgeProof=JSON.parse(await readFile('runtime/research-view.provenance.json','utf8'));
assert.equal(await sha('runtime/GhidraMCP-7.0.0.jar'),bridgeProof.sha256,'Research-view bridge differs from its provenance');
for(const [path,expected]of Object.entries(bridgeProof.inputs))if(path.startsWith('skills/ghidra-coordinator/'))assert.equal(await sha(path.slice('skills/ghidra-coordinator/'.length)),expected,'Bridge native source changed; rebuild bridge and provenance: '+path);
for(const [name,binary]of [['deadline-exec','deadline-exec-darwin-arm64'],['deadline-alarm','deadline-alarm-darwin-universal.dylib']]){
 const proof=JSON.parse(await readFile(native+name+'.provenance.json','utf8'));
 assert.equal(await sha(native+name+'.c'),proof.sourceSha256,'Native deadline source changed; rebuild and review its provenance');
 assert.equal(await sha(native+binary),proof.sha256,'Native deadline binary differs from its provenance');
}
const job=JSON.parse(await readFile(native+'windows-job/provenance.json','utf8'));
for(const [name,expected]of Object.entries({...job.inputs,'Insight.WindowsJob.dll':job.sha256,'windows-job.ps1':job.launcherSha256}))assert.equal(await sha(native+'windows-job/'+name),expected,'Windows job source/binary differs from its provenance: '+name);
const dnspy=JSON.parse(await readFile(native+'dnspy-extension/provenance.json','utf8'));
for(const [file,expected]of Object.entries({...dnspy.inputs,'Insight.DnSpy.x.dll':dnspy.sha256}))assert.equal(await sha(native+'dnspy-extension/'+file),expected,'dnSpy bridge source/binary differs from its reviewed build: '+file);
const registry=JSON.parse(await readFile(native+'windows-registry.provenance.json','utf8'));
for(const [file,expected] of Object.entries({'windows-registry.c':registry.sourceSha256,'windows-registry.def':registry.definitionCanonicalSha256,'insight-registry-win-x64.dll':registry.sha256,'sources/detours-e4bfd6b.tar.gz':registry.detoursSha256}))assert.equal(await sha(native+file),expected,'Private registry source/binary differs from its reviewed build: '+file);
const linux=JSON.parse(await readFile(native+'child-deadline-linux.provenance.json','utf8'));
assert.equal(await sha(native+'child-deadline-linux.c'),linux.sourceSha256,'Linux launcher source differs from its reviewed build');
assert.equal(await sha(native+'child-deadline-linux-x64'),linux.sha256,'Linux launcher binary differs from its reviewed build');
for(const helper of ['insight-managed','insight-heap']){
 const root=new URL('../skills/ghidra-coordinator/runtime/managed/'+helper+'/',import.meta.url);
 const proof=JSON.parse(await readFile(new URL('provenance.json',root),'utf8'));
 for(const [name,expected]of Object.entries(proof.inputs))assert.equal(await sha(new URL(name,root)),expected,'Managed helper source differs: '+helper+'/'+name);
 for(const [name,expected]of Object.entries(proof.files))assert.equal(await sha(new URL(name,root)),expected.sha256,'Managed helper binary differs: '+helper+'/'+name);
}
const binaryRoot=new URL('../skills/ghidra-coordinator/runtime/native/binary/',import.meta.url);
const binary=JSON.parse(await readFile(new URL('provenance.json',binaryRoot),'utf8'));
for(const [name,expected]of Object.entries(binary.inputs))assert.equal(await sha(new URL(name,binaryRoot)),expected,'Binary helper source differs: '+name);
for(const [name,expected]of Object.entries(binary.files))assert.equal(await sha(new URL(name,binaryRoot)),expected.sha256,'Binary helper differs: '+name);
await chmod(new URL('insight-binary-darwin-arm64',binaryRoot),0o755);
// TypeScript's output mode otherwise depends on whether the file already existed.
await chmod('dist/src/bin.js',0o755);
await prepareToolbox(process.cwd());
await writePackageBuildManifest(process.cwd());
