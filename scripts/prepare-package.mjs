import {writePackageBuildManifest} from '@eyeauras/cli-factory-ipc/build';
import {prepareToolbox} from './prepare-toolbox.mjs';
import {chmod,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const native='runtime/native/';
const sha=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
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
// TypeScript's output mode otherwise depends on whether the file already existed.
await chmod('dist/src/bin.js',0o755);
await prepareToolbox(process.cwd());
await writePackageBuildManifest(process.cwd());
