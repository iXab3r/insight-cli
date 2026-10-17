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
// TypeScript's output mode otherwise depends on whether the file already existed.
await chmod('dist/src/bin.js',0o755);
await prepareToolbox(process.cwd());
await writePackageBuildManifest(process.cwd());
