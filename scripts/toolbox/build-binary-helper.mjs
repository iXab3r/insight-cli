// Maintainer-only build. Consumers receive the prebuilt helper, never a compiler or SDK.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,mkdir,copyFile,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const [sdkArchive,sourceArchive,output]=process.argv.slice(2);assert.ok(output);
const source=resolve('skills/ghidra-coordinator/runtime/native/binary'),sha=b=>createHash('sha256').update(b).digest('hex');
const dependencies=JSON.parse(await readFile(join(source,'dependencies.json'),'utf8'));
assert.equal(sha(await readFile(sdkArchive)),dependencies.library.sdk.sha256);assert.equal(sha(await readFile(sourceArchive)),dependencies.library.source.sha256);
const compiler=execFileSync('/usr/bin/clang++',['--version'],{encoding:'utf8'}).split('\n')[0];assert.equal(compiler,'Apple clang version 17.0.0 (clang-1700.3.19.1)');
const inputs={};for(const name of ['helper.cpp','dependencies.json',...dependencies.notices.map(n=>n.path)])inputs[name]=sha(await readFile(join(source,name)));
const results=[];
for(let n=0;n<2;n++){const root=await mkdtemp('/tmp/insight-binary-build-');try{
 await copyFile(join(source,'helper.cpp'),join(root,'helper.cpp'));
 execFileSync('python3',['-c',`import tarfile,zipfile,io,pathlib,sys
root=pathlib.Path(sys.argv[3])
with tarfile.open(sys.argv[1]) as t:t.extractall(root/'sdk',filter='data')
with tarfile.open(sys.argv[2]) as t:
 data=t.extractfile('LIEF-1.0.0/third-party/json-3.12.0.zip').read()
 with zipfile.ZipFile(io.BytesIO(data)) as z:(root/'json.hpp').write_bytes(z.read('json-3.12.0/json.hpp'))`,sdkArchive,sourceArchive,root],{stdio:'pipe'});
 const sdk=join(root,'sdk/LIEF-1.0.0-Darwin-arm64'),binary=join(root,'insight-binary-darwin-arm64');
 execFileSync('/usr/bin/clang++',['-std=c++17','-O2','-DNDEBUG','-mmacosx-version-min=14.0','-ffile-prefix-map='+root+'=/_/insight-binary','-I'+join(sdk,'include'),'-I'+root,join(root,'helper.cpp'),join(sdk,'lib/libLIEF.a'),'-Wl,-dead_strip','-Wl,-reproducible','-o',binary],{stdio:'pipe'});
 const linked=execFileSync('/usr/bin/otool',['-L',binary],{encoding:'utf8'}).split('\n').slice(1).filter(Boolean).map(l=>l.trim().split(' ')[0]);assert.deepEqual(linked,['/usr/lib/libc++.1.dylib','/usr/lib/libSystem.B.dylib']);
 const config=execFileSync('/usr/bin/otool',['-l',binary],{encoding:'utf8'});assert.match(config,/minos 14\.0/);results.push(await readFile(binary));
}finally{await rm(root,{recursive:true,force:true});}}
assert.equal(sha(results[0]),sha(results[1]),'Independent native helper builds differ');await mkdir(output,{recursive:true});const name='insight-binary-darwin-arm64';await writeFile(join(output,name),results[0],{mode:0o755});
await writeFile(join(output,'provenance.json'),JSON.stringify({schema:1,compiler,platform:'darwin-arm64',minimumSystem:'macOS14+',sdkVersion:'26.0',inputs,files:{[name]:{size:results[0].length,sha256:sha(results[0])}},sourceLicense:'MIT',dependencies:'dependencies.json',reproducible:true,staticLibrary:dependencies.library.sdk,linkedSystemLibraries:['/usr/lib/libc++.1.dylib','/usr/lib/libSystem.B.dylib']},null,2)+'\n');
