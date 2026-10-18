// Maintainer-only fixture producer. Debug variables remain useful, author source is not
// reachable through LLDB's automatic source display during a blind agent investigation.
import assert from 'node:assert/strict';
import {mkdir,copyFile,readFile,writeFile,readdir} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
assert.equal(process.platform,'darwin');assert.equal(process.arch,'arm64');
const output=resolve(process.argv[2]),execute=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
await mkdir(output,{recursive:true,mode:0o700});assert.deepEqual(await readdir(output),[],'Use a fresh fixture directory');
const build=join(output,'build'),source=join(build,'fixture.c'),original=fileURLToPath(new URL('../../tests/acceptance/fixtures/toolbox/instrumented.c',import.meta.url)),unavailable='/__insight_fixture_source_unavailable__';
await mkdir(build);await copyFile(original,source);
const fastSource=join(build,'fast.c');await copyFile(fileURLToPath(new URL('../../tests/acceptance/fixtures/toolbox/debugger-fast.c',import.meta.url)),fastSource);
const recursiveSource=join(build,'recursive.c');await copyFile(fileURLToPath(new URL('../../tests/acceptance/fixtures/toolbox/debugger-recursive.c',import.meta.url)),recursiveSource);
const sourceFor=name=>name==='fast'?fastSource:name==='recursive'?recursiveSource:source;
const records=[];
for(const name of ['bare','cf','fast','recursive']){
 const executable=join(output,name),object=join(build,name+'.o'),args=['-g','-O0','-fdebug-prefix-map='+build+'='+unavailable,'-fdebug-compilation-dir='+unavailable,'-c',sourceFor(name),'-o',object,...(name==='cf'?['-DINSIGHT_WITH_CORE_FOUNDATION']:[])];
 await execute('/usr/bin/clang',args,{timeout:60000});
 await execute('/usr/bin/clang',[object,'-o',executable,...(name==='cf'?['-framework','CoreFoundation']:[])],{timeout:60000});
 await execute('/usr/bin/dsymutil',[executable],{timeout:60000});
 const symbols=executable+'.dSYM/Contents/Resources/DWARF/'+name,bytes=await readFile(symbols);
 assert.equal(bytes.includes(Buffer.from(build)),false,'DWARF must not resolve the author build directory');
 assert.equal(bytes.includes(Buffer.from(dirname(original))),false,'DWARF must not resolve the source checkout');
 assert.equal(bytes.includes(Buffer.from('return count < 11')),false,'Do not embed author source');
 const debug=await execute('/usr/bin/dwarfdump',['--debug-info',symbols],{timeout:10000,maxBuffer:1024**2});
 assert.ok(debug.stdout.includes(unavailable));assert.match(debug.stdout,/DW_AT_name\s*\("count"\)/);
 records.push({name,sourceSha256:sha(await readFile(sourceFor(name))),path:executable,sha256:sha(await readFile(executable)),symbols,symbolSha256:sha(bytes),sourceUnavailable:true,parameterDebugInfo:true});
}
await writeFile(join(output,'fixture.json'),JSON.stringify({schema:1,sourceSha256:sha(await readFile(source)),compiler:(await execute('/usr/bin/clang',['--version'])).stdout.split('\n')[0],files:records},null,2)+'\n');
console.log('Owned source-unavailable native fixtures prepared.');
