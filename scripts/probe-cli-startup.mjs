// Read-only diagnostic control, not a replacement CLI. Reuse Factory's exact implementation.
// Run separately from latency measurements: eager imports are grouped; these are not IPC spans.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';
const [input,argvFile]=process.argv.slice(2),root=resolve(input),argv=JSON.parse(await readFile(argvFile,'utf8'));
const mainUptimeMs=process.uptime()*1000;
async function dependency(name){for(const base of createRequire(join(root,'package.json')).resolve.paths(name)??[]){try{const path=join(base,name),pkg=JSON.parse(await readFile(join(path,'package.json'),'utf8'));assert.equal(pkg.name,name);return {path,pkg};}catch(e){if(e.code!=='ENOENT')throw e;}}throw Error('Dependency not found: '+name);}
const core=await dependency('@eyeauras/cli-factory'),ipc=await dependency('@eyeauras/cli-factory-ipc');
const measure=async action=>{const start=performance.now();const value=await action();return {ms:performance.now()-start,value};};
const imports=await measure(()=>Promise.all([import(pathToFileURL(join(core.path,core.pkg.main))),import(pathToFileURL(join(ipc.path,ipc.pkg.main))),import(pathToFileURL(join(root,'dist/src/cli.js')))]));
const [factory,,facade]=imports.value;
const definition=await measure(()=>facade.createDefinition());
const application=await measure(()=>factory.createCli(definition.value));
try{
 const classify=await measure(()=>application.value.classify(argv));assert.equal(classify.value,'owner');
 // This is the exported Factory build API used by readBuildManifest for a packaged install.
 const {readPackageBuildManifest}=await import(pathToFileURL(join(ipc.path,'dist/src/package-build.js')));
 const validationTraceStartUs=Number(process.hrtime.bigint()/1000n);
 const validation=await measure(()=>readPackageBuildManifest(join(root,'dist/src/bin.js')));assert.match(validation.value,/^[a-f0-9]{64}$/);
 const validationTraceEndUs=Number(process.hrtime.bigint()/1000n);
 const dispose=await measure(()=>application.value.dispose());
 console.log(JSON.stringify({mainUptimeMs,importsMs:imports.ms,definitionMs:definition.ms,applicationMs:application.ms,classifyMs:classify.ms,packageValidationMs:validation.ms,validationTraceStartUs,validationTraceEndUs,disposeMs:dispose.ms,build:validation.value,completionUptimeMs:process.uptime()*1000}));
}finally{await application.value.dispose();}
