import {runNpm} from './npm-command.mjs';
// Locked offline pack/install proof. npm ci setup populates the ordinary artifact cache.
import assert from 'node:assert/strict';import{execFile}from'node:child_process';import{promisify}from'node:util';import{mkdtemp,mkdir,readFile,writeFile,rm,realpath}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{createHash}from'node:crypto';import{fileURLToPath,pathToFileURL}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),exec=promisify(execFile);
const keep=process.argv.includes('--keep-installed');
const proof=await realpath(await mkdtemp(join(process.platform==='win32'?tmpdir():'/tmp','ip-'))),install=join(proof,'installed spaces-Ω');await mkdir(install);
const provenance=JSON.parse(await readFile(join(root,'vendor/provenance.json'),'utf8'));
const coreProvenance=JSON.parse(await readFile(join(root,'vendor/factory-core-c773126.json'),'utf8'));
for(const record of [provenance,coreProvenance])assert.equal(createHash('sha256').update(await readFile(join(root,'vendor',record.file))).digest('hex'),record.sha256);
try{
 const artifacts=join(install,'artifacts');await mkdir(artifacts);
 const pack=JSON.parse((await runNpm(['pack','--ignore-scripts','--json','--workspace','@eyeauras/insight-cli','--pack-destination',artifacts],{cwd:root})).stdout)[0];
 if(process.platform!=='win32')assert.equal(pack.files.find(file=>file.path==='dist/src/bin.js')?.mode&0o777,0o755,'Packed CLI entrypoint must be executable on a clean POSIX build');
 const files=new Set(pack.files.map(f=>f.path));for(const path of ['dist/src/ilspy.js','dist/src/ghidra-processes.js','dist/src/tool-runtime/launch-worker.js','dist/src/tool-runtime/supervisor.js','dist/src/tool-runtime/installer.js','runtime/tool-catalog.json','references/ilspy.md','references/native/InsightInitialJournal.java','references/native/InsightInitialImport.java','references/native/InsightInitialPublication.java','dist/src/initial-model.js','references/extensions-and-sync.md','references/native/InsightExtensions.java','references/native/InsightPlugins.java','dist/src/extensions.js','dist/src/sync-policy.js','references/native-workflows.md','references/native/InsightSdkTools.java','references/native/InsightSdkTypes.java','references/native/InsightSdkScript.java','references/native/InsightSdkFiles.java','references/native/InsightFunctionDatabases.java','references/native/InsightVersionTracking.java','references/native/InsightTraceTools.java','references/native/InsightNativeReceipt.java','dist/src/sdk.js','dist/src/sdk-files.js','dist/src/sdk-contracts.js','dist/src/version-tracking.js','references/native/InsightResearchQueries.java','references/native/InsightEmulation.java','dist/src/query-policy.js','dist/src/native-queries.js','dist/src/memory-inputs.js','README.md','SKILL.md','references/debugger.md','references/archive.md','dist/src/debugger.js','dist/src/debugger-supervisor.js','dist/src/debugger-results.js','dist/src/archive.js','dist/src/archive-contract.js','references/native/InsightTraceState.java','references/native/InsightTraceInspect.java','references/native/InsightStartDebugger.java','references/native/InsightStopDebugger.java','references/native/InsightPythonWheels.java','references/native/InsightArchivePayloads.java','references/setup.md','references/research.md','references/recovery.md','references/queries.json','references/mutations.json','runtime/GhidraMCP-7.0.0.jar','runtime/GhidraMCP-LICENSE','runtime/GhidraMCP-NOTICE','runtime/provenance.json','references/InsightRepositoryProbe.java','references/native/InsightGuiMain.java','references/native/InsightHeadlessMain.java','references/native/InsightServerMain.java','references/native/InsightSnapshotPublisher.java','references/native/InsightSnapshotFields.java','references/native/InsightPublicationRecovery.java','references/native/InsightBlockTransfer.java','LICENSE','dist/src/bin.js','dist/src/queries.js','dist/src/mutations.js','dist/src/scripts.js','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java','dist/src/data-effects.js','dist/src/documentation-effects.js','dist/src/mutation-inputs.js','dist/src/cross.js','dist/src/cross-results.js','.cli-package-build.json'])assert.ok(files.has(path),path);
 for(const path of ['references/performance.md','references/native/InsightResearchView.java'])assert.ok(files.has(path),path);
 assert.ok([...files].every(f=>!f.includes('/tests/')&&(!f.endsWith('.ts')||f.endsWith('.d.ts'))));
 for(const path of ['dist/src/runtime-manager.js','dist/src/runtime-selection.js','dist/src/runtime-catalog.js','dist/src/tool-runtime/archives.js','references/managed-runtime.md','references/native/InsightRuntimeDoctor.java','skills/insight-re/SKILL.md','references/artifacts.md','dist/src/saved-materials.js'])assert.ok(files.has(path),path);
 const toolbox=JSON.parse(await readFile(join(root,'skills/ghidra-coordinator/runtime/toolbox.json'),'utf8'));
 assert.ok(files.has('skill-bundle/manifest.json'));
 for(const skill of toolbox.skills){assert.ok(files.has('skill-bundle/'+skill.name+'/SKILL.md'));assert.ok(files.has(skill.path),skill.path);for(const destination of Object.keys(skill.resources))assert.ok(files.has(join(skill.path,'..',destination).replaceAll('\\','/')),destination);}
 const sourcePackage=JSON.parse(await readFile(join(root,'package.json'),'utf8'));const lock=JSON.parse(await readFile(join(root,'package-lock.json'),'utf8'));
 const packageFile='file:artifacts/'+pack.filename;
 const manifest={name:'isolated-insight-proof',version:'1.0.0',private:true,type:'module',dependencies:{'@eyeauras/insight-cli':packageFile},devDependencies:sourcePackage.devDependencies};
 lock.name=manifest.name;lock.version=manifest.version;lock.packages['']=manifest;
 for(const [name,item]of Object.entries(lock.packages)){if(item.link||name.startsWith('skills/'))delete lock.packages[name];}
 const cli=JSON.parse(await readFile(join(root,'skills/ghidra-coordinator/package.json'),'utf8'));
 for(const record of [provenance,coreProvenance])assert.equal(cli.dependencies[record.package],record.url,'Runtime dependency must match the recorded immutable artifact');
 lock.packages['node_modules/@eyeauras/insight-cli']={version:cli.version,resolved:packageFile,integrity:'sha512-'+createHash('sha512').update(await readFile(join(artifacts,pack.filename))).digest('base64'),dependencies:cli.dependencies,engines:cli.engines,bin:cli.bin,license:cli.license};
 await writeFile(join(install,'package.json'),JSON.stringify(manifest));await writeFile(join(install,'package-lock.json'),JSON.stringify(lock));
 await runNpm(['ci','--offline','--ignore-scripts','--no-audit','--no-fund'],{cwd:install,timeout:60000,maxBuffer:262144});
 const isolatedEnvironment=join(install,'isolated-environment.mjs');
 await writeFile(isolatedEnvironment,`import{AppArguments}from'@eyeauras/cli-factory';import{join}from'node:path';import{fileURLToPath,pathToFileURL}from'node:url';const original=AppArguments.CurrentEnvironment;const root=fileURLToPath(new URL('./owned appdata/',import.meta.url));AppArguments.CurrentEnvironment=()=>({...original(),EnvironmentAppData:root,EnvironmentLocalAppData:root});`);
 const hostedHelp=await exec(process.execPath,['--import',pathToFileURL(isolatedEnvironment).href,join(install,'node_modules/@eyeauras/insight-cli/dist/src/bin.js'),'--help'],{cwd:install,timeout:30000,maxBuffer:262144});
 assert.match(hostedHelp.stdout,/insight-cli/);
 await exec(process.execPath,['--import',pathToFileURL(isolatedEnvironment).href,join(install,'node_modules/@eyeauras/insight-cli/dist/src/bin.js'),'ipc-server','stop'],{cwd:install,timeout:30000,maxBuffer:262144});
 const fixture=join(install,'proof.mjs');await writeFile(fixture,`import test from'node:test';import assert from'node:assert/strict';import{createCliFixture}from'@eyeauras/cli-factory/testing';import{createInsightCli}from'@eyeauras/insight-cli';import{readFile}from'node:fs/promises';import{createHash}from'node:crypto';import{packagedMcpJar,pinnedMcpJar}from'./node_modules/@eyeauras/insight-cli/dist/src/native-inputs.js';test('installed skill and commands without source checkout',async t=>{assert.ok(packagedMcpJar.includes('node_modules'));assert.equal(createHash('sha256').update(await readFile(packagedMcpJar)).digest('hex'),pinnedMcpJar);const f=await createCliFixture(t,{applicationId:'insight-cli'});const app=f.createApplication(runtime=>createInsightCli({runtime}));const skill=await f.json(app,['skill']);assert.ok(skill.path.includes('node_modules'));assert.ok((await readFile(skill.path,'utf8')).includes('insight-cli '+${JSON.stringify(cli.version)}));const replies=await f.rpc(app,[['targets','list'],['sessions','list']]);assert.equal(replies.length,2);assert.equal(replies[0].result.items.length,0);assert.equal(replies[1].result.items.length,0);const extensions=await f.json(app,['ghidra','extensions','list']);assert.equal(extensions.items.length,0);const policyHelp=await f.run(app,['ghidra','sync-policy','set','--help']);assert.equal(policyHelp.exitCode,0);assert.match(policyHelp.stdout,/after-edit/);const denied=await f.run(app,['ghidra','open','missing.exe','--session','new','--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);const missing=await f.run(app,['ghidra','functions','get','--session','s_missing','--address','140001000','--json']);assert.notEqual(missing.exitCode,0);assert.match(missing.stderr,/target/);});`);
 await exec(process.execPath,['--test',fixture],{cwd:install,timeout:30000,maxBuffer:262144});
 const researchProof=join(install,'research-proof.mjs');
 await writeFile(researchProof,`import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '@eyeauras/insight-cli';
import {mkdir,writeFile,readFile,stat} from 'node:fs/promises';
import {join} from 'node:path';
test('relocated RE skill and ordinary materials without native runtime',async t=>{
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});
 const app=f.createApplication(runtime=>createInsightCli({runtime,backend:()=>{throw Error('Native runtime must not start');}}));
 const skill=await f.json(app,['skill','insight-re']);assert.equal(skill.name,'insight-re');assert.ok(skill.path.includes('node_modules'));
 const body=await readFile(skill.path,'utf8');assert.ok(body.includes('Insight RE '+${JSON.stringify(cli.version)}));
 for(const link of body.matchAll(/\\]\\(([^)]+)\\)/g))await stat(join(skill.path,'..',link[1]));
 const source=join(f.root,'research spaces-Ω');await mkdir(source);await writeFile(join(source,'notes.md'),'Evidence retained');await writeFile(join(source,'empty.txt'),'');
 const receipt=await f.json(app,['artifacts','save',source]);assert.equal(receipt.state,'saved');assert.equal(receipt.files,2);
 await writeFile(join(source,'notes.md'),'Later edits');assert.equal(await readFile(join(receipt.path,'notes.md'),'utf8'),'Evidence retained');
 const replies=await f.rpc(app,[['artifacts','save',join(source,'empty.txt')]]);assert.equal(replies[0].result.bytes,0);
 assert.equal(await readFile(replies[0].result.path,'utf8'),'');
});`);
 await exec(process.execPath,['--test',researchProof],{cwd:install,timeout:30000,maxBuffer:262144});
 console.log('Packed isolated install: skill/resources, profile/JSON/RPC, permission denial and spaces/Unicode PASS');
}finally{if(keep)console.log('Retained owned installed package:',install);else await rm(proof,{recursive:true,force:true});}
