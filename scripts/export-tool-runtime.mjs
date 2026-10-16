// Publish only bounded acceptance facts; private profiles, raw logs and author paths stay local.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const [resultPath,packagePath,trxPath,destination,globalFilesPath]=process.argv.slice(2),r=JSON.parse(await readFile(resultPath,'utf8'));
assert.equal(r.state,'passed');assert.equal(r.developmentContinuation,undefined);assert.equal(r.ghidra.state,'passed');assert.deepEqual(r.installedBuild,JSON.parse(await readFile('skills/ghidra-coordinator/.cli-package-build.json','utf8')),'Installed gate and current prepared package differ');assert.ok(Object.values(r.checks).every(x=>x===true));
const trx=await readFile(trxPath,'utf8');assert.match(trx,/<Counters[^>]*passed="1"/);assert.match(trx,/failed="0"/);
const sha=b=>createHash('sha256').update(b).digest('hex');
const publicCalls=calls=>calls.map(({command,...rest})=>({...rest,command:command.replace(/\/[^\s]+/g,'<path>').replace(/([a-f0-9]{8}-[a-f0-9-]{27,})/g,'<id>')}));
const globalFiles=JSON.parse(await readFile(globalFilesPath,'utf8'));assert.equal(globalFiles.state,'passed');assert.equal(globalFiles.packageSha256,sha(await readFile(packagePath)));assert.deepEqual(globalFiles.build,r.installedBuild);
const result={globalPackageFilesVerified:globalFiles.files,schema:1,state:'passed',date:new Date().toISOString(),sourceCommit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),
 scope:r.scope,installedVersion:r.installedVersion,installedBuild:r.installedBuild,packageSha256:sha(await readFile(packagePath)),
 automation:{scenario:'Independent clients research real native and managed inputs with safe recovery',passed:1,failed:0,trxSha256:sha(trx)},
 platform:r.platform,architecture:r.architecture,node:r.node,inputSha256:r.inputSha256,
 ghidra:{version:'12.1.2',jdk:'21.0.11+10',build:r.ghidra.installedBuild,runtimeFingerprint:r.ghidra.runtimeFingerprint,checks:r.ghidra.checks,calls:publicCalls(r.ghidra.calls),seconds:r.ghidraGateSeconds},
 ilspy:{version:'11.1.0.9782',runtime:'10.0.13'},checks:r.checks,calls:publicCalls(r.calls),findings:r.findings,
 limits:['Native macOS ARM64 acceptance; native Windows/Linux deferred.','Process ownership is not an OS security sandbox; detached descendants need adapter-specific cleanup.','macOS recovered ownership uses authenticated tool identity; ambiguous processes are not signalled.','System LLDB/developer tools and debugger authorization remain host prerequisites.','npm registry publication is not part of this delivery.']};
const text=JSON.stringify(result,null,2)+'\n';assert.doesNotMatch(text,/\/Users\/|\/private\/tmp\/|ghp_|github_pat_|npm_[a-zA-Z0-9]{20}/);await writeFile(destination,text);console.log('Exported complete native/Gherkin tool runtime acceptance receipt.');
