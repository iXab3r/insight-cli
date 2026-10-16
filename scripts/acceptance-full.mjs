// One current-source acceptance gate. Each native child owns its fixtures and teardown.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,readdir,mkdtemp} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {p3Inputs} from './native-p3-inputs.mjs';
import {runNpm} from './npm-command.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2),exec=promisify(execFile);
assert.ok(args.includes('--ack-disposable'),'Explicit disposable-fixture acknowledgment required');
assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]),'Full GUI/keyring acceptance is local only');
const directory=await mkdtemp(join(tmpdir(),'insight-full-'));
console.log('Owned full acceptance diagnostics:',directory);
const runners=[
 'proof-merge','proof-contexts','proof-managed-server',
 'proof-research-cli','proof-facade-lifecycle','proof-lifecycle-selection','proof-scalar-projection',
 'proof-queries','proof-query-variants','proof-mutations','proof-functions','proof-data',
 'proof-cross','proof-transfer','proof-cross-faults',
 'proof-administration','proof-projects','proof-project-recovery','proof-ui','proof-ui-recovery',
 'proof-debugger','proof-debugger-recovery','proof-debugger-crash','proof-archive',
 'proof-native-snapshots','proof-api-gaps','proof-p2-sdk','proof-p2-recovery',
 'proof-p2-tracking','proof-p2-databases','proof-p2-trace','proof-p3','acceptance-facade'
];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function inputs(){
 const hashes=await p3Inputs();
 async function walk(path){for(const e of await readdir(join(root,path),{withFileTypes:true})){
  const name=join(path,e.name);if(e.isDirectory())await walk(name);else if(e.isFile())hashes[name]=sha(await readFile(join(root,name)));
 }}
 await walk('scripts');await walk('skills/ghidra-coordinator/tests');
 for(const path of ['scripts/test-package.mjs','skills/ghidra-coordinator/SKILL.md','skills/ghidra-coordinator/tsconfig.json'])hashes[path]=sha(await readFile(join(root,path)));
 return Object.fromEntries(Object.entries(hashes).sort(([a],[b])=>a.localeCompare(b)));
}
const offline=await runNpm(['test'],{cwd:root,timeout:300000,maxBuffer:8*1024*1024});
await writeFile(join(directory,'offline.log'),offline.stdout+'\n'+offline.stderr);
const tests=Number(offline.stdout.match(/^(?:#|ℹ) pass (\d+)\s*$/m)?.[1]);assert.ok(tests>0,'Offline test count missing');
const sourceHashes=await inputs(),baseRevision=(await exec('git',['rev-parse','HEAD'],{cwd:root})).stdout.trim();
console.log('Offline acceptance passed:',tests);
const packaged=await exec(process.execPath,[join(root,'scripts/test-package.mjs'),'--keep-installed'],{cwd:root,timeout:300000,maxBuffer:8*1024*1024});
await writeFile(join(directory,'package.log'),packaged.stdout+'\n'+packaged.stderr);
const install=packaged.stdout.match(/^Retained owned installed package: (.+)$/m)?.[1];assert.ok(install,'Missing retained installed artifact');
const tarball=join(install,'artifacts','eyeauras-insight-cli-0.1.0.tgz'),artifactSha256=sha(await readFile(tarball));
assert.deepEqual(await inputs(),sourceHashes,'Inputs changed during package acceptance');
const groups=[];
for(const name of runners){
 console.log('Full native acceptance started:',name);const started=Date.now();
 const extra=name==='acceptance-facade'?['--faults','--automatic-faults','--source-revision',baseRevision]:
  name==='proof-p3'?['--installed-package',join(install,'node_modules/@eyeauras/insight-cli'),'--installed-tarball',tarball]:[];
 let output;
 try{output=await exec(process.execPath,[join(root,'scripts',name+'.mjs'),...args,...extra],{cwd:root,timeout:1800000,maxBuffer:16*1024*1024});}
 catch(error){await writeFile(join(directory,name+'.log'),(error.stdout??'')+'\n'+(error.stderr??''));console.error('Full acceptance failed:',name,'; owned diagnostics:',directory);throw error;}
 await writeFile(join(directory,name+'.log'),output.stdout+'\n'+output.stderr);
 const json=output.stdout.trim().split(/\r?\n/).toReversed().find(line=>line.startsWith('{')&&line.endsWith('}'));assert.ok(json,'Missing receipt '+name);
 const receipt=JSON.parse(json);assert.notEqual(receipt.state,'failed');
 assert.deepEqual(await inputs(),sourceHashes,'Inputs changed during '+name);
 if(name==='acceptance-facade')assert.equal(receipt.artifactSha256,artifactSha256,'Installed owner used a different artifact');
 if(name==='proof-p3')assert.equal(receipt.packageSha256,artifactSha256);
 await writeFile(join(directory,name+'.json'),JSON.stringify(receipt,null,2));
 groups.push({runner:name,state:'passed',elapsedSeconds:Math.round((Date.now()-started)/10)/100,receiptSha256:sha(JSON.stringify(receipt)),receipt});
 await writeFile(join(directory,'progress.json'),JSON.stringify({groups:groups.map(({runner,state,elapsedSeconds})=>({runner,state,elapsedSeconds}))},null,2));
 console.log('Full native acceptance passed:',name);
}
assert.deepEqual(await inputs(),sourceHashes,'Inputs changed before final receipt');
const report={schema:1,state:'passed',completedAt:new Date().toISOString(),sourceBaseRevision:baseRevision,
 scope:'Combined current-source M0–M5 and selected P0–P3 acceptance; 33 native groups, installed CLI/IPC, two agents/two EXEs/four contexts, seven manual and two automatic real owner SIGKILL phases',
 sourceHashes,offlineTests:tests,artifact:{sha256:artifactSha256,isolatedInstall:true,relocation:true},
 runtime:{platform:process.platform,architecture:process.arch,node:process.versions.node,ghidra:'12.1.2',java:'21'},groups};
await writeFile(join(directory,'report.json'),JSON.stringify(report,null,2));
console.log('Full acceptance passed; report:',join(directory,'report.json'));
