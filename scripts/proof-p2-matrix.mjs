// Sequential native regression gate: each child owns its input, server, projects and teardown.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,readdir,mkdtemp} from 'node:fs/promises';
import {join,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2),exec=promisify(execFile);
assert.ok(args.includes('--ack-disposable'));
assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
const directory=await mkdtemp(join(tmpdir(),'insight-p2-matrix-'));
const runners=['proof-p2-sdk','proof-p2-tracking','proof-p2-databases','proof-p2-trace','proof-api-gaps','proof-mutations','proof-debugger','acceptance-facade'];
async function inputs(){
 // Bind actual executable inputs. Markdown/package-only harness changes cannot change a
 // native operation; final package identity and offline tests have their own receipts.
 const files=['package.json','package-lock.json','vendor/provenance.json','vendor/factory-ipc-a2094fb.tgz',
  '.github/workflows/native-p2.yml','scripts/proof-p2-matrix.mjs','scripts/native-proof-guard.mjs','scripts/npm-command.mjs','scripts/fixtures/facade-owner.mjs',...runners.map(name=>'scripts/'+name+'.mjs')];
 async function walk(path,accept){for(const entry of await readdir(join(root,path),{withFileTypes:true})){const name=join(path,entry.name);if(entry.isDirectory())await walk(name,accept);else if(entry.isFile()&&accept(name))files.push(name);}}
 await walk('skills/ghidra-coordinator/src',name=>name.endsWith('.ts'));
 await walk('skills/ghidra-coordinator/dist/src',name=>name.endsWith('.js'));
 await walk('skills/ghidra-coordinator/references',name=>/\.(java|json)$/.test(name));
 files.push('skills/ghidra-coordinator/package.json','skills/ghidra-coordinator/tsconfig.json','skills/ghidra-coordinator/runtime/GhidraMCP-7.0.0.jar');
 return Object.fromEntries(await Promise.all(files.sort().map(async path=>[path,createHash('sha256').update(await readFile(join(root,path))).digest('hex')])));
}
const sourceHashes=await inputs(),groups=[];
for(const name of runners){
 console.log('Native matrix started:',name);let result;
 try{result=await exec(process.execPath,[join(root,'scripts',name+'.mjs'),...args],{cwd:root,timeout:1800000,maxBuffer:8*1024*1024});}
 catch(error){await writeFile(join(directory,name+'.log'),(error.stdout??'')+'\n'+(error.stderr??''));console.error('Native matrix failed:',name);console.error('Owned diagnostics:',directory);throw error;}
 await writeFile(join(directory,name+'.log'),result.stdout+'\n'+result.stderr);
 const lines=result.stdout.trim().split('\n'),json=lines.toReversed().find(line=>line.startsWith('{')&&line.endsWith('}'));assert.ok(json,'Missing receipt '+name);
 const receipt=JSON.parse(json);assert.deepEqual(await inputs(),sourceHashes,'Inputs changed during native matrix');
 await writeFile(join(directory,name+'.json'),JSON.stringify(receipt,null,2));groups.push({runner:name,state:'passed',receiptSha256:createHash('sha256').update(JSON.stringify(receipt)).digest('hex'),receipt});
 console.log('Native matrix passed:',name);await writeFile(join(directory,'progress.json'),JSON.stringify({groups:groups.map(g=>({runner:g.runner,state:g.state}))},null,2));
}
const report={schema:1,state:'passed',scope:'Selected P2 N01–N09, G07 convenience, larger database and affected native/installed regressions',sourceIdentity:'Native runtime source/compiled JS/resources, executed proof scripts and pinned package inputs; prose and offline-only harnesses are verified separately.',sourceHashes,groups};
await writeFile(join(directory,'sanitized-report.json'),JSON.stringify(report,null,2));console.log('All eight P2 native groups passed; sanitized report:',join(directory,'sanitized-report.json'));
