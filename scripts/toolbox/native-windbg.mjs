// Real Windows public CLI proof, globally installed in an isolated prefix.
import assert from 'node:assert/strict';import {readFile,writeFile,mkdir,stat} from 'node:fs/promises';import {join,resolve} from 'node:path';import {createPublicFixture,digest} from './public-fixture.mjs';import {runNpm} from '../npm-command.mjs';
assert.equal(process.platform,'win32');const preparation=JSON.parse((await readFile(process.env.INSIGHT_WINDBG_FIXTURE,'utf8')).replace(/^\uFEFF/,'')),root=preparation.root,packed=join(root,'packed'),prefix=join(root,'global');await mkdir(packed);
const pack=JSON.parse((await runNpm(['pack','--ignore-scripts','--json','--workspace','@eyeauras/insight-cli','--pack-destination',packed],{cwd:resolve('.')})).stdout)[0],archive=join(packed,pack.filename);
await runNpm(['install','--global','--prefix',prefix,'--ignore-scripts','--no-audit','--no-fund',archive],{timeout:180000});
const packageRoot=join(prefix,'node_modules/@eyeauras/insight-cli'),f=await createPublicFixture(packageRoot,join(root,'public-cli'));let complete=false;
try{
 const original=digest(await readFile(preparation.dump)),pdb=digest(await readFile(preparation.symbols));assert.equal((await f.call(['windbg','status'])).state,'not_ready');await f.call(['windbg','install','--archive',preparation.bundle,'--offline']);await f.call(['windbg','doctor']);
 const output=join(f.project,'research/native.json');const first=await f.call(['windbg','inspect',preparation.dump,'--symbols',preparation.symbols,'--output',output]);const snapshot=JSON.parse(await readFile(output,'utf8'));assert.match(snapshot.lines.join('\n'),/quote_total/);assert.match(snapshot.lines.join('\n'),/rip=/);const target=first.target;
 const memory=await f.call(['windbg','inspect','--target',target,'--view','memory','--address',preparation.address,'--count','4','--symbols',preparation.symbols]);assert.match(memory.lines.join('\n'),/6d 00 00 00/i);
 const paged=await f.call(['windbg','inspect','--target',target,'--limit','2']);assert.equal(paged.lines.length,2);assert.equal(paged.truncated,true);
 const bad=await f.call(['windbg','inspect','--target',target,'--view','memory','--address','0x1','--count','16'],{allowFailure:true});assert.ok(bad.code!==0||bad.value?.complete===false,'Unreadable memory must not be complete');
 const checkpoint=await f.call(['artifacts','save',join(f.project,'research')]);await f.call(['permissions','grant','Destructive']);await f.call(['windbg','uninstall']);await stat(checkpoint.path);
 const external=digest(await readFile(preparation.cdb));await f.call(['windbg','install','--executable',preparation.cdb]);await f.call(['windbg','inspect','--target',target,'--view','modules']);
 // Mutate a retained runtime family file without modifying a mapped DLL.
 const sibling=join(preparation.root,'debugger/amd64/insight-owned-drift.txt');await writeFile(sibling,'owned mutation');assert.notEqual((await f.call(['windbg','doctor'],{allowFailure:true})).code,0);const {rm}=await import('node:fs/promises');await rm(sibling);
 assert.equal((await f.call(['windbg','uninstall'])).externalInstallationPreserved,true);assert.equal(digest(await readFile(preparation.cdb)),external);assert.equal(digest(await readFile(preparation.dump)),original);assert.equal(digest(await readFile(preparation.symbols)),pdb);
 const processes=(await f.call(['tools','processes','--tool','windbg','--all'])).items;assert.ok(processes.every(p=>['exited','failed'].includes(p.state)));
 await f.cleanup();complete=true;const build=JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8'));
 await writeFile('toolbox-windbg.json',JSON.stringify({schema:1,state:'passed',scope:'Globally installed public CLI native proof; independent cold/prepared model gates pending',platform:process.platform,architecture:process.arch,node:process.version,packageSha256:digest(await readFile(archive)),build,dumpSha256:original,symbolsSha256:pdb,checks:{offlineManagedInstall:true,doctor:true,quoteTotalStack:true,registers:true,observedTotal109:true,boundedPagination:true,unreadableMemoryUnknown:true,externalDriftRefused:true,externalPreserved:true,inputsPreserved:true,checkpointPreserved:true,terminalOwnedProcesses:true},cleanupComplete:true},null,2)+'\n');
 console.log('WinDbg native public CLI PASS');
}finally{if(!complete)await f.cleanup();}
