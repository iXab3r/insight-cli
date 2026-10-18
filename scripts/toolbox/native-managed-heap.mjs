// Installed public CLI only; this test owns the managed subject and its immutable dump.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,stat} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,worker,mismatchedDac]=process.argv.slice(2);
const f=await createPublicFixture(packageRoot,directory);let child,complete=false;
try{
 await f.call(['dotnet-dump','download']);const installed=await f.call(['dotnet-dump','install','--offline']);await f.call(['dotnet-dump','doctor']);
 const ipc=join(f.appdata,'di');await mkdir(ipc);let stdout='',stderr='';const runtime=dirname(installed.executable);
 child=spawn(installed.executable,[worker],{env:{PATH:process.env.PATH,DOTNET_ROOT:runtime,DOTNET_MULTILEVEL_LOOKUP:'0',TMPDIR:ipc},stdio:['ignore','pipe','pipe']});child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 for(let n=0;n<100&&!stdout.includes('READY');n++){assert.equal(child.exitCode,null,stderr);await delay(100);}assert.match(stdout,/READY/);
 const dump=join(f.project,'research/worker.dmp'),capture=await f.call(['dotnet-dump','collect','--pid',String(child.pid),'--diagnostic-directory',ipc,'--output',dump]),before=digest(await readFile(dump));
 const overview=await f.call(['dotnet-dump','query','--target',capture.target]);assert.equal(overview.observation.architecture,'Arm64');assert.equal(overview.observation.canWalkHeap,true);assert.equal(overview.dacSelection,'managed-10.0.13');
 const objects=await f.call(['dotnet-dump','query','--target',capture.target,'--view','objects','--type','BusinessState']);assert.equal(objects.complete,true);assert.equal(objects.observation.items.length,1);const address=objects.observation.items[0].address;
 const detail=await f.call(['dotnet-dump','query',dump,'--view','object','--address',address,'--type','BusinessState']);assert.equal(detail.observation.fields.find(f=>f.name==='Pending').value,37);assert.equal(detail.observation.fields.find(f=>f.name==='Job').value,'owned-report');
 const fields=await f.call(['dotnet-dump','query',dump,'--view','object','--address',address,'--limit','1']);assert.equal(fields.observation.fields.length,1);assert.equal(fields.observation.truncated,true);
 const prefix=await f.call(['dotnet-dump','query',dump,'--view','objects','--type','BusinessState','--max-objects','1']);assert.equal(prefix.complete,false);assert.equal(prefix.reason,'object_scan_bound');
 const stacks=await f.call(['dotnet-dump','query',dump,'--view','stacks']);const thread=stacks.observation.items.find(t=>t.frames.some(f=>f.method?.includes('WaitForRelease')));assert.ok(thread);assert.ok(thread.frames.some(f=>f.method?.includes('Thread.Sleep')));
 const output=join(f.project,'research/waiting-stack.json');await f.call(['dotnet-dump','query',dump,'--view','stacks','--thread',String(thread.osThreadId),'--output',output]);assert.equal(JSON.parse(await readFile(output,'utf8')).observation.items.length,1);
 for(const options of [['--view','object','--address','0x1'],['--view','object','--address',address,'--type','Wrong.Type'],['--runtime-index','15'],['--view','stacks','--output',output],['--dac-file',mismatchedDac]])assert.notEqual((await f.call(['dotnet-dump','query',dump,...options],{allowFailure:true})).code,0);
 assert.equal(child.exitCode,null,'Offline queries must not change the original subject lifetime');assert.equal(digest(await readFile(dump)),before);
 child.kill('SIGTERM');await new Promise(ok=>child.once('close',ok));child=undefined;
 const saved=await f.call(['artifacts','save',join(f.project,'research')]);await f.call(['permissions','grant','Destructive']);await f.call(['dotnet-dump','uninstall']);await stat(saved.path);await stat(dump);await stat(output);const jobs=(await f.call(['tools','processes','--tool','dotnet-dump','--all','--limit','1000'])).items;assert.ok(jobs.every(p=>['exited','failed'].includes(p.state)));
 await f.cleanup();complete=true;await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Globally installed public CLI native ClrMD proof; independent model gates pending',platform:process.platform,architecture:process.arch,node:process.version,workerSha256:digest(await readFile(worker)),dumpSha256:before,dacSha256:overview.dacSha256,checks:{privateRuntimeAndMatchingDac:true,actualOwnedHeapDump:true,knownObjectType:true,actualPrimitiveAndStringFields:true,boundedFields:true,scanBoundRemainsPartial:true,actualWaitingStack:true,focusedThread:true,invalidObjectAndExpectedTypeRefused:true,runtimeSelectionRefused:true,mismatchedDacRefused:true,outputOverwriteRefused:true,immutableDump:true,subjectLifetimePreserved:true,evidenceSurvivesUninstall:true,terminalOwnedProcesses:true},build:JSON.parse(await readFile(join(packageRoot,'.cli-package-build.json'),'utf8')),cleanupComplete:true},null,2)+'\n');console.log('Managed heap native public CLI PASS');
}finally{if(child&&child.exitCode===null){child.kill('SIGKILL');await new Promise(ok=>child.once('close',ok));}if(!complete)await f.cleanup();}
