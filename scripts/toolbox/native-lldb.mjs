// Native public CLI acceptance; uses only an explicitly owned executable fixture.
import assert from 'node:assert/strict';import {readFile,writeFile,mkdir,stat} from 'node:fs/promises';import {join} from 'node:path';import {setTimeout as delay} from 'node:timers/promises';import {execFileSync} from 'node:child_process';import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,archive,fixture]=process.argv.slice(2);assert.ok(fixture,'Arguments: installed-package disposable-directory lldb-archive owned-Mach-O');
const f=await createPublicFixture(packageRoot,directory);let complete=false;
try{
 const original=digest(await readFile(fixture));assert.equal((await f.call(['lldb','status'])).state,'not_ready');await f.call(['lldb','install','--archive',archive,'--offline']);await f.call(['lldb','doctor']);
 const observations=[];let target;
 for(const [hit,count,total] of [[10,10,130],[11,11,109]]){
  const output=join(f.project,'research','runtime','hit-'+hit+'.json');const result=await f.call(['lldb','inspect',...(target?['--target',target]:[fixture]),'--breakpoint','quote_total','--hit',String(hit),'--step-out','--symbols',fixture+'.dSYM/Contents/Resources/DWARF/'+fixture.split('/').at(-1),'--memory-address','$sp','--memory-bytes','16','--output',output]);target=result.target;assert.equal(result.inferiorTerminated,true);
  const snapshot=JSON.parse(await readFile(output,'utf8')),text=snapshot.lines.join('\n');assert.match(text,new RegExp('\\(int\\) count = '+count+'\\b'));assert.match(text,new RegExp('Return value: \\(int\\) \\$1 = '+total+'\\b'));assert.match(text,/frame #1:.*main/);assert.match(text,/memory read/);assert.throws(()=>process.kill(result.inferiorPid,0),e=>e.code==='ESRCH');observations.push({count,total});
 }
 const bounded=await f.call(['lldb','inspect','--target',target,'--breakpoint','quote_total','--limit','2']);assert.equal(bounded.lines.length,2);assert.equal(bounded.truncated,true);
 assert.notEqual((await f.call(['lldb','inspect','--target',target,'--breakpoint','never_exists','--timeout-seconds','2'],{allowFailure:true})).code,0);
 assert.notEqual((await f.call(['lldb','inspect','--target',target,'--breakpoint','quote_total','--registers','unreal_register'],{allowFailure:true})).code,0);
 await f.call(['permissions','grant','Destructive']);
 for(const action of ['stop','kill']){
  const pending=f.call(['lldb','inspect','--target',target,'--breakpoint','never_exists','--timeout-seconds','30'],{allowFailure:true});let running;
  for(let n=0;n<20&&!running;n++){running=(await f.call(['tools','processes','--tool','lldb','--all'])).items.find(p=>p.state==='running'&&p.role==='inspect');if(!running)await delay(100);}
  assert.ok(running,'An owned inspect must become observable');const stopped=await f.call(['tools','processes',action,running.id]);assert.equal(stopped.state,action==='kill'?'killed':'stopped');assert.notEqual((await pending).code,0);
 }
 const checkpoint=await f.call(['artifacts','save',join(f.project,'research')]);await f.call(['permissions','grant','Destructive']);await f.call(['lldb','uninstall']);await stat(checkpoint.path);
 const external=join(directory,'external');await mkdir(external);execFileSync('tar',['-xzf',archive,'--strip-components=1','-C',external]);const executable=join(external,'bin/lldb'),code=digest(await readFile(executable));await f.call(['lldb','install','--executable',executable]);await f.call(['lldb','inspect','--target',target,'--breakpoint','quote_total']);
 const dependency=join(external,'bin/debugserver'),bytes=await readFile(dependency);await writeFile(dependency,Buffer.concat([bytes,Buffer.from('owned mutation')]));assert.notEqual((await f.call(['lldb','doctor'],{allowFailure:true})).code,0);await writeFile(dependency,bytes);assert.equal((await f.call(['lldb','uninstall'])).externalInstallationPreserved,true);assert.equal(digest(await readFile(executable)),code);assert.equal(digest(await readFile(fixture)),original);
 const processes=(await f.call(['tools','processes','--tool','lldb','--all'])).items;assert.ok(processes.every(p=>['exited','failed'].includes(p.state)));assert.ok(processes.some(p=>p.outcome==='timeout'));await f.cleanup();complete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Installed public CLI native proof; independent cold/prepared model gate pending',version:f.version,fixtureSha256:original,observations,checks:{offlineManagedInstall:true,doctor:true,immutableTargetReused:true,argumentsAndReturns:true,registerMemoryBacktrace:true,inferiorsAbsent:true,boundedPagination:true,missingBreakpointTimesOut:true,nativeCommandErrorFails:true,externalDependencyDriftRefused:true,externalPreserved:true,inputUnchanged:true,checkpointSurvivesRemoval:true,terminalOwnedProcesses:true,publicStopAndKill:true},cleanupComplete:true},null,2)+'\n');console.log('LLDB native public CLI PASS:',directory);
}finally{if(!complete)await f.cleanup();}
