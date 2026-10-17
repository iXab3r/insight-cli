import assert from 'node:assert/strict';import {readFile,writeFile,copyFile,stat} from 'node:fs/promises';import {join} from 'node:path';
import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,archive,subject]=process.argv.slice(2);assert.ok(subject,'Arguments: installed-package disposable-directory pinned-runtime.tgz research-container.zip');
const f=await createPublicFixture(packageRoot,directory);let cleanupComplete=false;
try{
 const input=join(f.project,'subject.zip');await copyFile(subject,input);const original=digest(await readFile(input));
 assert.equal((await f.call(['sevenzip','status'])).state,'not_ready');
 const installed=await f.call(['sevenzip','install','--archive',archive,'--offline']);assert.equal(installed.state,'installed');
 assert.equal((await f.call(['sevenzip','doctor'])).state,'verified');
 const inventory=await f.call(['sevenzip','list',input]);assert.ok(inventory.items.some(e=>e.path==='lib/ResearchFixture.dll'));
 const verified=await f.call(['sevenzip','test','--target',inventory.target]);assert.equal(verified.state,'verified');
 const output=join(f.project,'recovered');const recovered=await f.call(['sevenzip','extract','--target',inventory.target,'--output',output]);assert.equal(recovered.state,'extracted');
 assert.equal(digest(await readFile(join(output,'lib/ResearchFixture.dll'))),'5d26a212fc91bc0bbec4c95eda9dc98b18fc3cbbf84e09bd137c14db784e41fb');
 assert.equal(JSON.parse(await readFile(join(output,'configuration/settings.json'),'utf8')).retries,4);
 const checkpoint=await f.call(['artifacts','save',output]);assert.equal(checkpoint.state,'saved');assert.equal(checkpoint.files,2);
 assert.notEqual((await f.call(['sevenzip','extract','--target',inventory.target,'--output',output],{allowFailure:true})).code,0);
 assert.equal(digest(await readFile(input)),original);
 const processes=await f.call(['tools','processes','--tool','sevenzip','--all']);assert.ok(processes.items.every(p=>['exited','failed'].includes(p.state)));
 await f.call(['permissions','grant','Destructive']);assert.equal((await f.call(['sevenzip','uninstall'])).researchPreserved,true);assert.equal((await f.call(['sevenzip','status'])).state,'not_ready');
 await stat(checkpoint.path);
 await f.cleanup();cleanupComplete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Native public CLI developer proof; independent cold/prepared agent gate remains separate',version:f.version,sourceContainerSha256:original,recoveredFiles:recovered.files.length,checkpointFiles:checkpoint.files,checks:{exactBinaryBytes:true,configurationRead:true,containerUnchanged:true,refusesOverwrite:true,terminalOwnedProcesses:true,researchSurvivesUninstall:true},cleanupComplete},null,2)+'\n',{mode:0o600});console.log('7-Zip public CLI native proof PASS:',directory);
}finally{if(!cleanupComplete)await f.cleanup();}
