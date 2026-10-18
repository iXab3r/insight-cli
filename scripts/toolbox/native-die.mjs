import assert from 'node:assert/strict';import {readFile,writeFile,copyFile,mkdir,stat} from 'node:fs/promises';import {join} from 'node:path';import {execFileSync} from 'node:child_process';
import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,archive,nativeSubjects,managedSubject]=process.argv.slice(2);assert.ok(managedSubject,'Arguments: installed-package disposable-directory reviewed-console.tgz native-subjects managed-subject.dll');
const f=await createPublicFixture(packageRoot,directory);let complete=false;
try{
 assert.equal((await f.call(['die','status'])).state,'not_ready');
 const installed=await f.call(['die','install','--archive',archive,'--offline']);assert.equal(installed.mode,'managed');assert.equal((await f.call(['die','doctor'])).state,'verified');
 const inputs=[];for(const name of ['program.exe','program.elf','program.macho']){const path=join(f.project,name);await copyFile(join(nativeSubjects,name),path);inputs.push({path,sha256:digest(await readFile(path))});}
 const managed=join(f.project,'worker.dll');await copyFile(managedSubject,managed);inputs.push({path:managed,sha256:digest(await readFile(managed))});
 const pe=await f.call(['die','classify',inputs[0].path]);assert.equal(pe.information['File type'],'PE64');assert.equal(pe.information.Architecture,'AMD64');
 // This is a real upstream database failure, not an injected fixture. Keep useful data and uncertainty.
 assert.equal(pe.state,'partial');assert.equal(pe.complete,false);assert.ok(pe.diagnostics.some(d=>d.message.includes('TypeError')));
 const elf=await f.call(['die','classify',inputs[1].path]);assert.equal(elf.information['File type'],'ELF64');assert.equal(elf.complete,true);assert.ok(elf.findings.some(d=>d.type==='Unknown'));
 const macho=await f.call(['die','classify',inputs[2].path]);assert.equal(macho.information['File type'],'Mach-O64');assert.equal(macho.information.Architecture,'ARM64');
 const output=join(f.project,'research','triage','managed.json'),net=await f.call(['die','classify',managed,'--output',output]);assert.equal(net.state,'partial');const saved=JSON.parse(await readFile(output,'utf8'));assert.ok(saved.findings.some(f=>f.name==='.NET Core'));assert.ok(saved.diagnostics.length);
 const page=await f.call(['die','classify','--target',net.target,'--limit','1']);assert.equal(page.findings.length,1);assert.ok(page.totalFindings>1);assert.equal(page.truncated,true);
 assert.notEqual((await f.call(['die','classify',managed,'--output',output],{allowFailure:true})).code,0);
 const checkpoint=await f.call(['artifacts','save',join(f.project,'research')]);await f.call(['permissions','grant','Destructive']);await f.call(['die','uninstall']);await stat(checkpoint.path);
 const external=join(directory,'external');await mkdir(external);execFileSync('tar',['-xzf',archive,'--strip-components=1','-C',external]);
 assert.ok((await readFile(join(external,'NOTICE.txt'),'utf8')).includes('LGPL-3.0'));
 const executable=join(external,'MacOS/diec'),binaryHash=digest(await readFile(executable));await f.call(['die','install','--executable',executable]);await f.call(['die','classify',managed]);
 const database=join(external,'Resources/db/_init'),original=await readFile(database);await writeFile(database,Buffer.concat([original,Buffer.from('\n// owned mutation\n')]));
 assert.notEqual((await f.call(['die','classify',managed],{allowFailure:true})).code,0);await writeFile(database,original);await f.call(['die','classify',managed]);
 assert.equal((await f.call(['die','uninstall'])).externalInstallationPreserved,true);assert.equal(digest(await readFile(executable)),binaryHash);
 for(const input of inputs)assert.equal(digest(await readFile(input.path)),input.sha256);
 assert.ok((await f.call(['tools','processes','--tool','die','--all'])).items.every(p=>['exited','failed'].includes(p.state)));
 await f.cleanup();complete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Native public CLI triage proof; independent cold/prepared agent gate pending',version:f.version,inputs:inputs.map(({path,sha256})=>({name:path.split('/').at(-1),sha256})),checks:{privateQtClosure:true,peElfMachoHeaders:true,managedRuntimeSignature:true,realUpstreamErrorMarkedPartial:true,unknownSignaturePreserved:true,boundedPagination:true,newOutputAndWarningsRetained:true,externalDatabaseDriftRefused:true,externalFilesPreserved:true,inputsUnchanged:true,checkpointSurvivesRemoval:true,terminalOwnedProcesses:true},cleanupComplete:true},null,2)+'\n',{mode:0o600});console.log('DiE native public CLI proof PASS:',directory);
}finally{if(!complete)await f.cleanup();}
