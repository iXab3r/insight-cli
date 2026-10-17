import assert from 'node:assert/strict';import {readFile,writeFile,copyFile,mkdir,stat} from 'node:fs/promises';import {join} from 'node:path';
import {createPublicFixture,digest} from './public-fixture.mjs';
const [packageRoot,directory,archive,subjects]=process.argv.slice(2);assert.ok(subjects,'Arguments: installed-package disposable-directory pinned-runtime.tgz owned-subjects');
const f=await createPublicFixture(packageRoot,directory);let complete=false;
try{
 const identities=[];for(const name of ['program.exe','program.pdb','program.macho','program.elf']){const path=join(f.project,name);await copyFile(join(subjects,name),path);identities.push({name,sha256:digest(await readFile(path))});}
 assert.equal((await f.call(['llvm','status'])).state,'not_ready');
 const installed=await f.call(['llvm','install','--archive',archive,'--offline']);assert.equal(installed.mode,'managed');assert.equal((await f.call(['llvm','doctor'])).state,'verified');
 const pe=join(f.project,'program.exe'),pdb=join(f.project,'program.pdb');
 const headers=await f.call(['llvm','headers',pe]);assert.match(headers.content,/COFF-x86-64/);assert.match(headers.content,/ImageBase: 0x140000000/);
 const sections=await f.call(['llvm','sections','--target',headers.target]);assert.match(sections.content,/VirtualAddress: 0x1000/);
 const imports=await f.call(['llvm','imports',pe]);assert.match(imports.content,/PolicyNative.dll/);assert.match(imports.content,/upstream_adjust/);
 const exports=await f.call(['llvm','exports',pe]);assert.match(exports.content,/quote_total/);assert.match(exports.content,/RVA: 0x1000/);
 const instructions=await f.call(['llvm','disassemble',pe,'--address','0x140001040','--bytes','72']);assert.match(instructions.content,/\b(imul|cmpl|cmp)\b/);
 const summary=await f.call(['llvm','pdb',pdb]);assert.match(summary.content,/Has Types: true/);
 const modules=await f.call(['llvm','pdb',pdb,'--view','modules']);assert.match(modules.content,/program.obj/);
 const globals=await f.call(['llvm','pdb',pdb,'--view','globals','--symbol','quote_total']);assert.match(globals.content,/quote_total/);
 const publics=await f.call(['llvm','pdb',pdb,'--view','publics']);assert.match(publics.content,/quote_total/);
 const symbols=await f.call(['llvm','pdb',pdb,'--view','symbols','--module','0']);assert.match(symbols.content,/price_from_rule/);
 const types=await f.call(['llvm','pdb',pdb,'--view','types','--type-index','0x1005']);assert.match(types.content,/0x1005/);assert.match(types.content,/PricingRule/);assert.match(types.content,/sizeof 12/);
 const nextPage=await f.call(['llvm','pdb',pdb,'--view','symbols','--module','0','--limit','3','--offset','4']);assert.equal(nextPage.limit,3);assert.equal(nextPage.truncated,true);assert.ok(nextPage.content.split('\n').length<=3);
 const output=join(f.project,'research','native','procedures.txt');await f.call(['llvm','pdb',pdb,'--view','symbols','--module','0','--output',output]);assert.match(await readFile(output,'utf8'),/price_from_rule/);
 assert.notEqual((await f.call(['llvm','pdb',pdb,'--view','symbols','--output',output],{allowFailure:true})).code,0);
 assert.notEqual((await f.call(['llvm','disassemble',pe,'--address','0xffffffffffffffff','--bytes','2'],{allowFailure:true})).code,0);
 const macho=join(f.project,'program.macho');assert.match((await f.call(['llvm','imports',macho])).content,/_puts/);assert.match((await f.call(['llvm','symbols',macho])).content,/_quote_total/);assert.match((await f.call(['llvm','exports',macho])).content,/_quote_total/);
 const elf=join(f.project,'program.elf');assert.match((await f.call(['llvm','headers',elf])).content,/elf64-x86-64/);assert.match((await f.call(['llvm','imports',elf])).content,/libpolicy.so/);assert.match((await f.call(['llvm','imports',elf])).content,/upstream_adjust/);assert.match((await f.call(['llvm','exports',join(subjects,'libpolicy.so')])).content,/upstream_adjust/);
 const checkpoint=await f.call(['artifacts','save',join(f.project,'research')]);await f.call(['permissions','grant','Destructive']);await f.call(['llvm','uninstall']);await stat(checkpoint.path);
 const external=join(directory,'external');await mkdir(external);const hashes={};
 // Preserve an independent family before uninstalling its managed source.
 // The original reviewed archive is unpacked into this owned fixture by the maintainer helper below.
 const {execFileSync}=await import('node:child_process');execFileSync('tar',['-xzf',archive,'--strip-components=1','-C',external]);
 for(const name of ['llvm-readobj','llvm-objdump','llvm-nm','llvm-pdbutil'])hashes[name]=digest(await readFile(join(external,'bin',name)));
 const selected=await f.call(['llvm','install','--executable',join(external,'bin/llvm-readobj')]);assert.equal(selected.mode,'external');assert.equal((await f.call(['llvm','doctor'])).state,'verified');
 const sibling=join(external,'bin/llvm-nm'),bytes=await readFile(sibling);await writeFile(sibling,Buffer.concat([bytes,Buffer.from('changed owned fixture')]));
 assert.notEqual((await f.call(['llvm','symbols',macho],{allowFailure:true})).code,0);await writeFile(sibling,bytes);await f.call(['llvm','symbols',macho]);
 assert.equal((await f.call(['llvm','uninstall'])).externalInstallationPreserved,true);
 for(const [name,sha]of Object.entries(hashes))assert.equal(digest(await readFile(join(external,'bin',name))),sha);
 for(const input of identities)assert.equal(digest(await readFile(join(f.project,input.name))),input.sha256);
 assert.ok((await f.call(['tools','processes','--tool','llvm','--all'])).items.every(p=>['exited','failed'].includes(p.state)));
 await f.cleanup();complete=true;
 await writeFile(join(directory,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Real public CLI developer proof; independent cold/prepared model gate separate',version:f.version,inputs:identities,checks:{peLinkage:true,machoLinkage:true,elfLinkage:true,pdbSummaryModulesGlobalsPublicsProceduresTypes:true,hexTypeIndexCorrect:true,boundedDisassembly:true,pagedOutput:true,outputParentsAndNoOverwrite:true,externalFamilyDriftRefused:true,externalFamilyPreserved:true,inputsUnchanged:true,checkpointSurvivesRemoval:true,terminalOwnedProcesses:true},cleanupComplete:true},null,2)+'\n',{mode:0o600});console.log('LLVM public CLI native proof PASS:',directory);
}finally{if(!complete)await f.cleanup();}
