// Opt-in installed public-CLI acceptance. Fresh live agents supply ordinary findings/files.
import assert from 'node:assert/strict';
import {readFile,mkdir,copyFile,readdir,statfs,appendFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {PublicCli,json,save,exec} from './business/public-cli.mjs';
import {bindings} from './business/cases.mjs';

const [action,location,installed,input]=process.argv.slice(2),directory=resolve(location);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const address=value=>BigInt(/^0x/i.test(value)?value:'0x'+value);
const expected='256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');assert.ok(!process.env.CI);
function executableText(source){
 let result='',state='code';
 for(let i=0;i<source.length;i++){
  const c=source[i],next=source[i+1];
  if(state==='line'){if(c==='\n'){state='code';result+=' ';}continue;}
  if(state==='block'){if(c==='*'&&next==='/'){state='code';result+=' ';i++;}continue;}
  if(state==='string'||state==='char'){if(c==='\\')i++;else if(c===(state==='string'?'"':"'")){state='code';result+=' ';}continue;}
  if(c==='/'&&next==='/'){state='line';i++;continue;}if(c==='/'&&next==='*'){state='block';i++;continue;}
  if(c==='"'){state='string';result+=' ';continue;}if(c==="'"){state='char';result+=' ';continue;}result+=c;
 }
 return result;
}
async function client(m,label){return new PublicCli(m,join(directory,'transcripts',label));}
async function sameTree(source,copy){
 const left=await readdir(source,{withFileTypes:true}),right=await readdir(copy,{withFileTypes:true});
 assert.deepEqual(left.map(e=>e.name).sort(),right.map(e=>e.name).sort());
 for(const entry of left){assert.ok(entry.isFile()||entry.isDirectory());if(entry.isDirectory())await sameTree(join(source,entry.name),join(copy,entry.name));
  else assert.equal(sha(await readFile(join(source,entry.name))),sha(await readFile(join(copy,entry.name))));}
}
if(action==='prepare'){
 await mkdir(directory,{recursive:true,mode:0o700});assert.ok(!(await readdir(directory)).includes('manifest.json'),'Use a fresh owned run directory.');
 const bytes=await readFile(input);assert.equal(sha(bytes),expected);await mkdir(join(directory,'input'));await copyFile(input,join(directory,'input/7zr.exe'));
 for(const folder of ['A-password','B-extraction','C-binary'])await mkdir(join(directory,'research',folder),{recursive:true});
 await mkdir(join(directory,'receipts'));
 const artifact=join(installed,'artifacts/ixab3r-insight-cli-0.1.0.tgz'),m={schema:1,directory,cli:join(installed,'node_modules/@ixab3r/insight-cli/dist/src/bin.js'),
  artifact,artifactSha256:sha(await readFile(artifact)),profile:'re-skill-'+randomUUID(),java:'/opt/homebrew/opt/openjdk@21/bin/java',ghidra:'/opt/homebrew/opt/ghidra/libexec',
  inputs:[{path:join(directory,'input/7zr.exe'),sha256:expected,bytes:bytes.length}]};
 await save(join(directory,'manifest.json'),m);const cli=await client(m,'prepare');
 const skill=await cli.call(['skill','insight-re'],{global:true});assert.equal(skill.name,'insight-re');m.skill=skill.path;m.skillSha256=sha(await readFile(skill.path));
 await cli.setup();m.a=await cli.open();m.b=await cli.open();assert.equal(m.a.target,m.b.target);assert.notEqual(m.a.session,m.b.session);
 const native=await bindings(cli,m.a.target);assert.equal(native.length,2);assert.equal(new Set(native.map(n=>n.root)).size,2);
 m.native=native.map(n=>({pid:n.pid,ownedRootSha256:sha(n.root)}));const space=await statfs(directory);m.freeBytesBeforeResearch=Number(space.bavail)*Number(space.bsize);
 m.readyAt=new Date().toISOString();await save(join(directory,'manifest.json'),m);
 console.log(JSON.stringify({profile:m.profile,skill:m.skill,a:m.a,b:m.b,artifactSha256:m.artifactSha256,native:m.native}));
}else if(action==='finish'){
 const m=await json(join(directory,'manifest.json')),cli=await client(m,'finish'),a=m.a,b=m.b,review=await json(join(directory,'review.json'));
 assert.equal(review.password,true);assert.equal(review.extraction,true);assert.equal(review.external,true);
 assert.equal(sha(await readFile(m.inputs[0].path)),expected);assert.equal(sha(await readFile(m.artifact)),m.artifactSha256);assert.equal(sha(await readFile(m.skill)),m.skillSha256);
 for(const [name,folder] of [['A','A-password'],['B','B-extraction'],['C','C-binary']]){
  const receipt=await json(join(directory,'receipts',name+'.json'));assert.equal(receipt.state,'saved');assert.equal(receipt.kind,'directory');
  await sameTree(join(directory,'research',folder),receipt.path);
 }
 const pa='0x43f4f5',pb='0x436fea',textA=await cli.readComment(a,pa),textB=await cli.readComment(b,pb);
 assert.ok(textA.includes('A-password/finding.md'));assert.ok(textB.includes('B-extraction/finding.md'));
 assert.equal(await cli.readComment(b,pa),null,'B must still have its independent R1');
 const statusBefore=await cli.status(b);assert.equal(statusBefore.ghidra.pendingChanges,1);
 const mergeA=await cli.scoped(a,'merge');assert.equal(mergeA.state,'merged');assert.equal(mergeA.sharedRevision,'R2');
 assert.equal(await cli.readComment(b,pa),null);assert.equal(await cli.readComment(b,pb),textB);
 const refreshB=await cli.scoped(b,'refresh');assert.equal(refreshB.state,'updated');assert.equal(refreshB.preservedLocalChanges,1);
 assert.equal(await cli.readComment(b,pa),textA);assert.equal(await cli.readComment(b,pb),textB);
 const mergeB=await cli.scoped(b,'merge');assert.equal(mergeB.state,'merged');assert.equal(mergeB.sharedRevision,'R3');
 const reader=await cli.fresh(a.target);assert.equal(await cli.readComment(reader,pa),textA);assert.equal(await cli.readComment(reader,pb),textB);
 // Fresh native code readback corroborates the useful findings, not just their comments.
 const password=await cli.scoped(reader,'functions decompile',['--address',pa]),extraction=await cli.scoped(reader,'functions decompile',['--address',pb]);
 assert.equal(password.truncated,false);assert.equal(extraction.truncated,false);
 const passwordCode=executableText(password.code),extractionCode=executableText(extraction.code);
 assert.match(passwordCode,/\bGetConsoleMode\s*\(/);assert.match(passwordCode,/\bSetConsoleMode\s*\(/);assert.ok(passwordCode.includes('0xfffffffb'));
 assert.match(extractionCode,/\bswitch\s*\(/);
 await save(join(directory,'independent-code.json'),{password,extraction});
 const history=await cli.history(a.target);assert.deepEqual(history.versions.map(v=>v.version).sort(),[1,2,3]);
 const externalHash=(await readFile(join(directory,'research/C-binary/sha256.txt'),'utf8')).split(/\s/)[0];assert.equal(externalHash,expected);
 const imports=await readFile(join(directory,'research/C-binary/imports.txt'),'utf8');assert.ok(imports.includes('SetConsoleMode')&&imports.includes('GetConsoleMode'));
 await appendFile(join(directory,'research/notes.md'),'\nPublication verified: A merged R2; B refreshed while preserving its local annotation, then merged R3. A fresh session read both annotations and their native code. Repository history contains R1, R2 and R3.\n');
 const copied=await cli.call(['artifacts','save',join(directory,'research')]);assert.equal(copied.state,'saved');await sameTree(join(directory,'research'),copied.path);
 await save(join(directory,'receipts/final.json'),copied);
 const single=await cli.call(['artifacts','save',join(directory,'research/notes.md')]);assert.equal(single.state,'saved');assert.equal(await readFile(single.path,'utf8'),await readFile(join(directory,'research/notes.md'),'utf8'));
 await save(join(directory,'receipts/notes.json'),single);
 const savedNotes=await readFile(join(copied.path,'notes.md'),'utf8');assert.ok(savedNotes.includes('R3'));
 const result={schema:1,artifactSha256:m.artifactSha256,skillSha256:m.skillSha256,inputSha256:expected,agentCount:3,nativeWorkers:m.native,
  freeBytesBeforeResearch:m.freeBytesBeforeResearch,review,mergeA,refreshB,mergeB,history,independentReadback:true,
  workerMaterialsVerified:3,finalMaterials:copied,singleFile:single,sourceAndBuildUnchanged:true,finishedAt:new Date().toISOString()};
 await save(join(directory,'result.json'),result);
 const sessions=await cli.call(['sessions','list']);for(const session of sessions.items)await cli.close({session:session.id,target:a.target});
 await cli.call(['ghidra','server','disconnect']);result.cleanupComplete=true;await save(join(directory,'result.json'),result);
 console.log(JSON.stringify({passed:true,finalMaterials:copied,cleanupComplete:true}));
}else if(action==='inspect'){
 const previous=await json(join(directory,'manifest.json')),completed=await json(join(directory,'result.json'));
 assert.equal(completed.cleanupComplete,true);const cliPath=join(installed,'node_modules/@ixab3r/insight-cli/dist/src/bin.js');
 const m={...previous,cli:cliPath},cli=await client(m,'inspect-correction');await cli.call(['ghidra','server','connect']);
 const scopeFile=join(directory,'inspect-scope.json'),retained=await json(scopeFile).catch(error=>{if(error.code==='ENOENT')return null;throw error;});
 const reader=retained?await cli.call(['ghidra','open','--target',previous.a.target,'--session',retained.session]):await cli.fresh(previous.a.target);
 assert.equal(reader.state,'ready');await save(scopeFile,reader);
 const args=['--function','0x43f4b1','--include-call-context','true','--call-context-limit','5','--call-context-lines','12','--include-disasm','true'];
 const single=await cli.scoped(reader,'functions inspect',args);assert.equal(address(single.value.entry_point),0x43f4b1n);assert.ok(single.value.size>0);assert.ok(single.value.signature);
 const subset=await cli.scoped(reader,'functions inspect',['--function','0x43f4b1','--fields','signature','--include-call-context','false']);
 assert.ok(subset.value.name);assert.ok(subset.value.size>0);assert.ok(subset.value.signature);assert.equal(subset.value.entry_point,undefined);
 const bulk=await cli.scoped(reader,'functions inspect',['--functions','0x43f4b1,0x43f4f5','--fields','entry_point,signature','--include-call-context','false']);
 assert.equal(bulk.value.count,2);assert.equal(bulk.value.requested,2);assert.equal(address(bulk.value.functions['0x43f4b1'].entry_point),0x43f4b1n);
 const history=await cli.history(reader.target);assert.deepEqual(history.versions.map(v=>v.version).sort(),[1,2,3]);
 const copied=await cli.call(['artifacts','save',join(directory,'research')]);await sameTree(join(directory,'research'),copied.path);
 const notes=await cli.call(['artifacts','save',join(directory,'research/notes.md')]);assert.equal(await readFile(notes.path,'utf8'),await readFile(join(directory,'research/notes.md'),'utf8'));
 const artifact=join(installed,'artifacts/ixab3r-insight-cli-0.1.0.tgz'),skill=join(installed,'node_modules/@ixab3r/insight-cli/skills/insight-re/SKILL.md');
 const result={artifactSha256:sha(await readFile(artifact)),skillSha256:sha(await readFile(skill)),inputSha256:sha(await readFile(previous.inputs[0].path)),
  singleFunction:true,fieldSubset:true,bulk:true,historyUnchanged:true,folder:copied,file:notes};
 assert.equal(result.inputSha256,expected);assert.equal(result.skillSha256,previous.skillSha256);
 await cli.close(reader);await cli.call(['ghidra','server','disconnect']);result.cleanupComplete=true;
 await save(join(directory,'inspect-correction.json'),result);console.log(JSON.stringify({passed:true,...result}));
}else throw Error('Use prepare <new-run> <installed-package-directory> <7zr.exe>, finish <run> or inspect <completed-run> <installed-package-directory>. On failure preserve state and inspect public status/history before any retry.');
