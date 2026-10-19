// Opt-in installed-CLI acceptance. All research inputs and profiles are disposable.
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,writeFile,open,stat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
import {createHash} from 'node:crypto';
import {createPublicFixture} from './toolbox/public-fixture.mjs';
const exec=promisify(execFile);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const required=name=>{const value=process.env[name];assert.ok(value&&value.startsWith('/'),name+' must select an absolute disposable path');return resolve(value);};
const packageRoot=required('INSIGHT_STORAGE_PACKAGE_ROOT'),sourceBase=required('INSIGHT_STORAGE_SOURCE_BASE'),destinationBase=required('INSIGHT_STORAGE_DESTINATION_BASE');
const copyOnly=process.env.INSIGHT_STORAGE_COPY_ONLY==='1';
const java=copyOnly?undefined:required('INSIGHT_JAVA'),ghidra=copyOnly?undefined:required('INSIGHT_GHIDRA_HOME'),clang=copyOnly?undefined:required('INSIGHT_CLANG');
await mkdir(sourceBase,{recursive:true});await mkdir(destinationBase,{recursive:true});
const output=await mkdtemp(join(sourceBase,'acceptance-')),appDataBase=join(destinationBase,'control');await mkdir(appDataBase,{recursive:true});
const f=await createPublicFixture(packageRoot,output,{appDataBase});
console.log('Owned private acceptance directory:',output);
let receipt;
try{
  if(!copyOnly)await f.call(['profile','set',f.profile,'--java',java,'--ghidra-home',ghidra]);
  await f.call(['permissions','grant','Destructive']);
  const configured=await f.call(['storage','configure','--directory',join(output,'original storage Ω')]);assert.equal(configured.state,'committed');
  await f.call(['storage','cleanup']);
  const source=join(output,'subject.c'),binary=join(output,'subject');
  await writeFile(source,'__attribute__((noinline)) int fixture_value(int value){return value+42;}\nint main(void){return fixture_value(7);}\n');
  if(copyOnly)await writeFile(binary,'Generic disposable immutable input');else await exec(clang,['-O0','-g0',source,'-o',binary]);
  const symbols=copyOnly?'0 T _fixture_value':(await exec('/usr/bin/nm',['-g',binary])).stdout,match=/^([a-f0-9]+)\s+T\s+_fixture_value$/mi.exec(symbols);assert.ok(match);
  const address=match[1],opened=await f.call(copyOnly?['targets','add',binary]:['ghidra','open',binary,'--session','new']),scope=['--session',opened.session,'--target',opened.target];
  const note='Generic disposable migration finding';
  if(!copyOnly)await f.call(['ghidra','comments','set',...scope,'--address',address,'--kind','eol','--text',note,'--request-id','storage-native-edit']);
  const finding=join(output,'finding.txt');await writeFile(finding,note);const artifact=await f.call(['artifacts','save',finding]);
  if(!copyOnly){await f.call(['ghidra','close',...scope]);await f.call(['ghidra','server','stop']);}
  const before=await f.call(['storage','show']),dataRoot=before.directory;
  // A real byte stream makes the interruption observable without an artificial product hook.
  const large=join(dataRoot,'runtime/checks/disposable-copy.bin');await mkdir(join(dataRoot,'runtime/checks'),{recursive:true});
  const file=await open(large,'wx',0o600);try{const bytes=Buffer.alloc(1024*1024,0x5a);for(let i=0;i<256;i++)await file.writeFile(bytes);await file.sync();}finally{await file.close();}
  const destination=join(destinationBase,'migrated storage Ω'),plan=await f.call(['storage','migrate','--directory',destination,'--dry-run']);
  assert.notEqual((await stat(dataRoot)).dev,(await stat(destinationBase)).dev,'Acceptance must actually cross filesystems');
  assert.ok(plan.bytes>=256*1024**2);
  const control=join(f.appdata,'insight-cli',f.profile,'storage/migration.json'),oldJournal=JSON.parse(await readFile(control,'utf8'));
  const owner=await f.call(['ipc-server','status']);assert.equal(owner.running,true);assert.ok(Number.isSafeInteger(owner.pid));
  const copying=f.call(['storage','migrate','--directory',destination],{allowFailure:true});
  let interrupted=false;
  for(let attempt=0;attempt<6000;attempt++){
    const journal=JSON.parse(await readFile(control,'utf8'));
    if(journal.id!==oldJournal.id&&journal.state==='copying'){
      const identity=JSON.parse(await readFile(join(f.appdata,'insight-cli/.runtime/owner.json'),'utf8'));assert.equal(identity.pid,owner.pid);
      process.kill(owner.pid,'SIGKILL');interrupted=true;break;
    }
    if(journal.id!==oldJournal.id&&journal.state==='committed')break;
    await delay(10);
  }
  assert.equal(interrupted,true,'An actual elected owner must be interrupted while copying');
  assert.notEqual((await copying).code,0);
  const pending=await f.call(['storage','show']);assert.equal(pending.migration.state,'copying');
  assert.equal((await f.call(['targets','list'],{allowFailure:true})).code===0,false);
  assert.equal((await f.call(['storage','resume'])).state,'committed');
  // Independent owner and independently reopened native DB, not the pre-migration handle.
  await f.call(['ipc-server','stop']);
  if(copyOnly){assert.deepEqual(await f.call(['targets','show',opened.target]),opened);await f.call(['artifacts','save',finding]);}
  else{
  await f.call(['ghidra','open',...scope]);
  assert.equal((await f.call(['ghidra','comments','get',...scope,'--address',address,'--kind','eol'])).text,note);
  assert.equal(await readFile(artifact.path,'utf8'),note,'Old receipt paths remain usable');
  const merged=await f.call(['ghidra','merge',...scope,'--request-id','storage-native-publication']);assert.equal(merged.state,'merged');
  const independent=await f.call(['ghidra','open',binary,'--session','new']);assert.equal(independent.target,opened.target);
  const second=['--session',independent.session,'--target',independent.target];
  assert.equal((await f.call(['ghidra','comments','get',...second,'--address',address,'--kind','eol'])).text,note);
  for(const selected of [scope,second])await f.call(['ghidra','close',...selected]);await f.call(['ghidra','server','stop']);
  }
  assert.equal(await readFile(artifact.path,'utf8'),note);
  assert.notEqual((await f.call(['storage','rollback'],{allowFailure:true})).code,0,'Rollback must not discard new native writes');
  assert.equal((await f.call(['storage','cleanup'])).state,'cleaned');assert.equal(await readFile(artifact.path,'utf8'),note);
  const final=await f.call(['storage','show']);assert.equal(final.availability,'available');assert.equal(final.migration.state,'cleaned');
  assert.equal((await f.call(['ghidra','status'])).processes.length,0);
  receipt={schema:1,status:'passed',scope:copyOnly?'installed public CLI copy/resume/file-readback':'installed public CLI native Ghidra',native:!copyOnly,version:f.version,inputSha256:createHash('sha256').update(await readFile(binary)).digest('hex'),
    platform:process.platform,architecture:process.arch,node:process.versions.node,crossFilesystem:true,migratedBytes:plan.bytes,manifest:final.migration.manifest,
    assertions:copyOnly?['installed public CLI and Factory profile/IPC','actual cross-filesystem copy','actual elected-owner SIGKILL while copying','ordinary-command freeze and durable resume','replacement-owner target and file readback','rollback refuses subsequent writes','verified source cleanup and retained aliases']:['installed public CLI and Factory profile/keyring/IPC','spaces and Unicode destinations','native saved private edit and local server repository','actual elected-owner SIGKILL while copying','ordinary-command freeze and durable resume','independent replacement-owner native reopen','preserved session/target and saved-file receipt','publication and fresh-session shared readback','rollback refuses post-migration writes','verified source cleanup and retained aliases','owned native processes stopped']};
  await writeFile(join(output,'sanitized-receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));
}finally{await f.cleanup();}
