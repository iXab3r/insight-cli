import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {nextVersion,reserveVersion,applyVersion,verifyVersionChanges,versionFiles} from '../release-version.mjs';

test('increments from the greater stable source/latest, with explicit none and correct resets',()=>{
  assert.equal(nextVersion('0.2.0','0.2.0','patch'),'0.2.1');
  assert.equal(nextVersion('0.2.0','0.4.9','patch'),'0.4.10');
  assert.equal(nextVersion('0.2.0','0.4.9','minor'),'0.5.0');
  assert.equal(nextVersion('0.2.0','0.4.9','major'),'1.0.0');
  assert.equal(nextVersion('2.0.0','0.4.9','patch'),'2.0.1');
  assert.equal(nextVersion('0.2.0','0.4.9','none'),'0.2.0');
  assert.equal(nextVersion('1.0.0','1.0.9007199254740993','patch'),'1.0.9007199254740994');
  for(const invalid of ['0.2.0-beta.1','01.2.3','latest','1.2','1.2.3\n'])assert.throws(()=>nextVersion('0.2.0',invalid,'patch'));
  assert.throws(()=>nextVersion('0.2.0','0.2.0','unexpected'));
});

async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),'insight-version-test-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const values={
    [versionFiles[0]]:JSON.stringify({name:'@eyeauras/insight-cli',version:'0.2.0',dependencies:{external:'0.2.0'}},null,2)+'\n',
    'package-lock.json':JSON.stringify({version:'0.1.0',packages:{'':{version:'0.1.0'},'skills/ghidra-coordinator':{version:'0.2.0'},'node_modules/external':{version:'0.2.0'}}},null,2)+'\n',
    [versionFiles[2]]:'---\nname: insight-cli\n---\n# insight-cli 0.2.0\n\nExisting rules stay intact.\n',
    [versionFiles[3]]:'---\nname: insight-re\n---\n# Insight RE 0.2.0\n\nProject rules take precedence.\n',
    'untouched.txt':'original\n',
  };
  for(const [path,text] of Object.entries(values)){await mkdir(dirname(join(root,path)),{recursive:true});await writeFile(join(root,path),text);}
  return root;
}
const options={sourceCommit:'a'.repeat(40),runId:'123456',bump:'patch',attempt:1,latest:async()=>'0.2.0'};

test('re-run reuses its reserved version without consulting a newer registry',async t=>{
  const root=await fixture(t),first=await reserveVersion(root,options);
  assert.equal(first.version,'0.2.1');
  const restored=await reserveVersion(root,{...options,attempt:2,latest:async()=>{throw Error('Must not allocate again');}});
  assert.deepEqual(restored,first);
  await assert.rejects(reserveVersion(root,{...options,attempt:2,sourceCommit:'b'.repeat(40)}),/source commit/);
  await assert.rejects(reserveVersion(root,{...options,attempt:2,runId:'999'}),/workflow run/);
  await assert.rejects(reserveVersion(root,{...options,attempt:2,bump:'minor'}),/increment/);
});

test('missing or corrupt reservation never silently increments a re-run',async t=>{
  const root=await fixture(t);let queries=0;
  await assert.rejects(reserveVersion(root,{...options,attempt:2,latest:async()=>{queries++;return '0.3.0';}}),/original version artifact/);
  assert.equal(queries,0);
  await reserveVersion(root,options);
  await writeFile(join(root,'version-record/version.json'),'{invalid');
  await assert.rejects(reserveVersion(root,options),SyntaxError);
});

test('version application changes only owned metadata/headings and preserves dependency versions',async t=>{
  const root=await fixture(t),record=await reserveVersion(root,options);
  await applyVersion(root,record);
  const pkg=JSON.parse(await readFile(join(root,versionFiles[0]),'utf8'));
  const lock=JSON.parse(await readFile(join(root,'package-lock.json'),'utf8'));
  assert.equal(pkg.version,'0.2.1');assert.equal(pkg.dependencies.external,'0.2.0');
  assert.equal(lock.packages['skills/ghidra-coordinator'].version,'0.2.1');
  assert.equal(lock.packages['node_modules/external'].version,'0.2.0');assert.equal(lock.version,'0.1.0');
  assert.match(await readFile(join(root,versionFiles[2]),'utf8'),/# insight-cli 0.2.1\n\nExisting rules stay intact/);
  assert.match(await readFile(join(root,versionFiles[3]),'utf8'),/# Insight RE 0.2.1\n\nProject rules take precedence/);
  assert.equal(await readFile(join(root,'untouched.txt'),'utf8'),'original\n');
});

test('missing heading fails before writing any version input',async t=>{
  const root=await fixture(t),record=await reserveVersion(root,options);
  await writeFile(join(root,versionFiles[3]),'# Unexpected skill\n');
  await assert.rejects(applyVersion(root,record),/Missing original skill heading/);
  assert.equal(JSON.parse(await readFile(join(root,versionFiles[0]),'utf8')).version,'0.2.0');
});

test('build guard permits the exact version transformation and rejects unrelated or extra edits',async t=>{
  const root=await fixture(t);
  const git=args=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
  git(['init','--quiet']);git(['add','.']);
  git(['-c','user.name=CI fixture','-c','user.email=fixture@example.invalid','commit','--quiet','-m','fixture']);
  const record=await reserveVersion(root,{...options,sourceCommit:git(['rev-parse','HEAD'])});
  await applyVersion(root,record);await verifyVersionChanges(root,record);
  await writeFile(join(root,'untouched.txt'),'unexpected build mutation');
  await assert.rejects(verifyVersionChanges(root,record),/outside the version inputs/);
  await writeFile(join(root,'untouched.txt'),'original\n');
  const pkg=JSON.parse(await readFile(join(root,versionFiles[0]),'utf8'));pkg.dependencies.external='999.0.0';
  await writeFile(join(root,versionFiles[0]),JSON.stringify(pkg,null,2)+'\n');
  await assert.rejects(verifyVersionChanges(root,record),/Unexpected build change/);
});
