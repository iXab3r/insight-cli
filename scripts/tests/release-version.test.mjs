import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {setVersion,versionFiles} from '../release-version.mjs';

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
  const registry=JSON.parse(await readFile(new URL('../../skills/ghidra-coordinator/runtime/toolbox.json',import.meta.url),'utf8'));
  for(const skill of registry.skills.slice(2))values['skills/ghidra-coordinator/'+skill.path]='---\nname: '+skill.name+'\n---\n# '+skill.title+' 0.2.0\n\nAdditional shipped tool.\n';
  for(const [path,text] of Object.entries(values)){await mkdir(dirname(join(root,path)),{recursive:true});await writeFile(join(root,path),text);}
  return root;
}
test('version application changes only owned metadata/headings and preserves dependency versions',async t=>{
  const root=await fixture(t);
  assert.deepEqual(await setVersion(root,'0.2.1'),{previous:'0.2.0',version:'0.2.1'});
  const pkg=JSON.parse(await readFile(join(root,versionFiles[0]),'utf8'));
  const lock=JSON.parse(await readFile(join(root,'package-lock.json'),'utf8'));
  assert.equal(pkg.version,'0.2.1');assert.equal(pkg.dependencies.external,'0.2.0');
  assert.equal(lock.packages['skills/ghidra-coordinator'].version,'0.2.1');
  assert.equal(lock.packages['node_modules/external'].version,'0.2.0');assert.equal(lock.version,'0.1.0');
  assert.match(await readFile(join(root,versionFiles[2]),'utf8'),/# insight-cli 0.2.1\n\nExisting rules stay intact/);
  assert.match(await readFile(join(root,versionFiles[3]),'utf8'),/# Insight RE 0.2.1\n\nProject rules take precedence/);
  for(const path of versionFiles.slice(4))assert.match(await readFile(join(root,path),'utf8'),/ 0\.2\.1\n\nAdditional shipped tool/);
  assert.equal(await readFile(join(root,'untouched.txt'),'utf8'),'original\n');
});

test('missing heading fails before writing any version input',async t=>{
  const root=await fixture(t);
  await writeFile(join(root,versionFiles[3]),'# Unexpected skill\n');
  await assert.rejects(setVersion(root,'0.2.1'),/Missing original skill heading/);
  assert.equal(JSON.parse(await readFile(join(root,versionFiles[0]),'utf8')).version,'0.2.0');
});

test('only stable versions are accepted',async t=>{
  const root=await fixture(t);for(const invalid of [undefined,'01.2.3','0.2.0-beta.1','latest','1.2'])await assert.rejects(setVersion(root,invalid),/stable version/);
});
