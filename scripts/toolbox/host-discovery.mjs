import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,symlink,writeFile,readFile,unlink,cp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createInterface} from 'node:readline';
import assert from 'node:assert/strict';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const [base,output]=process.argv.slice(2);assert.ok(base&&output,'Arguments: installed-package result-directory');await mkdir(output,{recursive:true,mode:0o700});
const root=await mkdtemp(join(tmpdir(),'insight-toolbox-host-'));
await mkdir(join(root,'.agents/skills'),{recursive:true});
await mkdir(join(root,'.agents/skills/unrelated-local'),{recursive:true});
await writeFile(join(root,'.agents/skills/unrelated-local/SKILL.md'),'---\nname: unrelated-local\ndescription: Synthetic unrelated local skill\n---\n# Unrelated fixture\n');
await symlink(join(base,'skill-bundle'),join(root,'.agents/skills/insight-toolbox'),'dir');
const child=spawn('codex',['app-server','--listen','stdio://'],{cwd:root,stdio:['pipe','pipe','pipe']});
let stderr='';child.stderr.on('data',c=>stderr+=c);const pending=new Map();let id=0;
const rl=createInterface({input:child.stdout});rl.on('line',line=>{let r;try{r=JSON.parse(line);}catch{return;}const waiting=pending.get(r.id);if(waiting){pending.delete(r.id);r.error?waiting.reject(Error(JSON.stringify(r.error))):waiting.resolve(r.result);}});
const send=m=>child.stdin.write(JSON.stringify(m)+'\n');
const request=(method,params)=>new Promise((resolve,reject)=>{const key=++id;const timer=setTimeout(()=>{pending.delete(key);reject(Error('Host discovery deadline: '+method));},20000);pending.set(key,{resolve:r=>{clearTimeout(timer);resolve(r);},reject:e=>{clearTimeout(timer);reject(e);}});send({id:key,method,params});});
try{
 await request('initialize',{clientInfo:{name:'insight_toolbox_discovery',version:'0.1.0'}});send({method:'initialized',params:{}});
 const results=await request('skills/list',{cwds:[root],forceReload:true});

 const actual=results.data.flatMap(d=>d.skills).filter(s=>s.name.startsWith('insight-'));
 const expected=JSON.parse(await readFile(join(base,'runtime/toolbox.json'),'utf8')).skills.map(s=>s.name).sort();
 const selected=actual.filter(s=>s.path.startsWith(join(base,'skill-bundle')));

 assert.deepEqual(selected.map(s=>s.name).sort(),expected);
 await unlink(join(root,'.agents/skills/insight-toolbox'));
 const removed=await request('skills/list',{cwds:[root],forceReload:true});
 assert.equal(removed.data.flatMap(d=>d.skills).filter(s=>s.path.startsWith(join(base,'skill-bundle'))&&s.name.startsWith('insight-')).length,0);
 assert.equal(removed.data.flatMap(d=>d.skills).filter(s=>s.name==='unrelated-local').length,1);
 const upgraded=join(root,'upgraded-package/skill-bundle');
 await cp(join(base,'skill-bundle'),upgraded,{recursive:true});
 await mkdir(join(upgraded,'insight-synthetic-upgrade'));
 await writeFile(join(upgraded,'insight-synthetic-upgrade/SKILL.md'),'---\nname: insight-synthetic-upgrade\ndescription: Synthetic new registered skill in upgrade fixture\n---\n# Upgrade fixture\n');
 await symlink(upgraded,join(root,'.agents/skills/insight-toolbox'),'dir');
 const changed=await request('skills/list',{cwds:[root],forceReload:true});
 assert.equal(changed.data.flatMap(d=>d.skills).filter(s=>s.name==='insight-synthetic-upgrade').length,1);
 assert.equal(changed.data.flatMap(d=>d.skills).filter(s=>s.name==='unrelated-local').length,1);
 await unlink(join(root,'.agents/skills/insight-toolbox'));
 await writeFile(join(output,'result.json'),JSON.stringify({schema:1,state:'passed',scope:'Actual Codex skill metadata; controlled bundle upgrade simulation; no model inference',skills:expected,checks:{allInstalledSkillsVisible:true,unrelatedSkillPreserved:true,scopedDisconnect:true,simulatedUpgradeEntryVisible:true},cleanupComplete:true},null,2)+'\n',{mode:0o600});
 console.log('Codex packaged skill discovery PASS');
}catch(error){await writeFile(join(output,'host.stderr'),stderr,{mode:0o600});throw error;}
finally{child.stdin.end();child.kill();await rm(root,{recursive:true,force:true});}
