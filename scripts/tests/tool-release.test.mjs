import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {validateRecipe,acquire} from '../tool-release.mjs';
const a={name:'fixture.zip',upstream:'https://example.invalid/file',sha256:'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',size:5,license:'Synthetic',role:'source'};
test('mirror admits only reviewed exact assets with source companions',()=>{
 const r={schema:1,repository:'iXab3r/insight-cli',tag:'tool-fixture-1-r1',assets:[a],redistribution:'Fixture'};validateRecipe(r);
 for(const patch of [{assets:[{...a,name:'../escape'}]},{assets:[a,a]},{assets:[{...a,role:'binary'}]},{tag:'latest'},{assets:[{...a,size:2*1024**3}]}])assert.throws(()=>validateRecipe({...r,...patch}));
});
test('mirror acquisition verifies size and hash and reuses exact retained bytes',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'mirror-'));t.after(()=>rm(dir,{recursive:true,force:true}));let count=0;
 const fetcher=async()=>{count++;return new Response('hello');};
 const file=await acquire(a,dir,fetcher);assert.equal(await readFile(file,'utf8'),'hello');await acquire(a,dir,fetcher);assert.equal(count,1);
 await assert.rejects(acquire({...a,name:'bad.zip',sha256:'f'.repeat(64)},dir,fetcher),/differs/);
 await assert.rejects(acquire({...a,name:'oversize.zip',size:1},dir,fetcher),/Oversized/);
});
test('published immutable verification needs neither upstream acquisition nor upload authority',async t=>{
 const {writeFile,mkdir,chmod}=await import('node:fs/promises');
 const {execFile}=await import('node:child_process');const {promisify}=await import('node:util');
 const {createHash}=await import('node:crypto');const {fileURLToPath}=await import('node:url');
 const root=await mkdtemp(join(tmpdir(),'mirror-retry-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const recipe={schema:1,repository:'iXab3r/insight-cli',tag:'tool-fixture-1-r1',assets:[a],redistribution:'Fixture'};
 const bytes=Buffer.from(JSON.stringify(recipe,null,2)+'\n');
 const remote={draft:false,immutable:true,html_url:'https://example.invalid/release',assets:[{name:a.name,size:a.size,digest:'sha256:'+a.sha256},{name:'manifest.json',size:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex')}]};
 const input=join(root,'recipe.json');await writeFile(input,bytes);const bin=join(root,'bin');await mkdir(bin);
 const executable=join(bin,process.platform==='win32'?'gh.cmd':'gh');
 if(process.platform==='win32')return; // POSIX CLI seam; production portable acquisition tests run above.
 await writeFile(executable,'#!'+process.execPath+'\nif(process.argv[2]!=="api"||!process.argv[3].includes("/releases/tags/"))process.exit(11);console.log('+JSON.stringify(JSON.stringify(remote))+');\n');await chmod(executable,0o755);
 const run=promisify(execFile),script=fileURLToPath(new URL('../tool-release.mjs',import.meta.url));
 const env={...process.env,PATH:bin+':'+process.env.PATH,GITHUB_ACTIONS:'true',TOOL_RELEASE_IMMUTABLE_READY:'true'};
 const result=await run(process.execPath,[script,input,join(root,'out'),'--publish'],{env});
 assert.equal(JSON.parse(result.stdout).state,'published_verified');
 const {stat}=await import('node:fs/promises');await assert.rejects(stat(join(root,'out',a.name)));
 await assert.rejects(run(process.execPath,[script,input,join(root,'denied'),'--publish'],{env:{...env,TOOL_RELEASE_IMMUTABLE_READY:''}}),/setup is not confirmed/);
});
test('draft/readback reconciliation tolerates delayed visibility with bounded read-only polling',async()=>{
 const {waitFor}=await import('../tool-release.mjs');let reads=0;
 assert.equal(await waitFor(()=>++reads>=3?'visible':undefined,Boolean,4,1),'visible');assert.equal(reads,3);
 await assert.rejects(waitFor(()=>undefined,Boolean,2,1),/visibility is unresolved/);
});
