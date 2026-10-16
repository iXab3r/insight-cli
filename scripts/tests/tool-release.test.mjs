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
