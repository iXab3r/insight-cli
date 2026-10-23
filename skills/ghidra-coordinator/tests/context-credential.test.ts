import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {releaseStoppedContextCredential} from '../src/context-credential.js';

test('retired context credential release requires exact owned stopped receipt and no live PID',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'insight-context-credential-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const native=join(directory,'native'),root=join(native,'context','context-id','stage');await mkdir(root,{recursive:true});
 const binding={root,kind:'context',target:'target-id',context:'context-id',pid:123456789,
  tokenSecret:'context-11111111-1111-4111-8111-111111111111',runtimeFingerprint:'fixture-runtime'};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));
 const deleted:string[]=[],secrets={delete:async(name:string)=>{deleted.push(name);}};
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>false),false,'No stop evidence');
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>true),false,'Live/reused PID');
 let probes=0;
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>++probes>1),false,'PID becomes live during validation');
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid+1,tokenSecret:binding.tokenSecret}));
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>false),false,'Wrong stopped PID');
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:'foreign'}));
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>false),false,'Wrong credential');
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
 await mkdir(join(directory,'foreign'));
 await assert.rejects(releaseStoppedContextCredential(join(directory,'foreign'),binding,secrets,()=>false),/receipt changed/);
 await writeFile(join(root,'process.json'),JSON.stringify({...binding,target:'different'}));
 await assert.rejects(releaseStoppedContextCredential(native,binding,secrets,()=>false),/receipt changed/);
 await writeFile(join(root,'process.json'),JSON.stringify(binding));
 assert.deepEqual(deleted,[]);
 assert.equal(await releaseStoppedContextCredential(native,binding,secrets,()=>false),true);
 assert.deepEqual(deleted,[binding.tokenSecret]);
});

test('credential release never sweeps server or unrelated references',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'insight-context-credential-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const root=join(directory,'context','context-id','stage');await mkdir(root,{recursive:true});
 const binding={root,kind:'context',target:'target',context:'context-id',pid:123456789,
  tokenSecret:'server-fixture-readerPassword',runtimeFingerprint:'fixture'};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));
 await writeFile(join(root,'stopped.json'),JSON.stringify({pid:binding.pid,tokenSecret:binding.tokenSecret}));
 await assert.rejects(releaseStoppedContextCredential(directory,binding,{delete:async()=>assert.fail('Unrelated secret')},()=>false),/receipt changed/);
});
