import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {PlatformSecretStore,ProfileSecrets} from '@eyeauras/cli-factory';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';

test('Windows facade auth persists in the default platform store across applications and profiles',
 {skip:process.platform!=='win32'},async t=>{
 const values={server:'ghidra://127.0.0.1:14100',repository:'synthetic',readerUser:'reader',publisherUser:'publisher'};
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',values},{name:'other',values}]});
 const make=()=>f.createApplication(runtime=>{
  const {secretStore:_,...platformRuntime}=runtime;
  return createInsightCli({runtime:{...platformRuntime,fetch:async()=>{throw Error('Unexpected network');}}});
 });
 const app=make(),value='synthetic-reader-🔒';
 const login=await f.run(app,['auth','login','--role','reader','--password-stdin','--json'],{input:Readable.from([value+'\n'])});
 assert.equal(login.exitCode,0,login.stderr);
 assert.ok(!login.stdout.includes(value));assert.ok(!login.stderr.includes(value));
 const store=new PlatformSecretStore(f.appArguments);
 const secrets=new ProfileSecrets(store,'insight-cli','default');
 assert.equal(await secrets.require('readerPassword'),value);
 assert.equal(await new ProfileSecrets(store,'insight-cli','other').get('readerPassword'),undefined);
 const directory=join(f.appArguments.AppDataDirectory,'secrets'),files=await readdir(directory);
 assert.equal(files.length,1);assert.match(files[0]!,/^[a-f0-9]{64}\.dpapi$/);
 assert.ok(!(await readFile(join(directory,files[0]!))).includes(Buffer.from(value)));
 await app.dispose();
 const reopened=make();
 const status=await f.json(reopened,['auth','status']) as {identity:{readerStored:boolean}};
 assert.equal(status.identity.readerStored,true);
 await f.json(reopened,['auth','logout']);
 assert.equal(await secrets.get('readerPassword'),undefined);
 assert.deepEqual(await readdir(directory),[]);
});
