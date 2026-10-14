// Owned local/external authority fixture. Never invoked by the default CI suite.
import assert from 'node:assert/strict';
import {mkdtemp,realpath,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {nativeInputs,nativeHelpers,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';

const options={},argv=process.argv.slice(2);
for(let i=0;i<argv.length;i++) {
  if(argv[i]==='--ack-disposable') options.ack=true;
  else if(argv[i].startsWith('--')&&argv[i+1]) options[argv[i].slice(2)]=argv[++i];
  else throw Error('Invalid proof argument');
}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]),'Native proof is local only');
for(const key of ['ghidra-home','java','mcp-jar']) assert.ok(options[key],`Missing --${key}`);
const root=await realpath(await mkdtemp('/tmp/insight-server-proof-'));
// This fixture adapter exercises the same scoped credential interface without using a real account.
const secrets=new Map();
const secretStore={
  get:async key=>secrets.get(key),
  set:async(key,value)=>{secrets.set(key,value);},
  require:async key=>{assert.ok(secrets.has(key),'Missing owned fixture credential');return secrets.get(key);},
};
const context={profile:{name:'default',values:{}},environment:{PATH:process.env.PATH},
  signal:new AbortController().signal,fetch,secrets:secretStore};
let owner,receipt;
try {
  const inputs=await nativeInputs({java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']});
  await nativeHelpers(root,inputs);
  owner=new GhidraServer(root,inputs,context);
  const binding=await owner.ensure();assert.equal(binding.mode,'local');
  const resumed=new GhidraServer(root,inputs,context);assert.deepEqual(await resumed.ensure(),binding);
  secrets.set('readerPassword',secrets.get(binding.readerSecret));secrets.set('publisherPassword',secrets.get(binding.publisherSecret));
  const externalContext={...context,profile:{name:'external',values:{server:binding.origin,repository:binding.repository,
    readerUser:binding.readerUser,publisherUser:binding.publisherUser}}};
  const external=new GhidraServer(join(root,'external'),inputs,externalContext);
  assert.equal((await external.ensure()).mode,'external');await external.stop();
  assert.deepEqual(await new GhidraServer(root,inputs,context).ensure(),binding);
  await assert.rejects(new GhidraServer(root,inputs,externalContext).ensure(),/original binding/);
  const token=secrets.get(binding.tokenSecret);
  secrets.set(binding.tokenSecret,'wrong-owned-token');
  await assert.rejects(new GhidraServer(root,inputs,context).stop(),/identity was not verified/);
  secrets.set(binding.tokenSecret,token);
  assert.deepEqual(await new GhidraServer(root,inputs,context).ensure(),binding);
  const swapped=new Map(secrets);
  swapped.set('readerPassword',secrets.get(binding.publisherSecret));swapped.set('publisherPassword',secrets.get(binding.readerSecret));
  const wrongAuthority={...externalContext,profile:{...externalContext.profile,values:{...externalContext.profile.values,
    readerUser:binding.publisherUser,publisherUser:binding.readerUser}},secrets:{...secretStore,
    require:async key=>{assert.ok(swapped.has(key));return swapped.get(key);}}};
  await assert.rejects(new GhidraServer(join(root,'wrong-authority'),inputs,wrongAuthority).ensure(),/could not be verified/);
  await owner.stop();const after=await owner.ensure();assert.equal(after.repository,binding.repository);
  assert.notEqual(after.pid,binding.pid);
  receipt={schema:1,scope:'owned local bootstrap and external profile authority proof',localBootstrap:true,
    strongCredentialsBeforeListener:true,readerReadOnly:true,publisherAdmin:true,ownedIdentityVerified:true,
    wrongTokenCannotStopServer:true,wrongAuthorityRejected:true,externalProfile:true,externalStopDoesNotStopServer:true,
    wrongProfileRejected:true,restartPreservesRepository:true,ghidra:inputs.ghidraVersion,java:'21',node:process.versions.node,
    mcpJarSha256:pinnedMcpJar,runtimeFingerprint:inputs.fingerprint,
    limitations:['server/bootstrap only; no combined session facade acceptance','synthetic credential interface; Factory credential-store integration is a later installed CLI gate']};
} catch(error) {
  console.error(error.message);console.error('Owned fixture retained for diagnostics:',root);process.exitCode=1;
} finally {await owner?.stop();}
if(receipt){await writeFile(join(root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
