// Native saved-effect cases for structural edits. All inputs/processes/storage are owned fixtures.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;
  else if(arg.startsWith('--')&&process.argv[i+1])options[arg.slice(2)]=process.argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const sourceFiles=['src/cli.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let context,native,fixtureWorkspace;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){int y=0;for(int i=0;i<4;i++)y+=x+i;return y+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const invoke=(args)=>f.json(app,['ghidra','server',...args]);
  assert.equal((await invoke(['status'])).connected,false);
  const connected=await invoke(['connect','--request-id','connect']);assert.equal(connected.connected,true);
  const name='owned_administration_fixture';
  const created=await invoke(['repositories','create','--repository',name,'--request-id','create']);assert.equal(created.state,'created');
  assert.deepEqual(await invoke(['repositories','create','--repository',name,'--request-id','create']),created);
  assert.ok((await invoke(['repositories','list'])).repositories.includes(name));
  assert.equal((await invoke(['repositories','files','--repository',name])).files.length,0);
  const users=await invoke(['admin','users']);assert.ok(users.users.some(user=>user.name==='reader'));
  await invoke(['admin','set-permissions','--repository',name,'--user','reader','--access','read_only','--request-id','permission']);
  const acl=await invoke(['admin','permissions','--repository',name]);assert.ok(acl.users.some(user=>user.name==='reader'&&user.access===0));assert.ok(acl.users.some(user=>user.name==='publisher'&&user.access===2));
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),snapshot=fixtureWorkspace.context(a).workingSnapshot;
  const inputs=await nativeInputs(values),classes=await (await import('../skills/ghidra-coordinator/dist/src/native-inputs.js')).nativeHelpers(fixtureWorkspace.directory,inputs);
  const fixtureClasses=join(f.root,'fixture-classes');await mkdir(fixtureClasses);
  await exec(join((await import('node:path')).dirname(inputs.java),'javac'),['-cp',classes+(await import('node:path')).delimiter+inputs.classpath,'-d',fixtureClasses,new URL('./fixtures/InsightAdministrativeFixture.java',import.meta.url).pathname]);
  const server=new GhidraServer(fixtureWorkspace.directory,inputs,context),binding=await server.ensure(),environment={...process.env,...await server.credentials(binding,'publisher')};
  const prepare=async(mode)=>{
    const result=await exec(inputs.java,['-Djava.awt.headless=true','-Dghidra.home='+inputs.ghidraHome,'-Duser.home='+f.root,'-cp',fixtureClasses+(await import('node:path')).delimiter+classes+(await import('node:path')).delimiter+inputs.classpath,'db.InsightAdministrativeFixture',name,mode,'program',await fixtureWorkspace.artifacts.verify(snapshot)],{env:environment,timeout:60000,maxBuffer:262144});return JSON.parse(result.stdout);
  };
  const first=await prepare('create');assert.ok(first.checkoutId);
  assert.equal((await invoke(['repositories','file','--repository',name,'--path','/program'])).file.version,1);
  assert.equal((await invoke(['history','--repository',name,'--path','/program'])).versions.length,1);
  assert.ok((await invoke(['checkouts','--repository',name])).checkouts.some(item=>item.id===first.checkoutId));
  assert.equal((await invoke(['admin','terminate-checkout','--repository',name,'--path','/program','--checkout-id',first.checkoutId,'--request-id','terminate'])).terminated,1);
  await prepare('checkout');assert.equal((await invoke(['admin','terminate-all-checkouts','--repository',name,'--request-id','terminate-all'])).terminated,1);
  assert.equal((await invoke(['checkouts','--repository',name])).checkouts.length,0);
  assert.equal((await invoke(['disconnect','--request-id','disconnect'])).connected,false);assert.equal((await invoke(['status'])).connected,false);
  assert.equal((await invoke(['connect','--request-id','reconnect'])).connected,true);
  assert.ok((await invoke(['repositories','list'])).repositories.includes(name));
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native configured-server administration',repositories:true,filesAndHistory:true,usersAndAclReadback:true,checkoutsAndVerifiedTermination:true,retryDoesNotCreateAgain:true,reconnectPreservesRepositories:true,
   ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:true,
   limitations:['source Factory fixture and synthetic credentials','unknown external outcomes, external profile and final installed matrix need further acceptance']};
}catch(error){console.error('Owned administration diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
