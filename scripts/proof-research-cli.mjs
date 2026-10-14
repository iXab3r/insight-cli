// Factory CLI/API against owned native fixtures; complete installed IPC acceptance is separate.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={},argv=process.argv.slice(2);
for(let i=0;i<argv.length;i++){if(argv[i]==='--ack-disposable')options.ack=true;else if(argv[i].startsWith('--')&&argv[i+1])options[argv[i].slice(2)]=argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]),'Native proof is local only');
for(const key of ['ghidra-home','java','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
test('native Factory research facade',async t=>{
  const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']};
  // Keep the owned native diagnostics/receipt; cleanup below releases processes explicitly.
  const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
  const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);
  const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
  await writeFile(c,'const char message[]="config.json";\n__declspec(noinline) int first(int x){return x+message[x&1];}\nint main(void){return first(2);}\n');
  await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
  await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
  // Capture the fixture's scoped secret interface for receipt-verified local-server cleanup.
  let serverContext;
  const actual=f.createApplication(runtime=>createInsightCli({runtime,backend:async(workspace,context)=>{
    serverContext=context;
    const {GhidraContexts}=await import('../skills/ghidra-coordinator/dist/src/contexts.js');
    return new GhidraContexts(workspace,await nativeInputs(context.profile.values),context);
  }}));
  try {
    const a=await f.json(actual,['ghidra','open',exe,'--session','new','--request-id','open-A']);
    const b=await f.json(actual,['ghidra','open',exe,'--session','new']);
    assert.equal(a.target,b.target);assert.notEqual(a.session,b.session);assert.equal(a.state,'ready');
    assert.deepEqual(await f.json(actual,['ghidra','open',exe,'--session','new','--request-id','open-A']),a);
    const selected=['--session',a.session,'--target',a.target];
    const strings=await f.json(actual,['ghidra','strings','search',...selected,'--contains','config.json','--limit','10']);
    assert.ok(strings.items.length>0,'Native string search did not find the fixture data');
    const xrefs=await f.json(actual,['ghidra','xrefs','to',...selected,'--address',strings.items[0].address]);
    const from=xrefs.items.find(item=>item.function);assert.ok(from,'Native references did not provide a traversable function');
    const at=from.function.address;
    const before=await f.json(actual,['ghidra','functions','get',...selected,'--address',at]);
    await f.json(actual,['ghidra','functions','rename',...selected,'--address',at,'--name','LoadFixtureConfig','--request-id','rename-A']);
    const changed=await f.json(actual,['ghidra','comments','set',...selected,'--address',at,'--kind','eol','--text','Private native CLI finding','--request-id','comment-A']);
    assert.equal(changed.state,'applied');
    const readback=await f.json(actual,['ghidra','functions','get',...selected,'--address',at]);
    assert.equal(readback.name,'LoadFixtureConfig');assert.equal(readback.comments.eol,'Private native CLI finding');
    const decompiled=await f.json(actual,['ghidra','functions','decompile',...selected,'--address',at]);assert.ok(decompiled.code.includes('LoadFixtureConfig'));
    const responses=await f.rpc(actual,[['ghidra','functions','get',...selected,'--address',at],
      ['ghidra','functions','get','--session',b.session,'--target',b.target,'--address',at]]);
    assert.equal(responses[0].result.name,'LoadFixtureConfig');assert.equal(responses[1].result.name,before.name);
    assert.equal(responses[1].result.comments.eol,null);
    await f.json(actual,['ghidra','comments','set',...selected,'--address',at,'--kind','eol','--clear']);
    assert.equal((await f.json(actual,['ghidra','comments','get',...selected,'--address',at,'--kind','eol'])).text,null);
    const status=await f.json(actual,['sessions','status',a.session,'--target',a.target]);assert.equal(status.ghidra.pendingChanges,1);
    const receipt={schema:1,scope:'owned native Factory research commands',sessions:2,targets:1,
      openRetryRetainsSession:true,stringsXrefsFunctionsTraversable:true,renameAndCommentsReadback:true,
      savedPrivateEdits:true,otherAgentUnchanged:true,clearReturnsNull:true,jsonRpcSameScope:true,
      ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,
      limitations:['source-package Factory fixture transport and credential adapter; final installed IPC/credential/crash/full-catalog gates remain']};
    await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
  } catch(error) {console.error('Owned Factory fixture diagnostics:',f.root);throw error;}
  finally {
    // Application fixture cleanup stops only native context children it created.
    await actual.dispose();
    if(serverContext)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),serverContext).stop();
  }
});
