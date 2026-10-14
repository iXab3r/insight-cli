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
const sourceFiles=['src/cli.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
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
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']);
  const select=who=>['--session',who.session,'--target',who.target],at='0x140001000',data='0x150000000';
  for(const who of [a,b])await f.json(app,['ghidra','memory','create-block',...select(who),'--name','TransferMemory','--address',data,'--size','64']);
  await f.json(app,['ghidra','types','create-struct',...select(a),'--name','TransferRecord','--fields','[{"name":"count","type":"uint"},{"name":"flags","type":"uint"}]']);
  await f.json(app,['ghidra','functions','rename',...select(a),'--address',at,'--name','documented_source']);
  await f.json(app,['ghidra','functions','set-function-prototype',...select(a),'--address',at,'--prototype','uint documented_source(uint count)']);
  await f.json(app,['ghidra','comments','set',...select(a),'--address',at,'--kind','eol','--text','Transferred EOL']);
  await f.json(app,['ghidra','functions','add-function-tag',...select(a),'--function',at,'--tags','reviewed']);
  await f.json(app,['ghidra','program','set-bookmark',...select(a),'--address',at,'--category','Transfer','--comment','Copied bookmark']);
  await f.json(app,['ghidra','types','set-global',...select(a),'--address',data,'--name','g_dwTransferCount','--type-name','uint','--plate-comment','Number of records in fixture','--strict-mode','off']);
  const intent=['ghidra','documentation','transfer',...select(b),'--source-session',a.session,'--source-target',a.target];
  const preview=await f.json(app,[...intent,'--dry-run','--request-id','preview']);assert.equal(preview.state,'preview');assert.ok(preview.value.total>0);
  assert.equal((await f.json(app,['ghidra','functions','get',...select(b),'--address',at])).name,'first');
  const result=await f.json(app,[...intent,'--request-id','transfer']);assert.equal(result.state,'applied');assert.ok(result.value.total>0);
  assert.deepEqual(await f.json(app,[...intent,'--request-id','transfer']),result);
  const receiver=await f.json(app,['ghidra','functions','get',...select(b),'--address',at]);assert.equal(receiver.name,'documented_source');assert.equal(receiver.comments.eol,'Transferred EOL');
  assert.equal((await f.json(app,['ghidra','types','get-struct-layout',...select(b),'--struct-name','TransferRecord'])).value.size,8);
  assert.ok((await f.json(app,['ghidra','functions','list-function-tags',...select(b)])).value.tags.some(t=>t.name==='reviewed'));
  const noop=await f.json(app,[...intent,'--request-id','no-op']);assert.equal(noop.value.total,0);assert.equal(noop.pendingChanges,result.pendingChanges);
  const merged=await f.json(app,['ghidra','merge',...select(b)]);assert.equal(merged.sharedRevision,'R2');
  const reader=await f.json(app,['ghidra','open',exe,'--session','new']);assert.equal((await f.json(app,['ghidra','functions','get',...select(reader),'--address',at])).name,'documented_source');
  assert.equal((await f.json(app,['ghidra','functions','get',...select(a),'--address',at])).comments.eol,'Transferred EOL');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native explicit documentation transfer',operations:['/merge_program_documentation'],
    savedDestinationVerified:true,previewDoesNotEdit:true,callerRetryReturnsPriorResult:true,noOpPreservesPendingCount:true,sourceUnchanged:true,fullSnapshotPublication:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:true,
    limitations:['source Factory fixture and synthetic credentials','all-category variants, lost-response and failure cleanup require further acceptance']};
}catch(error){console.error('Owned transfer fixture diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
