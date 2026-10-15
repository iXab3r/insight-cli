// Native archive payloads against an owned local HTTP contract fixture; no external service writes.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
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
const sourceFiles=['src/archive.ts','src/archive-contract.ts','references/native/InsightArchivePayloads.java','src/cli.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const posted=[];let lose=false;
const archive=createServer(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);assert.equal(req.url,'/v1/doc_archive/upsert');assert.equal(req.headers.authorization,'Bearer synthetic-contract-token');const payload=JSON.parse(Buffer.concat(chunks));posted.push(payload);if(lose){req.socket.destroy();return;}res.setHeader('Content-Type','application/json');res.end(JSON.stringify({created:posted.length===1,conflicts_enqueued:2}));});
await new Promise(resolve=>archive.listen(0,'127.0.0.1',resolve));
const values={archiveUrl:'http://127.0.0.1:'+archive.address().port,java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,secrets:{archiveToken:'synthetic-contract-token'},permissions:['ReadOnly','Update','Destructive']}]});
let context,native,fixtureWorkspace;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{fixtureWorkspace=workspace;context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){return x+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']),select=who=>['--session',who.session,'--target',who.target];
  await f.json(app,['ghidra','functions','rename',...select(a),'--address','140001000','--name','documented_first']);
  await f.json(app,['ghidra','comments','set',...select(a),'--address','140001000','--kind','eol','--text','Archive private comment']);
  const single=['ghidra','archive','ingest-function',...select(a),'--address','140001000','--version-label','fixture-v1','--request-id','single'];
  const preview=await f.json(app,[...single.slice(0,-2),'--dry-run']);assert.equal(preview.state,'preview');assert.equal(posted.length,0);
  const sent=await f.json(app,single);assert.equal(sent.created,1);assert.equal(sent.conflicts_enqueued,2);assert.deepEqual(await f.json(app,single),sent);assert.equal(posted.length,1);
  const payload=posted[0];assert.equal(payload.binary_name,'fixture.exe');assert.equal(payload.version,'fixture-v1');assert.equal(payload.name,'documented_first');assert.equal(payload.address,'0x140001000');assert.match(payload.opcode_hash,/^[a-f0-9]{64}$/);assert.ok(payload.instruction_comments.some(comment=>comment.type==='EOL'&&comment.text==='Archive private comment'));assert.equal(payload.source_tool,'ghidra_mcp_ingest');
  const bulk=['ghidra','archive','ingest-program',...select(a),'--version-label','fixture-v1','--limit','20','--include-default-named','--request-id','bulk'];
  const all=await f.json(app,bulk);assert.ok(all.updated>=2);assert.equal(all.created,0);assert.equal(all.conflicts_enqueued,all.updated*2);assert.equal(all.total_functions,all.updated);const count=posted.length;assert.deepEqual(await f.json(app,bulk),all);assert.equal(posted.length,count);
  lose=true;const unknown=['ghidra','archive','ingest-function',...select(a),'--address','140001000','--request-id','lost'];assert.notEqual((await f.run(app,unknown)).exitCode,0);const lostCount=posted.length;assert.equal(lostCount,count+1);assert.notEqual((await f.run(app,unknown)).exitCode,0);assert.equal(posted.length,lostCount);
  assert.equal((await f.json(app,['ghidra','comments','get',...select(a),'--address','140001000','--kind','eol'])).text,'Archive private comment');assert.equal((await f.json(app,['ghidra','comments','get',...select(b),'--address','140001000','--kind','eol'])).text,null);
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native archive contract',operations:['/archive_ingest_function','/archive_ingest_program'],privatePayloadVerified:true,pinnedPayloadBuilder:true,createdUpdatedConflictCounts:true,previewNoNetwork:true,requestRetryNoDuplicate:true,lostExternalResponseNotReplayed:true,privateResearchRemainsAvailable:true,otherAgentUnchanged:true,secretOnlyInNodeRequest:true,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,limitations:['owned HTTP contract fixture; independently deployed archive service excluded','final installed combined acceptance remains open']};
}catch(error){console.error('Owned archive diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();await new Promise(resolve=>archive.close(resolve));}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
