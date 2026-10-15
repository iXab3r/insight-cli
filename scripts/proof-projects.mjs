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
const sourceFiles=['src/projects.ts','references/native/InsightProjectFiles.java','src/cli.ts','src/lifecycle.ts','src/utility.ts','src/administration.ts','src/workspace.ts','src/cross.ts','src/cross-results.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightServerAdministration.java','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
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
  const invoke=(name,args=[])=>f.json(app,['ghidra','projects',name,...args]);
  assert.equal((await invoke('list')).count,0);
  const select=['--project','first'];
  const createArgs=[...select,'--request-id','create-project'];
  const created=await invoke('create',createArgs);assert.equal(created.state,'ready');assert.deepEqual(await invoke('create',createArgs),created);
  assert.equal((await invoke('list')).count,1);
  assert.equal((await invoke('open',select)).state,'ready');assert.equal((await invoke('info',select)).project,'first');
  await invoke('create-folder',[...select,'--path','/research']);await invoke('create-folder',[...select,'--path','/moved']);
  const a=await f.json(app,['ghidra','open',exe,'--session','new']);
  await f.json(app,['ghidra','comments','set','--session',a.session,'--target',a.target,'--address','140001000','--kind','eol','--text','exported private']);
  const output=join(f.root,'private.gzf'),exportArgs=['ghidra','program','export','--session',a.session,'--target',a.target,'--output',output,'--request-id','export'];
  const exported=await f.json(app,exportArgs);assert.equal(exported.state,'exported');assert.deepEqual(await f.json(app,exportArgs),exported);
  const imported=await f.json(app,['ghidra','program','import',...select,'--input',output,'--path','/research/program','--request-id','import']);assert.equal(imported.file.path,'/research/program');
  const files=await invoke('files',[...select,'--path','/research']);assert.equal(files.items.length,1);assert.equal(files.items[0].type,'Program');
  assert.equal((await invoke('move-file',[...select,'--path','/research/program','--destination','/moved'])).path,'/moved/program');
  assert.equal((await invoke('move-folder',[...select,'--path','/research','--destination','/moved'])).path,'/moved/research');
  const archive=join(f.root,'first.gar'),archived=await invoke('archive',[...select,'--output',archive,'--request-id','archive']);assert.ok(archived.size>0);
  await invoke('restore',['--project','restored','--input',archive,'--request-id','restore']);
  const restored=await invoke('files',['--project','restored','--path','/moved']);assert.equal(restored.items.length,2);
  await invoke('delete-file',[...select,'--path','/moved/program']);assert.equal((await invoke('files',['--project','restored','--path','/moved'])).items.length,2);
  assert.equal((await invoke('close',select)).state,'closed');await invoke('open',select);
  assert.equal((await invoke('delete',select)).state,'deleted');assert.deepEqual((await invoke('list')).items,[{project:'restored'}]);
  assert.equal((await f.json(app,['ghidra','comments','get','--session',a.session,'--target',a.target,'--address','140001000','--kind','eol'])).text,'exported private');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native project lifecycle and files',createOpenCloseDelete:true,foldersAndMoves:true,programExportImport:true,archiveRestore:true,privateContextPreserved:true,restoredProjectIndependent:true,retriesRecorded:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:true,
    limitations:['source Factory fixture and synthetic credentials','unknown project outcome reconciliation and final installed matrix require acceptance']};
}catch(error){console.error('Owned project diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
