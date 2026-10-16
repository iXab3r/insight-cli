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
  const otherDir=join(f.root,'second input');await mkdir(otherDir);const secondExe=join(otherDir,'fixture.exe');
  await writeFile(c,'__declspec(noinline) int first(int x){int y=0;for(int i=0;i<4;i++)y+=x+i;return y+23;}\nint main(void){return first(2); }\n');
  await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
  await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+secondExe,obj]);
  const d=await f.json(app,['ghidra','open',secondExe,'--session',a.session]);assert.notEqual(d.target,a.target);
  const select=who=>['--session',who.session,'--target',who.target],pair=(who,other)=>[...select(who),'--other-session',other.session,'--other-target',other.target],at='0x140001000';
  await f.json(app,['ghidra','functions','rename',...select(a),'--address',at,'--name','private_first']);
  const compare=await f.json(app,['ghidra','documentation','compare',...pair(a,b)]);assert.equal(compare.value.programs.length,2);assert.ok(compare.value.programs.every(p=>p.session&&p.target));completed.push('/compare_programs_documentation');
  const diff=await f.json(app,['ghidra','functions','diff',...pair(a,b),'--address-a',at,'--address-b',at]);
  assert.equal(diff.value.function_a.name,'private_first');assert.equal(diff.value.function_b.name,'first');assert.ok(diff.value.summary.body_equal>0);
  assert.equal(diff.value.summary.body_added,0);assert.equal(diff.value.summary.body_removed,0);completed.push('/diff_functions');
  const fuzzy=await f.json(app,['ghidra','documentation','find-similar-functions-fuzzy',...pair(a,b),'--function',at,'--threshold','0.2']);assert.ok(fuzzy.value.matches.some(match=>match.name==='first'));completed.push('/find_similar_functions_fuzzy');
  const bulk=await f.json(app,['ghidra','documentation','bulk-fuzzy-match',...pair(a,d),'--threshold','0.2']);assert.ok(bulk.value.matches.length);completed.push('/bulk_fuzzy_match');
  for(const result of [compare,diff,fuzzy,bulk]){assert.equal(result.session,a.session);assert.equal(result.target,a.target);assert.ok(result.other);assert.ok(!JSON.stringify(result).includes('__insight_peer_'));}
  const reverse=await Promise.all([f.json(app,['ghidra','functions','diff',...pair(a,b),'--address-a',at,'--address-b',at]),f.json(app,['ghidra','functions','diff',...pair(b,a),'--address-a',at,'--address-b',at])]);assert.equal(reverse.length,2);
  assert.equal((await f.json(app,['ghidra','functions','get',...select(b),'--address',at])).name,'first');
  assert.equal((await f.json(app,['ghidra','functions','get',...select(d),'--address',at])).name,'first');
  for(const who of [a,b,d]){const status=await f.json(app,['sessions','status',who.session,'--target',who.target]);assert.equal(status.ghidra.pendingChanges,who===a?1:0);}
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native explicit cross-target reads',operations:completed,privateSourceSelected:true,otherContextUnchanged:true,
    twoEqualFilenames:true,opposingCallersComplete:true,logicalScopesOnly:true,bundledRuntime:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,
    limitations:['source Factory fixture and synthetic credentials','documentation transfer and failure cleanup pending','remaining variants and final installed acceptance required']};
}catch(error){console.error('Owned cross-target fixture diagnostics:',f.root);console.error('Queries completed:',completed);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
