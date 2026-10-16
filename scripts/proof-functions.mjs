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
const sourceFiles=['src/cli.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightSnapshotInspect.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
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
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']);
  const select=who=>['--session',who.session,'--target',who.target], at='0x140001000';
  await f.json(app,['ghidra','functions','set-function-prototype',...select(a),'--address',at,'--prototype','int first(int count)']);
  const run=async(path,leaf,args)=>{
    const intent=['ghidra',...(leaf.includes(' ')?leaf.split(' '):['functions',leaf]),...select(a),...args,'--request-id','function-'+path.slice(1)];
    const result=await f.run(app,[...intent,'--json']);
    if(result.exitCode!==0)await writeFile(join(f.root,'function-failure.json'),JSON.stringify({path,args,stdout:result.stdout,stderr:result.stderr}),{mode:0o600});
    assert.equal(result.exitCode,0,'Saved function effect failed '+path+': '+result.stderr);
    const value=JSON.parse(result.stdout);assert.equal(value.state,'applied');assert.equal(value.session,a.session);assert.equal(value.target,a.target);
    assert.deepEqual(await f.json(app,intent),value);completed.push(path);console.log('Saved function effect passed:',path);return value;
  };
  await run('/set_function_no_return','set-function-no-return',['--function-address',at,'--non-returning','true']);
  await run('/set_variable_type','set-variable-type',['--function-address',at,'--variable-name','count','--new-type','uint']);
  await run('/set_variable_storage','set-variable-storage',['--function',at,'--variable-name','count','--storage','ECX:4']);
  await run('/rename_variables','rename-variables',['--function',at,'--variable-renames','{"count":"quantity"}']);
  await run('/set_variables','set-variables',['--function',at,'--variables','{"quantity":{"name":"amount","type":"int"}}']);
  await run('/batch_rename_function_components','batch-rename-function-components',['--function',at,'--function-name','first_updated','--parameter-renames','{"amount":"inputCount"}','--local-renames','{}','--return-type','uint']);
  await run('/add_function_tag','add-function-tag',['--function',at,'--tags','reviewed,temporary','--tag-comments','{"reviewed":"Initial review"}']);
  await run('/set_function_tag_comment','set-function-tag-comment',['--name','reviewed','--comment','Verified review']);
  await run('/remove_function_tag','remove-function-tag',['--function',at,'--tags','temporary']);
  await run('/delete_function_tag','delete-function-tag',['--name','temporary']);
  await run('/clear_instruction_flow_override','clear-instruction-flow-override',['--address',at]);
  await run('/disassemble_bytes','disassemble-bytes',['--start-address',at,'--length','1']);
  await run('/delete_function','delete',['--function',at]);
  await run('/create_function','create',['--address',at,'--name','final_first']);
  const inline=await run('/run_script_inline','scripts run-inline',['--code','setPlateComment(toAddr("0x140001000"), "Inline fixture"); println("INLINE_OK");']);
  assert.ok(inline.value.output.includes('INLINE_OK'));
  const nativeRoot=join(f.appArguments.AppDataDirectory,'workspace','ghidra-native','context');
  // Resolve the selected context directly from its durable scope, rather than a program basename.
  // Fixture writes below affect only that owned context's script directory.
  const binding=JSON.parse(await readFile(join(nativeRoot,fixtureWorkspace.context(a).id,'current.json'),'utf8'));
  await mkdir(join(binding.root,'ghidra_scripts'),{recursive:true});
  await writeFile(join(binding.root,'ghidra_scripts','OwnedNamedFixture.java'),'import ghidra.app.script.GhidraScript;\npublic class OwnedNamedFixture extends GhidraScript {public void run() throws Exception {setPlateComment(toAddr("0x140001000"),"Named fixture");println("NAMED_OK");}}\n');
  const named=await run('/run_ghidra_script','scripts run',['--script-name','context:OwnedNamedFixture.java']);assert.ok(named.value.output.includes('NAMED_OK'));
  await run('/batch_set_comments','comments set-batch',['--address',at,'--decompiler-comments','[{"address":"0x140001001","comment":"Interior PRE"}]','--disassembly-comments','[{"address":"0x140001001","comment":"Interior EOL"}]','--plate-comment','Batch fixture']);
  await run('/clear_function_comments','comments clear-function',['--function',at]);
  await run('/batch_apply_documentation','analysis batch-apply-documentation',['--address',at,'--name','final_first','--prototype','int final_first(int count)','--variable-types','{}','--variable-renames','{}','--plate-comment','Documented fixture','--score','false']);
  const analyzers=await f.json(app,['ghidra','analysis','list-analyzers',...select(a)]);assert.ok(analyzers.value.analyzers.length);
  await run('/configure_analyzer','analysis configure-analyzer',['--name',analyzers.value.analyzers[0].name,'--enabled','false']);
  await run('/run_analysis','analysis run',[]);
  await run('/reanalyze','analysis reanalyze',[]);
  const region=await f.json(app,['ghidra','analysis','analyze-data-region',...select(a),'--address',at,'--max-scan-bytes','16','--include-boundary-detection','false']);assert.equal(region.value.byte_span,16);
  const bounds=await f.json(app,['ghidra','analysis','detect-array-bounds',...select(a),'--address',at,'--max-scan-range','16']);assert.equal(bounds.value.detection_method,'xref_analysis');
  assert.equal(completed.length,22);
  const old=await f.json(app,['ghidra','functions','get',...select(b),'--address',at]);assert.notEqual(old.name,'final_first');
  const merged=await f.json(app,['ghidra','merge',...select(a)]);assert.equal(merged.sharedRevision,'R2');
  await f.json(app,['ghidra','refresh',...select(b)]);
  assert.equal((await f.json(app,['ghidra','functions','get',...select(b),'--address',at])).name,'final_first');
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native saved function, batch, script and analysis effects',operations:completed,savedImmutableReadback:true,
    callerRetryReturnsPriorResult:true,otherAgentStable:true,fullSnapshotPublication:true,sharedRefreshReadsEffects:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:!options['mcp-jar'],
    limitations:['source Factory fixture and synthetic credentials','remaining edit groups and variants require acceptance']};
}catch(error){console.error('Owned function fixture diagnostics:',f.root);console.error('Saved effects completed:',completed.length);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
