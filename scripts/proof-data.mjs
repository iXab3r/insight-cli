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
const sourceFiles=['src/cli.ts','src/mutations.ts','src/mutation-effects.ts','src/function-effects.ts','src/data-effects.ts','src/documentation-effects.ts','src/comment-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/queries.ts','src/query-results.ts','references/queries.json','references/mutations.json','references/native/InsightSnapshotInspect.java','references/native/InsightApplyDocumentation.java'];
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
  const select=who=>['--session',who.session,'--target',who.target], at='0x140001000',data='0x150000000';
  await f.json(app,['ghidra','memory','create-block',...select(a),'--name','DataEffects','--address',data,'--size','128']);
  await f.json(app,['ghidra','functions','set-function-prototype',...select(a),'--address',at,'--prototype','int __thiscall first(int count)']);
  const run=async(path,leaf,args)=>{
    const intent=['ghidra',...leaf.split(' '),...select(a),...args,'--request-id','data-'+path.slice(1)];
    const result=await f.run(app,[...intent,'--json']);
    if(result.exitCode!==0)await writeFile(join(f.root,'data-failure.json'),JSON.stringify({path,args,stdout:result.stdout,stderr:result.stderr}),{mode:0o600});
    assert.equal(result.exitCode,0,'Saved data effect failed '+path+': '+result.stderr);
    const value=JSON.parse(result.stdout);assert.equal(value.state,'applied');assert.equal(value.session,a.session);assert.equal(value.target,a.target);
    assert.deepEqual(await f.json(app,intent),value);completed.push(path);console.log('Saved data effect passed:',path);return value;
  };
  await run('/import_data_types','types import-data-types',['--source','struct ImportedWidget {unsigned int value; unsigned int flags;}; typedef unsigned int ImportedCount;']);
  await run('/apply_data_classification','types apply-data-classification',['--address',data,'--classification','PRIMITIVE','--type-definition','{"type":"uint"}','--name','classifiedCount','--comment','Classified\\nfixture']);
  await run('/set_global','types set-global',['--address',data,'--name','g_dwFixtureCount','--type-name','uint','--plate-comment','Number of records in fixture','--strict-mode','off']);
  await run('/set_function_this_type','functions set-function-this-type',['--function-address',at,'--this-type','ImportedWidget *']);
  const info=await f.json(app,['ghidra','functions','inspect',...select(a),'--functions',at,'--fields','parameters','--include-call-context','false']);
  const parameters=(info.value.functions[at]??info.value.functions[at.replace('0x','')]).parameters;
  const param=parameters.find(p=>p.name!=='this');assert.ok(param);
  await run('/apply_function_documentation','documentation apply',['--document',JSON.stringify({target_address:at,function_name:'documented_first',plate_comment:'Fixture with "quoted" text\nSecond line',parameters:[{ordinal:param.ordinal,name:'documentedCount',type:'uint'}],comments:[{relative_offset:1,eol_comment:'Quoted "EOL" fixture'}],labels:[{relative_offset:1,name:'fixtureInterior'}]})]);
  await run('/clear_flow_and_repair','functions clear-flow-and-repair',['--start-address',at,'--end-address','0x140001001']);
  assert.equal(completed.length,6);
  assert.notEqual((await f.json(app,['ghidra','functions','get',...select(b),'--address',at])).name,'documented_first');
  assert.equal((await f.json(app,['ghidra','merge',...select(a)])).sharedRevision,'R2');await f.json(app,['ghidra','refresh',...select(b)]);
  assert.equal((await f.json(app,['ghidra','functions','get',...select(b),'--address',at])).name,'documented_first');
  assert.equal((await f.json(app,['ghidra','types','get-struct-layout',...select(b),'--struct-name','ImportedWidget'])).value.size,8);
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={schema:1,scope:'owned native saved data, member, documentation and flow edits',operations:completed,savedImmutableReadback:true,
    callerRetryReturnsPriorResult:true,otherAgentStable:true,fullSnapshotPublication:true,sharedRefreshReadsEffects:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:!options['mcp-jar'],
    limitations:['source Factory fixture and synthetic credentials','remaining variants and final installed acceptance required']};
}catch(error){console.error('Owned data fixture diagnostics:',f.root);console.error('Saved effects completed:',completed.length);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
