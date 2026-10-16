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
const sourceFiles=['src/mutations.ts','src/mutation-effects.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/arguments.ts','src/json.ts','src/transport.ts','references/mutations.json','references/native/InsightSnapshotInspect.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let context,native;const completed=[];let receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}
  if(!response.ok||value?.error||value?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,value}),{mode:0o600});return response;
}},backend:async(workspace,c)=>{context=c;native=new GhidraContexts(workspace,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'__declspec(noinline) int first(int x){return x+17;}\nint main(void){return first(2);}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
try {
  const a=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']);
  const selectors=who=>['--session',who.session,'--target',who.target],at='0x140001000',data='0x150000000',label='0x150000020';
  await f.json(app,['ghidra','types','create-struct',...selectors(a),'--name','EditRecord','--fields','[{"name":"count","type":"uint"},{"name":"flags","type":"uint"}]']);
  await f.json(app,['ghidra','memory','create-block',...selectors(a),'--name','EditMemory','--address',data,'--size','64']);
  const run=async(path,command,args)=>{
    const intent=['ghidra',...command.split(' '),...selectors(a),...args,'--request-id','edit-'+path.slice(1)];
    const result=await f.run(app,[...intent,'--json']);
    if(result.exitCode!==0)await writeFile(join(f.root,'mutation-failure.json'),JSON.stringify({path,args,stdout:result.stdout,stderr:result.stderr}),{mode:0o600});
    assert.equal(result.exitCode,0,'Saved effect failed '+path+': '+result.stderr);
    const value=JSON.parse(result.stdout);assert.equal(value.state,'applied');assert.equal(value.session,a.session);assert.equal(value.target,a.target);
    assert.deepEqual(await f.json(app,intent),value,'Request retry must retrieve the prior mutation result');completed.push(path);console.log('Saved effect passed:',path);return value;
  };
  await run('/create_data_type_category','types create-data-type-category',['--category-path','/Editing']);
  await run('/create_enum','types create-enum',['--name','EditChoice','--size','8','--values','{"One":1,"Wide":"9223372036854775807"}']);
  await run('/create_derived_type','types create-derived-type',['--kind','typedef','--base-type','uint','--name','EditAlias']);
  await run('/create_function_signature','types create-function-signature',['--name','EditSignature','--return-type','uint','--parameters','[{"name":"count","type":"uint"}]']);
  await run('/create_union','types create-union',['--name','EditUnion','--fields','[{"name":"wide","type":"uint"},{"name":"small","type":"byte"}]']);
  await run('/clone_data_type','types clone-data-type',['--source-type','EditRecord','--new-name','CopiedRecord']);
  await run('/add_struct_field','types add-struct-field',['--struct-name','CopiedRecord','--field-name','extra','--field-type','byte']);
  await run('/modify_struct_field','types modify-struct-field',['--struct-name','CopiedRecord','--field-name','extra','--new-type','uchar','--new-name','extraFlag']);
  await run('/resize_struct','types resize-struct',['--name','CopiedRecord','--new-size','16']);
  await run('/remove_struct_field','types remove-struct-field',['--struct-name','CopiedRecord','--field-name','extraFlag']);
  await run('/move_data_type_to_category','types move-data-type-to-category',['--type-name','CopiedRecord','--category-path','/Editing']);
  await run('/rename_data_type','types rename-data-type',['--old-name','CopiedRecord','--new-name','RenamedRecord']);
  await run('/recreate_struct','types recreate-struct',['--name','RenamedRecord','--fields','[{"name":"value","type":"uint"}]','--force','true','--size','8']);
  await run('/delete_data_type','types delete-data-type',['--type-name','RenamedRecord']);
  await run('/resolve_duplicate_type','types resolve-duplicate-type',['--type-name','EditRecord']);
  await run('/apply_data_type','types apply-data-type',['--address',data,'--type-name','EditRecord']);
  await run('/create_property_map','program create-property-map',['--name','EditProperties','--type','long']);
  await run('/set_property','program set-property',['--map','EditProperties','--address',at,'--value','9223372036854775807']);
  await run('/remove_property','program remove-property',['--map','EditProperties','--address',at]);
  await run('/delete_property_map','program delete-property-map',['--name','EditProperties']);
  await run('/set_program_option','program set-program-option',['--group','Program Information','--name','FixtureCount','--type','int','--value','23']);
  await run('/remove_program_option','program remove-program-option',['--group','Program Information','--name','FixtureCount']);
  await run('/set_bookmark','program set-bookmark',['--address',at,'--category','Fixture','--comment','Saved bookmark']);
  await run('/delete_bookmark','program delete-bookmark',['--address',at,'--category','Fixture']);
  await run('/set_memory_block','memory set-block',['--block','EditMemory','--write','false','--volatile','true']);
  await run('/create_label','symbols create-label',['--address',label,'--name','fixtureLabel']);
  await run('/rename_symbol','symbols rename-symbol',['--symbol',label,'--kind','label','--old-name','fixtureLabel','--new-name','renamedLabel']);
  await run('/delete_label','symbols delete-label',['--address',label,'--name','renamedLabel']);
  await run('/add_memory_reference','xrefs add-memory-reference',['--from-address',at,'--to-address',data,'--operand-index','0']);
  await run('/remove_reference','xrefs remove-reference',['--from-address',at,'--to-address',data,'--operand-index','0']);
  await run('/set_image_base','program set-image-base',['--address','0x130000000']);
  assert.equal(completed.length,31);
  const old=await f.run(app,['ghidra','types','get-struct-layout',...selectors(b),'--struct-name','EditRecord','--json']);assert.notEqual(old.exitCode,0);
  const merged=await f.json(app,['ghidra','merge',...selectors(a)]);assert.equal(merged.sharedRevision,'R2');
  await f.json(app,['ghidra','refresh',...selectors(b)]);
  assert.equal((await f.json(app,['ghidra','types','get-struct-layout',...selectors(b),'--struct-name','EditRecord'])).value.size,8);
  const memory=await f.json(app,['ghidra','memory','list',...selectors(b)]);assert.ok(memory.value.items.some(i=>i.name==='EditMemory'&&i.writable===false));
  receipt={schema:1,scope:'owned native saved structural mutation effects',operations:completed,savedImmutableReadback:true,
    callerRetryReturnsPriorResult:true,otherAgentStable:true,fullSnapshotPublication:true,sharedRefreshReadsEffects:true,
    ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,sourceHashes,bundledRuntime:!options['mcp-jar'],
    limitations:['source Factory fixture and synthetic credentials','remaining program edit groups and result variants still require acceptance']};
}catch(error){console.error('Owned mutation fixture diagnostics:',f.root);console.error('Saved effects completed:',completed.length);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
