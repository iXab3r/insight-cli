// Positive native read cases on one owned synthetic PE; fixture setup is not editing coverage.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++) {
  const arg=process.argv[i];if(arg==='--ack-disposable')options.ack=true;
  else if(arg.startsWith('--')&&process.argv[i+1])options[arg.slice(2)]=process.argv[++i];else throw Error('Invalid query proof argument');
}
assert.equal(options.ack,true);assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));
for(const key of ['java','ghidra-home','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const sourceFiles=['src/cli.ts','src/queries.ts','src/query-results.ts','src/json.ts','src/transport.ts','src/scripts.ts','src/research.ts','src/contexts.ts','src/server.ts','src/native-inputs.ts','src/workspace.ts','references/queries.json','references/native/InsightSnapshotInspect.java'];
const sourceHashes=Object.fromEntries(await Promise.all(sourceFiles.map(async file=>[file,createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex')])));
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']},
  f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
let native,workspace,context;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
  const response=await fetch(...args);let result;try{result=await response.clone().json();}catch{}
  if(!response.ok||result?.error||result?.success===false)await writeFile(join(f.root,'backend-failure.json'),JSON.stringify({path:new URL(args[0]).pathname,result}),{mode:0o600});
  return response;
}},backend:async(w,c)=>{
  workspace=w;context=c;native=new GhidraContexts(w,await nativeInputs(values),c);return native;
}}));
const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);
const dep=join(dir,'dep.c'),depObj=join(dir,'dep.obj'),dll=join(dir,'FixtureDepot.dll'),lib=join(dir,'FixtureDepot.lib');
await writeFile(dep,'__declspec(dllexport) int fixture_api(int x){return x+1;}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',dep,'-o',depObj]);
await exec(options.lld,['/dll','/noentry','/nodefaultlib','/out:'+dll,'/implib:'+lib,depObj]);
const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
await writeFile(c,'struct Record {unsigned count; unsigned flags;};\n__declspec(dllexport) struct Record sample={17,3};\n__declspec(dllimport) int fixture_api(int);\nconst char config_text[]="fixture/config.json";\n__declspec(noinline) unsigned first(struct Record *r,unsigned x){return r->count+x;}\n__declspec(noinline) unsigned hash(const char *s){unsigned h=0;for(;*s;s++)h+=(unsigned char)*s;return h;}\nint main(void){return first(&sample,fixture_api(2))+config_text[0]+hash("A");}\n');
await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:hash','/export:main','/out:'+exe,obj,lib]);
const completed=[],results={},failures=[];let receipt;
try {
  const selected=await f.json(app,['ghidra','open',exe,'--session','new']),selectors=['--session',selected.session,'--target',selected.target];
  const first=await native.call(selected,'/get_functions',{functions:'first',fields:'entry_point',include_call_context:false}),
    hash=await native.call(selected,'/get_functions',{functions:'hash',fields:'entry_point',include_call_context:false});
  const at=first.functions.first.entry_point,hashAt=hash.functions.hash.entry_point;
  const exports=await native.call(selected,'/list_program_items',{kind:'exports',limit:100,offset:0});
  const sample=exports.items.find(item=>item.name==='sample');assert.ok(sample,'Fixture global export missing');const sampleAt=sample.address;
  const external=await native.call(selected,'/list_program_items',{kind:'external_locations',limit:100,offset:0});
  const location=external.items.find(item=>item.name==='fixture_api');assert.ok(location,'Fixture external location missing');
  await f.json(app,['ghidra','types','create-struct',...selectors,'--name','FixtureRecord','--fields','[{"name":"count","type":"uint"},{"name":"flags","type":"uint"}]']);
  await f.json(app,['ghidra','functions','set-function-prototype',...selectors,'--address',at,'--prototype','unsigned int first(FixtureRecord *record, unsigned int count)']);
  await native.call(selected,'/apply_data_type',{address:sampleAt,type_name:'FixtureRecord',strict_mode:'off'});
  await native.call(selected,'/create_enum',{name:'FixtureEnum',values:{One:1,Two:2},size:4});
  await native.call(selected,'/create_property_map',{name:'FixtureProperties',type:'string'});
  await native.call(selected,'/set_property',{map:'FixtureProperties',address:at,value:'fixture value'});
  await native.call(selected,'/set_bookmark',{address:at,category:'Fixture',comment:'Owned query fixture'});
  const saved=await native.saved(selected),before=workspace.context(selected);
  workspace.saveContext(selected,before.generation,{workingSnapshot:saved,complexChanges:[...before.complexChanges,'query_fixture_setup']});
  const pcode=await native.call(selected,'/get_function_pcode',{function:at,granularity:'high'});
  const anchor=pcode.high_pcodes.find(op=>op.output&&op.seq?.address);assert.ok(anchor,'Fixture P-code anchor missing');
  const common={function:at,function_name:'first',target_function:'first',start_function:'main',end_function:'first',
    address:at,start_address:at,variable:'record',criteria:'any',pattern:'first',direction:'ascending',struct_address:sampleAt,
    struct_name:'FixtureRecord',type_name:'FixtureRecord',enum_name:'FixtureEnum',category:'all',
    prototype:'unsigned int first(FixtureRecord *record, unsigned int count)',calling_convention:'__cdecl',class_name:'FixtureRecord',
    kind:'functions',map:'FixtureProperties',xref_sources:[at],hash_function_address:hashAt,string_register:'RCX',target_hash:'0x41',
    candidates:['A','BC'],registers:{RCX:'0x'+sampleAt.replace(/^0x/,''),RDX:'2'},memory:[]};
  const overrides={
    '/analyze_dataflow':{address:anchor.seq.address,variable:'',direction:'backward'},
    '/analyze_global_completeness':{address:sampleAt},'/audit_global':{address:sampleAt},'/validate_data_type':{address:sampleAt},
    '/analyze_struct_field_usage':{address:sampleAt},'/get_functions':{functions:'first',fields:'entry_point,signature',include_call_context:false},
    '/get_external_location':{address:location.address_full??location.address},'/get_function_call_graph':{direction:'both'},
    '/search_byte_patterns':{pattern:'48 83'},'/search_strings':{search_term:'config'},'/find_data_types':{pattern:'Fixture'},
    '/list_data_items_by_xrefs':{format:'json'},'/emulate_function':{return_registers:'RAX'},'/emulate_hash_batch':{result_register:'EAX'},
    '/list_program_items':{kind:'imports'},'/search_instructions':{mnemonic:'MOV'},
    '/suggest_field_names':{struct_size:8},'/get_type_size':{type_name:'FixtureRecord'},'/get_property':{address:at,map:'FixtureProperties'}};
  const catalog=JSON.parse(await readFile(new URL('../skills/ghidra-coordinator/references/queries.json',import.meta.url),'utf8'));
  for(const query of catalog.tools) {
    if(options.group&&!query.command.startsWith(options.group+' '))continue;
    const argumentsFor={};for(const p of query.params)if(p.required) {
      const input=overrides[query.path]?.[p.name]??common[p.name];
      assert.notEqual(input,undefined,'Missing owned case input '+query.path+' '+p.name);argumentsFor[p.name]=input;
    }
    if(query.path!=='/get_functions'&&query.params.some(p=>p.name==='function'))argumentsFor.function=at;
    if(query.params.some(p=>p.name==='address'))argumentsFor.address=at;
    Object.assign(argumentsFor,overrides[query.path]);
    const args=['ghidra',...query.command.split(' '),...selectors];
    for(const [name,input]of Object.entries(argumentsFor)) {
      const p=query.params.find(p=>p.name===name);assert.ok(p,'Unknown owned case input '+query.path+' '+name);
      args.push('--'+name.replaceAll('_','-'),['json','object','array','any'].includes(p.type)?JSON.stringify(input):String(input));
    }
    const outcome=await f.run(app,[...args,'--json']);
    if(outcome.exitCode!==0){await writeFile(join(f.root,'query-failure.json'),JSON.stringify({path:query.path,args,stdout:outcome.stdout,stderr:outcome.stderr},null,2),{mode:0o600});}
    if(outcome.exitCode!==0){failures.push({path:query.path,error:outcome.stderr});await writeFile(join(f.root,'query-failures.json'),JSON.stringify(failures,null,2),{mode:0o600});console.log('Owned query failed:',query.command);continue;}
    const result=JSON.parse(outcome.stdout);assert.equal(result.session,selected.session);assert.equal(result.target,selected.target);
    assert.notEqual(result.value,undefined);results[query.path]=result.value;completed.push(query.path);
    await writeFile(join(f.root,'query-results.json'),JSON.stringify(results,null,2),{mode:0o600});
    console.log('Owned query passed:',query.command);
  }
  await writeFile(join(f.root,'query-results.json'),JSON.stringify(results,null,2),{mode:0o600});
  await writeFile(join(f.root,'query-failures.json'),JSON.stringify(failures,null,2),{mode:0o600});
  assert.equal(failures.length,0,'Owned query contracts still failed: '+failures.map(f=>f.path).join(', '));
  if(!options.group) {
    assert.equal(completed.length,74);
    assert.equal(results['/analyze_control_flow'].function_name,'first');
    assert.equal(results['/analyze_dataflow'].function.name,'first');
    assert.equal(results['/analyze_for_documentation'].name,'first');
    assert.equal(results['/analyze_function_complete'].name,'first');
    assert.equal(results['/analyze_function_completeness'].function_name,'first');
    assert.ok(results['/get_function_pcode'].high_pcodes.length>0);
    assert.ok(results['/get_field_access_context'].examples.some(e=>e.function_name==='main'));
    assert.equal(results['/get_struct_layout'].size,8);assert.equal(results['/get_struct_layout'].fields[0].name,'count');
    assert.deepEqual(results['/get_enum_values'].values.map(v=>[v.name,v.value]),[['One',1],['Two',2]]);
    assert.equal(results['/get_type_size'].size,8);
    assert.ok(results['/find_data_types'].data_types.some(t=>t.name==='FixtureRecord'));
    assert.equal(results['/get_function_documentation'].function_name,'first');
    assert.equal(results['/get_function_documentation'].parameters[0].type,'FixtureRecord *');
    assert.equal(results['/emulate_function'].hit_return,true);assert.equal(results['/emulate_function'].registers.RAX,'0x13');
    assert.equal(results['/emulate_hash_batch'].resolved,true);assert.equal(results['/emulate_hash_batch'].best_match,'A');
    assert.equal(results['/get_external_location'].label,'fixture_api');
    assert.ok(results['/list_program_items'].items.some(i=>i.name==='fixture_api'));
    assert.equal(results['/get_property'].value,'fixture value');
    assert.ok(results['/list_properties'].entries.some(e=>e.value==='fixture value'));
    assert.ok(results['/list_bookmarks'].bookmarks.some(b=>b.comment==='Owned query fixture'));
    assert.ok(results['/search_strings'].matches.some(s=>JSON.stringify(s).includes('config.json')));
    assert.ok(results['/get_xrefs_to'].references.length>0);
    assert.ok(results['/get_address_spaces'].address_spaces.length>0);
    assert.equal(results['/get_functions'].functions.first.entry_point,at);
    assert.ok(results['/force_decompile'].decompiled.includes('first'));
    assert.ok(results['/list_scripts'].total>0);assert.ok(results['/list_scripts'].items.every(s=>s.script&&s.name&&s.origin));
  }
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  receipt={sourceHashes,schema:1,scope:'owned native scoped query contracts',queries:completed,ghidra:'12.1.2',java:'21',node:process.versions.node,
    mcpJarSha256:pinnedMcpJar,knownInputValuesAsserted:!options.group,
    limitations:['source Factory fixture and synthetic credentials','fixture setup does not establish editing coverage','variant/nested-output completion remains part of full coverage acceptance']};
} catch(error){console.error('Owned query fixture diagnostics:',f.root);console.error('Completed query cases:',completed.length);throw error;}
finally {await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
