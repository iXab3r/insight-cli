// Native result variants on an owned synthetic PE; fixture setup is not editing coverage.
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
  const invoke=async(label,command,args,verify)=>{
    const result=await f.run(app,['ghidra',...command.split(' '),...selectors,...args,'--json']);
    try{assert.equal(result.exitCode,0,result.stderr);const value=JSON.parse(result.stdout);assert.equal(value.session,selected.session);assert.equal(value.target,selected.target);verify(value.value);completed.push(label);console.log('Variant PASS:',label);}
    catch(error){failures.push({case:label,error:error.message});console.log('Variant FAIL:',label);}
  };
  await f.json(app,['ghidra','comments','set',...selectors,'--address',at,'--kind','eol','--text','Owned query variant']);
  for(const kind of ['plate','pre','eol','post','repeatable'])await f.json(app,['ghidra','comments','set',...selectors,'--address',hashAt,'--kind',kind,'--clear']);
  await invoke('comments multiple addresses','comments inspect',['--addresses',at+','+hashAt],v=>{assert.equal(v.results.length,2);assert.equal(v.requested,2);assert.ok(v.results.some(row=>row.eol==='Owned query variant'));});
  await invoke('comments filtered bulk','comments inspect',['--addresses',at+','+hashAt,'--only-with-comments','true'],v=>{assert.equal(v.results.length,1);assert.equal(v.with_comments,1);assert.equal(v.results[0].eol,'Owned query variant');});
  await invoke('type categories','types find-data-types',['--categories','true'],v=>{assert.ok(v.categories.length);});
  await invoke('hash inventory','documentation get-function-hash',[],v=>{assert.ok(v.functions.some(f=>f.function_name==='first'||f.name==='first'));});
  await invoke('program option group','program get-program-options',['--group','Program Information'],v=>{assert.ok(v.options.some(o=>o.name==='Executable SHA256'));});
  for(const format of [undefined,'text','json'])await invoke('data format '+(format??'default'),'listing list-data-items-by-xrefs',format?['--format',format]:[],v=>{assert.ok(v.data_items.some(row=>row.name==='sample'&&row.type==='FixtureRecord'&&row.xref_count>=0));assert.equal(v.count,v.data_items.length);});
  for(const format of ['edges','json_edges','dot','mermaid','adjacency'])await invoke('call graph '+format,'xrefs get-full-call-graph',['--format',format],v=>{
    assert.ok(JSON.stringify(v).includes('first'));
    if(format==='json_edges'){assert.ok(v.edges.some(e=>e.callee_name==='first'&&e.callee_addr===at));assert.equal(v.edge_count,v.edges.length);}
    else if(['dot','mermaid'].includes(format))assert.equal(typeof v.diagram,'string');
    else if(format==='adjacency')assert.ok(v.adjacency&&Object.keys(v.adjacency).length);
  });
  for(const type of ['summary','path','cycles','strongly_connected','entry_points','leaf_functions'])await invoke('call analysis '+type,'xrefs analyze-call-graph',['--start-function','main','--end-function','first','--analysis-type',type],v=>{
    if(type==='path'){assert.equal(v.path_found,true);assert.ok(v.path.some(p=>p.startsWith('first@')));}
    else if(type==='cycles')assert.equal(v.cycles_found,0);
    else if(type==='strongly_connected'){assert.equal(v.non_trivial_sccs,0);assert.ok(Array.isArray(v.components));}
    else if(type==='entry_points')assert.ok(v.entry_points.some(row=>row.name.startsWith('main@')));
    else if(type==='leaf_functions')assert.ok(v.leaf_functions.some(row=>row.name.startsWith('first@')));
    else assert.ok(v.total_functions>1);
  });
  await invoke('multiple function fields','functions inspect',['--functions','first,hash','--fields','entry_point,signature'],v=>{assert.equal(v.functions.first.entry_point,at);assert.equal(v.functions.hash.entry_point,hashAt);assert.ok(v.functions.first.signature.includes('first'));});
  await invoke('multiple assembly contexts','xrefs get-assembly-context',['--xref-sources',JSON.stringify([at,hashAt])],v=>{assert.ok(v[at]);assert.ok(v[hashAt]);});
  await writeFile(join(f.root,'variant-results.json'),JSON.stringify({completed,failures},null,2),{mode:0o600});
  for(const file of sourceFiles)assert.equal(createHash('sha256').update(await readFile(new URL('../skills/ghidra-coordinator/'+file,import.meta.url))).digest('hex'),sourceHashes[file],'Proof source changed during execution');
  assert.equal(failures.length,0,'Query variants failed: '+failures.map(f=>f.case).join(', '));
  receipt={schema:1,scope:'owned native query output variants',cases:completed,sourceHashes,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,limitations:['source Factory fixture and synthetic credentials','bounded representative output variants, not exhaustive input combinations']};
} catch(error){console.error('Owned query variant diagnostics:',f.root);console.error('Variant failures:',JSON.stringify(failures));throw error;}
finally {await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
