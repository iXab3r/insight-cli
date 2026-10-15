import {nativeProofGuard} from './native-proof-guard.mjs';
// Owned native Version Tracking, including moved/ambiguous/unmatched functions and restart.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {writeFile,mkdir} from 'node:fs/promises';import {join} from 'node:path';
import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];if(key==='--ack-disposable')options.ack=true;else if(key.startsWith('--')&&process.argv[i+1])options[key.slice(2)]=process.argv[++i];else throw Error('Invalid proof option');}
nativeProofGuard(options.ack);
for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key]);
const values={java:options.java,ghidraHome:options['ghidra-home']},f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let native,context,receipt;const cases=[],make=()=>f.createApplication(runtime=>createInsightCli({runtime,backend:async(w,c)=>{context=c;native=new GhidraContexts(w,await nativeInputs(values),c);return native;}}));let app=make();
const input=join(f.root,'inputs'),exec=promisify(execFile);await mkdir(input);
async function compile(name,functions){const source=join(input,name+'.c'),object=join(input,name+'.obj'),exe=join(input,name+'.exe');
 await writeFile(source,functions.map(([name,expression])=>`__declspec(noinline) int ${name}(int value){return ${expression};}`).join('\n')+'\nint main(void){return '+functions.map(([name])=>name+'(2)').join('+')+';}\n');
 await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);
 await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/opt:noicf',...functions.map(([name])=>'/export:'+name),'/out:'+exe,object]);return exe;}
const old=await compile('old',[['shared','value*7+3'],['dup_a','value+11'],['dup_b','value+11'],['removed','value^0x5a5a']]),
 updated=await compile('new',[['added','value==0?13:((value>>2)^(value*value+4))'],['renamed','value*7+3'],['dup_x','value+11'],['dup_y','value+11']]);
const select=s=>['--session',s.session,'--target',s.target];
async function run(s,path,args=[]){const command=['ghidra',...path.split(' '),...select(s),...args,'--json'],result=await f.run(app,command);
 if(result.exitCode){await writeFile(join(f.root,'failure.json'),JSON.stringify({command,...result}),{mode:0o600});throw Error('Native VT case failed '+path+': '+result.stderr);}return JSON.parse(result.stdout);}
function passed(name){cases.push(name);console.log('Native VT passed:',name);}
try{
 const source=await f.json(app,['ghidra','open',old,'--session','new']),destination=await f.json(app,['ghidra','open',updated,'--session',source.session]);
 const from=(await native.call(source,'/get_functions',{functions:'shared,dup_a,dup_b,removed',fields:'entry_point',include_call_context:false})).functions,
  to=(await native.call(destination,'/get_functions',{functions:'renamed,dup_x,dup_y,added',fields:'entry_point',include_call_context:false})).functions;
 assert.notEqual(from.shared.entry_point,to.renamed.entry_point);
 await run(source,'functions rename',['--address',from.shared.entry_point,'--name','PortedShared']);
 const createArgs=['--source-target',source.target,'--request-id','owned-vt-create'],created=await run(destination,'version-tracking create',createArgs),tracking=created.tracking;
 assert.deepEqual(await run(destination,'version-tracking create',createArgs),created);
 assert.ok((await run(destination,'version-tracking list')).items.some(row=>row.tracking===tracking));
 const matches=(await run(destination,'version-tracking matches',['--tracking',tracking,'--limit','1000'])).value;
 const normal=value=>value.toLowerCase().replace(/^0x/,'').replace(/^0+(?=.)/,'');
 const moved=matches.items.find(row=>normal(row.source)===normal(from.shared.entry_point)&&normal(row.destination)===normal(to.renamed.entry_point));assert.ok(moved);
 assert.ok(matches.match_sets.some(row=>row.correlator==='Exact Function Bytes Match'));assert.ok(matches.items.every(row=>Number.isFinite(row.similarity)&&Number.isFinite(row.confidence)));
 assert.ok(matches.unmatched_source.items.some(row=>normal(row.address)===normal(from.removed.entry_point)));assert.ok(matches.unmatched_destination.items.some(row=>normal(row.address)===normal(to.added.entry_point)));passed('Native VT persistent match sets identify moved and unmatched functions with score provenance');
 const decision=['--tracking',tracking,'--source-address',moved.source,'--destination-address',moved.destination,'--decision','accepted','--request-id','owned-vt-accept'];
 const accepted=await run(destination,'version-tracking decide',decision);assert.equal(accepted.value.status,'ACCEPTED');assert.deepEqual(await run(destination,'version-tracking decide',decision),accepted);
 const markup=(await run(destination,'version-tracking markup',['--tracking',tracking,'--source-address',moved.source,'--destination-address',moved.destination])).value;assert.equal(markup.association_status,'ACCEPTED');assert.ok(markup.items.some(row=>row.type.toLowerCase().includes('name')));passed('Explicit native acceptance, actual markup inventory and caller retry');
 const ambiguous=matches.items.filter(row=>normal(row.source)===normal(from.dup_a.entry_point));assert.ok(ambiguous.length>=2);
 await run(destination,'version-tracking decide',['--tracking',tracking,'--source-address',ambiguous[0].source,'--destination-address',ambiguous[0].destination,'--decision','accepted']);
 const conflict=await f.run(app,['ghidra','version-tracking','decide',...select(destination),'--tracking',tracking,'--source-address',ambiguous[1].source,'--destination-address',ambiguous[1].destination,'--decision','accepted','--json']);assert.notEqual(conflict.exitCode,0);
 assert.ok((await run(destination,'version-tracking matches',['--tracking',tracking,'--limit','1000'])).value.items.some(row=>normal(row.source)===normal(ambiguous[0].source)&&normal(row.destination)===normal(ambiguous[0].destination)&&row.status==='ACCEPTED'));passed('Duplicate native candidates retain ambiguity and enforce one-to-one decisions');
 await app.dispose();app=make();
 const resumed=await run(destination,'version-tracking matches',['--tracking',tracking,'--limit','1000']);assert.ok(resumed.value.items.some(row=>normal(row.source)===normal(moved.source)&&normal(row.destination)===normal(moved.destination)&&row.status==='ACCEPTED'));
 await run(destination,'functions rename',['--address',to.renamed.entry_point,'--name','PortedShared']);assert.equal((await run(destination,'functions get',['--address',to.renamed.entry_point])).name,'PortedShared');
 assert.equal((await run(destination,'version-tracking matches',['--tracking',tracking])).destinationContextChanged,true);passed('VT survives a replacement owner; agent-directed porting uses ordinary saved edits and exposes changed context provenance');
 receipt={schema:1,state:'passed',scope:'owned native Version Tracking workflow',cases,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,
 limitations:['Native match sets retain original snapshots; edits are explicit facade operations, not automatic markup publication.','Tiny owned version pairs; at most 10000 functions per input and 60-second native correlation budget.']};
}catch(error){console.error('Owned VT diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
