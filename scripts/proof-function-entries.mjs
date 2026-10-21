// Installed public before/after proof. All programs, profiles and writes are disposable.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile,readFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {performance} from 'node:perf_hooks';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
import {nativeProofGuard} from './native-proof-guard.mjs';
const {values:o}=parseArgs({options:{before:{type:'string'},after:{type:'string'},root:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},rounds:{type:'string',default:'24'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['before','after','root','java','ghidra-home'])assert.ok(o[k],k);
const root=resolve(o.root),rounds=Number(o.rounds);assert.ok(Number.isSafeInteger(rounds)&&rounds>=4&&rounds<=100);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const exec=promisify(execFile),before=resolve(o.before),after=resolve(o.after),checks={},cleanup=[],rows=[],warmups=[],fixtures=[];
const B=0x180000000n,H=n=>n.toString(16),addr=n=>H(B+BigInt(n));
const source=`import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import java.util.*;
public class OwnedEntryFixture extends GhidraScript {
 long base=0x180000000L;Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
 void block(String name,long start,int length,boolean execute)throws Exception{var b=currentProgram.getMemory().createInitializedBlock(name,at(start),length,(byte)0x90,monitor,false);b.setExecute(execute);}
 void fn(long start,AddressSet body)throws Exception{currentProgram.getMemory().setBytes(at(start),HexFormat.of().parseHex("b80100000083c002c3"));currentProgram.getFunctionManager().createFunction("FUN_"+Long.toHexString(start),null,at(start),body,SourceType.ANALYSIS);}
 public void run()throws Exception{
  AutoAnalysisManager.getAnalysisManager(currentProgram).initializeOptions();var options=currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
  for(String name:options.getOptionNames())if(options.getType(name)==OptionType.BOOLEAN_TYPE)options.setBoolean(name,false);
  block("owned-entry-early",0x10000L,32,true);block("owned-entry-code",base,0x3000,true);
  for(int offset:new int[]{0x1000,0x1020,0x1040})fn(base+offset,new AddressSet(at(base+offset)));
  fn(base+0x2000,new AddressSet(at(base+0x2000),at(base+0x201f)));
  AddressSet disjoint=new AddressSet(at(base+0x2100),at(base+0x2108));disjoint.add(at(base+0x2080),at(base+0x2087));fn(base+0x2100,disjoint);
  block("owned-entry-adjacent",base+0x3000,0x100,true);block("owned-entry-gapped",base+0x5000,0x100,true);block("owned-entry-data",base+0x6000,0x100,false);
  currentProgram.getMemory().createUninitializedBlock("owned-entry-uninitialized",at(base+0x7000),0x100,false).setExecute(true);
   for(int offset:new int[]{0x6040,0x6080,0x7040,0x7080})currentProgram.getFunctionManager().createFunction("FUN_"+Long.toHexString(base+offset),null,at(base+offset),new AddressSet(at(base+offset),at(base+offset+0x1f)),SourceType.ANALYSIS);
  block("owned-entry-noise",base+0x100000,0x5000,true);
  for(int i=0;i<2048;i++){long start=base+0x100000+i*8;currentProgram.getMemory().setByte(at(start),(byte)0xc3);currentProgram.getFunctionManager().createFunction("noise_"+i,null,at(start),new AddressSet(at(start)),SourceType.ANALYSIS);}
  println("OWNED_ENTRY_FIXTURE_READY");
 }
}`;
// Compile fixture API usage before any script dispatch; no speculative live script retry.
const compile=join(root,'compile');await mkdir(compile);await writeFile(join(compile,'OwnedEntryFixture.java'),source);const jars=[];
async function walk(dir){for(const e of await readdir(dir,{withFileTypes:true})){const p=join(dir,e.name);if(e.isDirectory())await walk(p);else if(e.name.endsWith('.jar'))jars.push(p);}}
await walk(join(resolve(o['ghidra-home']),'Ghidra'));await exec(resolve(o.java).replace(/java$/,'javac'),['-proc:none','-cp',jars.join(':'),'-d',compile,join(compile,'OwnedEntryFixture.java')],{maxBuffer:262144});
const input=join(root,'fixture.exe');await writeFile(join(root,'fixture.c'),'int main(void){return 7;}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',join(root,'fixture.c'),'-o',join(root,'fixture.obj')]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,join(root,'fixture.obj')]);
const {connectInsight}=await import(pathToFileURL(join(after,'dist/src/persistent-client.js')).href);
assert.equal(digest(await readFile(join(before,'dist/src/persistent-client.js'))),digest(await readFile(join(after,'dist/src/persistent-client.js'))),'Transport bytes identical across builds');
const checkpoint=f=>{const d=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{return {context:JSON.parse(d.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(f.scope.session,f.scope.target).data),requests:d.prepare('SELECT id,state FROM requests ORDER BY rowid').all()};}finally{d.close();}};
const traces=async f=>{const d=join(f.appdata,'insight-cli',f.profile,'workspace/diagnostics');const rows=[];for(const n of ['timings.jsonl.previous','timings.jsonl'])try{rows.push(...(await readFile(join(d,n),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse));}catch(e){if(e.code!=='ENOENT')throw e;}return rows;};
const queryAddresses=[addr(0x1008),addr(0x1009),addr(0x1028),addr(0x1048)];
const fields=['--fields','entry_point,decompiled_code','--include-call-context','false','--limit-chars','4000','--total-chars','16000'];
const inspect=(f,selectors,extra=[])=>['ghidra','functions','inspect',...f.select,'--functions',selectors.join(','),...fields,...extra];
let seq=0;async function call(f,argv,phase){const id=++seq,started=performance.now();let value,error;try{value=await f.client.execute(argv);}catch(e){error={name:e.name,message:e.message,rpc:e.rpc,dispatched:e.dispatched};}const elapsedMs=performance.now()-started,raw=JSON.stringify({value,error});await writeFile(join(root,f.label,id+'.json'),raw,{mode:0o600});f.receipts.push({id,phase,argv,elapsedMs,sha256:digest(Buffer.from(raw)),error});if(error)throw Object.assign(Error('Fixture command failed; '+f.label+'/'+id+'.json'),{details:error});return value;}
function selectedContent(row){return {entry:BigInt('0x'+row.entry_point.replace(/^0x/,'' )).toString(16),name:row.name,code:row.decompiled_code,hash:row.text.textSha256,totalCharacters:row.text.totalCharacters,sourceTruncated:row.text.sourceTruncated};}
function collect(x,out=[]){if(x&&typeof x==='object'){if(typeof x.name==='string'&&x.name.startsWith('FUN_1800010'))out.push(x);for(const v of Object.values(x))collect(v,out);}return out;}
async function workload(f,phase,round){const beforeTrace=await traces(f),began=performance.now(),count=f.receipts.length;let result;
 if(f.label==='before'){
  const miss=await call(f,inspect(f,queryAddresses),phase);assert.ok(Object.values(miss.value.functions).every(x=>x.status==='not_found'));
  const inventory=await call(f,['ghidra','functions','search',...f.select,'--name-pattern','^FUN_1800010','--regex','true','--limit','20'],phase);
  const entries=[...new Set(collect(inventory).map(x=>x.address??x.entry_point))].filter(Boolean).map(x=>BigInt('0x'+x.replace(/^0x/,''))).sort((a,b)=>a<b?-1:1);assert.equal(entries.length,3,'Search response must supply exactly three fixture entries');
  const picks=queryAddresses.map(q=>{const n=BigInt('0x'+q),p=entries.filter(x=>x<=n).at(-1);assert.ok(p!==undefined&&n-p<=4096n);return H(p);});
  const exact=await call(f,inspect(f,[...new Set(picks)]),phase);result=Object.fromEntries(queryAddresses.map((q,i)=>[q,selectedContent(exact.value.functions[picks[i]])]));
 }else{
  const v=await call(f,inspect(f,queryAddresses,['--resolve-address','containing-or-preceding','--max-entry-distance','4096']),phase);
  result=Object.fromEntries(queryAddresses.map(q=>{const row=v.value.functions[q];assert.equal(row.status,'success');assert.equal(row.resolution.kind,'preceding-entry-candidate');assert.equal(row.resolution.recordedBodyContainsAddress,false);return [q,selectedContent(row)];}));
 }
 const elapsedMs=performance.now()-began,added=(await traces(f)).slice(beforeTrace.length),native=added.filter(x=>x.phase==='native.http');
 const row={label:f.label,phase,round,elapsedMs,requests:f.receipts.length-count,nativeHttp:native.length,getFunctions:native.filter(x=>x.operation==='/get_functions').length,entryLookup:native.filter(x=>x.operation==='/insight/function-entries/v1').length,contentSha256:digest(Buffer.from(JSON.stringify(result))),result};
 (phase==='measured'?rows:warmups).push(row);return result;
}
const q=values=>{const a=values.toSorted((x,y)=>x-y);return {n:a.length,p50:a[Math.ceil(a.length*.5)-1],p95:a[Math.ceil(a.length*.95)-1],sum:a.reduce((x,y)=>x+y,0)};};
try{
 for(const label of ['before','after']){
  await mkdir(join(root,label));const f=await createPublicFixture(label==='before'?before:after,join(root,label,'public'));Object.assign(f,{label,receipts:[]});fixtures.push(f);
  await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);f.scope=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);f.select=['--session',f.scope.session,'--target',f.scope.target];
  await f.call(['ghidra','scripts','run-inline',...f.select,'--code',source,'--request-id','owned-entry-fixture']);await f.call(['permissions','revoke','Update']);
  f.client=await connectInsight({executable:process.execPath,arguments:[f.cli],cwd:f.project,env:f.environment});f.initial=checkpoint(f);
 }
 const f=fixtures[1];const inspectAt=(addresses,maximum='4096',extra=[])=>call(f,['ghidra','functions','inspect',...f.select,'--functions',addresses.join(','),'--resolve-address','containing-or-preceding','--max-entry-distance',maximum,'--fields','entry_point','--include-call-context','false',...extra],'proof');
 const probe=await inspectAt([addr(0x1000),addr(0x1008),addr(0x2018),addr(0x2084)]),items=probe.value.functions;
 assert.equal(items[addr(0x1000)].resolution.kind,'exact-entry');assert.equal(items[addr(0x1008)].resolution.kind,'preceding-entry-candidate');assert.equal(items[addr(0x2018)].resolution.kind,'recorded-containing');assert.equal(items[addr(0x2084)].entry_point,addr(0x2100));assert.equal(items[addr(0x2084)].resolution.distanceBytes,undefined);checks.exactSparseAndNoncontiguousContainment=true;
 assert.equal((await inspectAt([addr(0x2018)],'1')).value.functions[addr(0x2018)].resolution.kind,'recorded-containing');
  const recorded=(await inspectAt([addr(0x6040),addr(0x6088),addr(0x7040),addr(0x7088)],'1')).value.functions;
  for(const n of [0x6040,0x7040])assert.equal(recorded[addr(n)].resolution.kind,'exact-entry');
  for(const n of [0x6088,0x7088])assert.equal(recorded[addr(n)].resolution.kind,'recorded-containing');
  checks.recordedFunctionsBeforeFallbackBlockAndDistanceGates=true;
 const misses=await inspectAt(['10010',addr(0x10),addr(0x3008),addr(0x5008),addr(0x6008),addr(0x7008),addr(0x4008),addr(0x1048)],'7');const reasons=Object.fromEntries(Object.entries(misses.value.functions).map(([k,v])=>[k,v.reason]));
 assert.equal(reasons['10010'],'no_preceding_entry');assert.equal(reasons[addr(0x10)],'entry_outside_block');assert.equal(reasons[addr(0x3008)],'entry_outside_block');assert.equal(reasons[addr(0x5008)],'entry_outside_block');assert.equal(reasons[addr(0x1048)],'entry_distance_exceeded');for(const n of [0x6008,0x7008,0x4008])assert.equal(reasons[addr(n)],'address_not_in_initialized_executable_block');checks.distanceBlocksHolesAndIneligibleMemory=true;
 await assert.rejects(inspectAt([addr(0x1008)],'0'));await assert.rejects(inspectAt(['name']));await assert.rejects(inspectAt([addr(0x1008)],'65537'));checks.invalidOptions=true;
 const folded=await call(f,inspect(f,[addr(0x1008),'0x'+addr(0x1009)],['--resolve-address','containing-or-preceding','--max-entry-distance','4096','--fields','decompiled_code','--limit-chars','4','--total-chars','7']),'proof');const aliases=Object.values(folded.value.functions);assert.equal(folded.value.textBudget.returnedCharacters,7);assert.equal(aliases[0].text.textSha256,aliases[1].text.textSha256);assert.equal(aliases[0].entry_point,aliases[1].entry_point);checks.aliasProjectionAndBudget=true;
 const continuation=await inspectAt([addr(0x1008)],'4096',['--expect-view',folded.value.view.identity]);assert.equal(continuation.value.functions[addr(0x1008)].resolution.kind,'preceding-entry-candidate');checks.viewContinuation=true;
 const warmBefore=await workload(fixtures[0],'warmup',-1),warmAfter=await workload(fixtures[1],'warmup',-1);assert.deepEqual(warmAfter,warmBefore);checks.crossBuildSelectedEntriesAndText=true;
 for(let round=0;round<rounds;round++)for(const f of round%2?[...fixtures].reverse():fixtures){const value=await workload(f,'measured',round);assert.deepEqual(value,warmBefore);}
 for(const f of fixtures){assert.deepEqual(checkpoint(f),f.initial);checks[f.label+'ReadOnlyState']=true;await writeFile(join(root,f.label,'requests.json'),JSON.stringify(f.receipts,null,2));await writeFile(join(root,f.label,'timings.json'),JSON.stringify(await traces(f)));}
 const summary=Object.fromEntries(fixtures.map(f=>{const a=rows.filter(x=>x.label===f.label);return [f.label,{workloads:a.length,requests:a.reduce((s,x)=>s+x.requests,0),elapsedMs:q(a.map(x=>x.elapsedMs)),nativeHttp:a.reduce((s,x)=>s+x.nativeHttp,0),getFunctions:a.reduce((s,x)=>s+x.getFunctions,0),entryLookup:a.reduce((s,x)=>s+x.entryLookup,0)}];}));
 await writeFile(join(root,'result.json'),JSON.stringify({schema:1,state:'passed',checks,rounds,inputSha256:digest(await readFile(input)),builds:await Promise.all([before,after].map(async p=>({package:p,manifest:JSON.parse(await readFile(join(p,'.cli-package-build.json'),'utf8'))}))),queryAddresses,summary,rows,warmups,method:{clock:'performance.now, retained client calls; excludes setup, warmups and trace-file reads. Includes per-command raw receipt persistence consistently in both routes.',order:'alternating before/after and after/before, no overlap',baseline:'batch miss, one bounded regex inventory, exact-entry batch; generous same-prefix fixture permits a single search',after:'one opt-in fused batch, same original query addresses',content:'exact comparison of selected entries/name/decompile/hash/length/truncation; excludes scope/native revision identities',limits:'one generated sparse PE,2048 noise entries, shared host, no inference/tool approval/one-shot startup timing. Lookup is indexed; upstream decompiler CPU bounds unchanged.'}},null,2));console.log(JSON.stringify({checks,summary}));
}finally{
 for(const f of fixtures.reverse()){
   try{await f.call(['permissions','grant','Update']);if(f.scope)await f.call(['ghidra','close','--session',f.scope.session,'--target',f.scope.target]);await f.call(['ghidra','server','stop']);}catch(e){cleanup.push(f.label+': '+e.message);}
  try{if(f.client)await f.client.close();await f.cleanup();}catch(e){cleanup.push(f.label+': '+e.message);}
  await writeFile(join(root,f.label,'requests.json'),JSON.stringify(f.receipts,null,2));
 }
 await writeFile(join(root,'cleanup.json'),JSON.stringify({cleanup},null,2));assert.deepEqual(cleanup,[]);
}
