// Opt-in installed before/after proof. Only generated PE inputs and disposable native contexts.
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
const root=resolve(o.root),rounds=Number(o.rounds);assert.ok(Number.isInteger(rounds)&&rounds>=4&&rounds<=100);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const exec=promisify(execFile),before=resolve(o.before),after=resolve(o.after),checks={},cleanup=[],rows=[],warmups=[],fixtures=[];
const B=0x181000000n,C=0x180100000n,H=n=>n.toString(16),encs=['ascii','utf16le'],cap=1024,size=65536;
const literals=[[5000,'Data/Balance/Widget.dat','ascii'],[9000,'Widget/Widget','ascii'],[17001,'Data/Balance/Widget.dat','utf16le'],[30000,'Widget/Widget','utf16le']];
const corpus=Buffer.alloc(size,0x91);for(const [at,text,e]of literals){const bytes=Buffer.from(text,e==='ascii'?'ascii':'utf16le'),unit=e==='ascii'?1:2;corpus.fill(0,at-unit,at);bytes.copy(corpus,at);corpus.fill(0,at+bytes.length,at+bytes.length+unit);}
const source=`import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*; import ghidra.program.model.listing.Program;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager; import ghidra.framework.options.OptionType;
import java.util.*; import java.nio.charset.StandardCharsets;
public class OwnedAnchorFixture extends GhidraScript {
 Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
 void block(String name,long start,int length)throws Exception{currentProgram.getMemory().createInitializedBlock(name,at(start),length,(byte)0x91,monitor,false).setExecute(false);}
 void bytes(long at,String hex)throws Exception{currentProgram.getMemory().setBytes(at(at),HexFormat.of().parseHex(hex));}
 void literal(long address,String text,boolean utf)throws Exception{int w=utf?2:1;currentProgram.getMemory().setBytes(at(address-w),new byte[w]);byte[] value=text.getBytes(utf?StandardCharsets.UTF_16LE:StandardCharsets.US_ASCII);currentProgram.getMemory().setBytes(at(address),value);currentProgram.getMemory().setBytes(at(address+value.length),new byte[w]);}
 public void run()throws Exception{
  AutoAnalysisManager.getAnalysisManager(currentProgram).initializeOptions();var options=currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);for(String name:options.getOptionNames())if(options.getType(name)==OptionType.BOOLEAN_TYPE)options.setBoolean(name,false);
  long c=0x180100000L;block("anchor-left",c,4096);block("anchor-adjacent",c+4096,4096);block("anchor-after-hole",c+8193,4096);
  currentProgram.getMemory().createUninitializedBlock("anchor-uninitialized",at(c+16384),4096,false);
  literal(c+4093,"Widget",false);bytes(c+8190,"5769");bytes(c+8193,"6467657400");
  bytes(c+100,"00ff57696467657400");literal(c+201,"ababa",false);literal(c+301,"A",true);
  bytes(c+499,"0000780000d85700690064006700650074000000");
  block("anchor-long",c+65536,50000);literal(c+65536+5000,"x".repeat(4000)+"Widget"+"y".repeat(4000),false);
  block("anchor-workload",0x181000000L,65536);
  ${literals.map(([n,t,e])=>`literal(0x181000000L+${n},${JSON.stringify(t)},${e==='utf16le'});`).join('\n  ')}
  println("OWNED_ANCHOR_FIXTURE_READY");
 }
}`;
// Verify fixture Java API use before a script can be dispatched.
const compile=join(root,'compile');await mkdir(compile);await writeFile(join(compile,'OwnedAnchorFixture.java'),source);const jars=[];
async function walk(dir){for(const e of await readdir(dir,{withFileTypes:true})){const p=join(dir,e.name);if(e.isDirectory())await walk(p);else if(e.name.endsWith('.jar'))jars.push(p);}}
await walk(join(resolve(o['ghidra-home']),'Ghidra'));await exec(resolve(o.java).replace(/java$/,'javac'),['-proc:none','-cp',jars.join(':'),'-d',compile,join(compile,'OwnedAnchorFixture.java')],{maxBuffer:262144});
const input=join(root,'fixture.exe');await writeFile(join(root,'fixture.c'),'int main(void){return 7;}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',join(root,'fixture.c'),'-o',join(root,'fixture.obj')]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,join(root,'fixture.obj')]);
const {connectInsight}=await import(pathToFileURL(join(after,'dist/src/persistent-client.js')).href);
assert.equal(digest(await readFile(join(before,'dist/src/persistent-client.js'))),digest(await readFile(join(after,'dist/src/persistent-client.js'))),'Identical persistent transport');
const checkpoint=f=>{const d=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{return {context:JSON.parse(d.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(f.scope.session,f.scope.target).data),requests:d.prepare('SELECT id,state FROM requests ORDER BY rowid').all()};}finally{d.close();}};
const traces=async f=>{const d=join(f.appdata,'insight-cli',f.profile,'workspace/diagnostics'),rows=[];for(const n of ['timings.jsonl.previous','timings.jsonl'])try{rows.push(...(await readFile(join(d,n),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse));}catch(e){if(e.code!=='ENOENT')throw e;}return rows;};
let seq=0;async function call(f,argv,phase='proof'){const id=++seq,started=performance.now();let value,error;try{value=await f.client.execute(argv);}catch(e){error={name:e.name,message:e.message,rpc:e.rpc,dispatched:e.dispatched};}const elapsedMs=performance.now()-started,raw=JSON.stringify({value,error});await writeFile(join(root,f.label,id+'.json'),raw,{mode:0o600});f.receipts.push({id,phase,argv,elapsedMs,sha256:digest(Buffer.from(raw)),error});if(error)throw Object.assign(Error('Fixture command failed; '+f.label+'/'+id+'.json'),{details:error});return value;}
const anchors=(f,text='Widget',encodings='ascii,utf16le',from=B,through=B+BigInt(size-1),extra=[])=>['ghidra','strings','anchors',...f.select,'--text',text,'--encodings',encodings,'--scan-from',H(from),'--scan-through',H(through),'--max-string-bytes',String(cap),'--max-bytes','4194304','--timeout-seconds','10','--limit','100',...extra];
function decode(bytes,e){if(e==='ascii')return bytes.some(x=>x>127)?null:bytes.toString('ascii');try{return new TextDecoder('utf-16le',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{return null;}}
// Independent test-side reconstruction of bounded memory readbacks; no hidden binary scanner.
function context(data,base,match,text,e){const width=e==='ascii'?1:2,needle=Buffer.from(text,e==='ascii'?'ascii':'utf16le'),at=Number(match-base),allow=cap-needle.length;
 const probe=left=>{let n=0,p=left?at-width:at+needle.length;while(p>=0&&p+width<=data.length){if(data[p]===0&&(width===1||data[p+1]===0))return {n,nul:p,boundary:'nul'};if(n===allow)return {n,nul:null,boundary:'string_limit'};n+=width;p+=left?-width:width;}return {n,nul:null,boundary:'range_edge'};};
 const left=probe(true),right=probe(false),spare=cap-needle.length;let l=Math.min(left.n,Math.floor(spare/2/width)*width),r=Math.min(right.n,spare-l);l+=Math.min(left.n-l,spare-l-r);r+=Math.min(right.n-r,spare-l-r);
 const from=at-l,bytes=data.subarray(from,at+needle.length+r),value=decode(bytes,e),bounded=left.nul!==null&&right.nul!==null,total=left.n+needle.length+right.n,complete=bounded&&total<=cap&&value!==null;
 return {encoding:e,matchAddress:H(match),matchByteLength:needle.length,matchOffsetBytes:left.nul===null?null:left.n,literalCandidate:{start:left.nul===null?null:H(base+BigInt(left.nul+width)),terminatorAddress:right.nul===null?null:H(base+BigInt(right.nul)),byteLength:bounded?total:null,textFrom:H(base+BigInt(from)),text:value,textBytes:bytes.toString('hex'),textByteLength:bytes.length,leftBoundary:left.boundary,rightBoundary:right.boundary,boundariesComplete:bounded,decoding:value===null?'invalid':'valid',complete,reason:complete?'complete':bounded&&total>cap||left.boundary==='string_limit'||right.boundary==='string_limit'?'string_limit':!bounded?'missing_boundary':'invalid_encoding'}};
}
const expected=[];for(const e of encs){const needle=Buffer.from('Widget',e==='ascii'?'ascii':'utf16le');for(let offset=corpus.indexOf(needle);offset>=0;offset=corpus.indexOf(needle,offset+1))expected.push(context(corpus,B,B+BigInt(offset),'Widget',e));}expected.sort((a,b)=>BigInt('0x'+a.matchAddress)<BigInt('0x'+b.matchAddress)?-1:BigInt('0x'+a.matchAddress)>BigInt('0x'+b.matchAddress)?1:encs.indexOf(a.encoding)-encs.indexOf(b.encoding));
async function workload(f,phase,round){const initialTrace=(await traces(f)).length,began=performance.now(),count=f.receipts.length;let matches=[],bytes=0,pages=0;
 if(f.label==='before'){
  for(const e of encs){const needle=Buffer.from('Widget',e==='ascii'?'ascii':'utf16le'),found=await call(f,['ghidra','analysis','search-byte-patterns',...f.select,'--pattern',needle.toString('hex'),'--scan-from',H(B),'--max-bytes',String(size),'--timeout-seconds','10','--max-scan','100000','--limit','100'],phase);assert.equal(found.value.complete,true);assert.equal(found.value.scanned_bytes,size);bytes+=found.value.scanned_bytes;pages++;
   for(const hit of found.value.matches){const at=BigInt('0x'+hit.address.replace(/^0x/,'')),width=e==='ascii'?1:2,lo=at-BigInt(cap-needle.length+width),hi=at+BigInt(cap+width-1);assert.ok(lo>=B&&hi<B+BigInt(size));const read=await call(f,['ghidra','memory','read',...f.select,'--address',H(lo),'--length',String(hi-lo+1n)],phase);const data=Buffer.from(read.value.hex.replace(/\s/g,''),'hex');assert.equal(data.length,Number(hi-lo+1n));bytes+=data.length;matches.push(context(data,lo,at,'Widget',e));}
  }
  matches.sort((a,b)=>BigInt('0x'+a.matchAddress)<BigInt('0x'+b.matchAddress)?-1:BigInt('0x'+a.matchAddress)>BigInt('0x'+b.matchAddress)?1:encs.indexOf(a.encoding)-encs.indexOf(b.encoding));
 }else{const v=await call(f,anchors(f),phase);assert.equal(v.value.scan.complete,true);matches=v.value.matches;bytes=v.value.scan.bytesRead;pages++;}
 assert.deepEqual(matches,expected);const elapsedMs=performance.now()-began,trace=(await traces(f)).slice(initialTrace),native=trace.filter(x=>x.phase==='native.http');
 (phase==='measured'?rows:warmups).push({label:f.label,phase,round,elapsedMs,requests:f.receipts.length-count,pages,bytesRead:bytes,nativeHttp:native.length,nativeHttpMs:native.reduce((s,x)=>s+x.durationMs,0),operations:native.map(x=>({operation:x.operation,durationMs:x.durationMs})),contentSha256:digest(Buffer.from(JSON.stringify(matches)))});return matches;
}
const quantile=values=>{const a=values.toSorted((x,y)=>x-y);return {n:a.length,p50:a[Math.ceil(a.length*.5)-1],p95:a[Math.ceil(a.length*.95)-1],sum:a.reduce((x,y)=>x+y,0)};};
try{
 for(const label of ['before','after']){await mkdir(join(root,label));const f=await createPublicFixture(label==='before'?before:after,join(root,label,'public'));Object.assign(f,{label,receipts:[]});fixtures.push(f);await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);f.scope=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);f.select=['--session',f.scope.session,'--target',f.scope.target];await f.call(['ghidra','scripts','run-inline',...f.select,'--code',source,'--request-id','owned-anchor-fixture']);await f.call(['permissions','revoke','Update']);f.client=await connectInsight({executable:process.execPath,arguments:[f.cli],cwd:f.project,env:f.environment});f.initial=checkpoint(f);f.nativeView=(await call(f,['ghidra','functions','inspect',...f.select,'--functions','180001000','--fields','entry_point','--include-call-context','false'])).value.view.identity;}
 const f=fixtures[1],probe=async(...args)=>(await call(f,anchors(f,...args))).value;
 const adjacent=await probe('Widget','ascii',C+4092n,C+4100n);assert.deepEqual(adjacent.matches.map(x=>x.matchAddress),[H(C+4093n)]);assert.equal(adjacent.matches[0].literalCandidate.complete,true);checks.adjacentInitializedBlocksMerge=true;
 assert.equal((await probe('Widget','ascii',C+8190n,C+8200n)).matches.length,0);checks.holeNotBridged=true;
 const invalid=await probe('Widget','ascii',C+100n,C+110n);assert.equal(invalid.matches[0].literalCandidate.decoding,'invalid');assert.equal(invalid.matches[0].literalCandidate.boundariesComplete,true);checks.invalidAsciiRetainsRawHit=true;
 const invalidUtf=await probe('Widget','utf16le',C+499n,C+530n);assert.equal(invalidUtf.matches[0].literalCandidate.decoding,'invalid');checks.invalidUtf16RetainsRawHit=true;
 const overlap=await probe('aba','ascii',C+200n,C+210n);assert.deepEqual(overlap.matches.map(x=>x.matchAddress),[H(C+201n),H(C+203n)]);checks.overlaps=true;
 const edge=await probe('Widget','ascii',C+4093n,C+4098n);assert.equal(edge.matches[0].literalCandidate.leftBoundary,'range_edge');assert.equal(edge.matches[0].literalCandidate.rightBoundary,'range_edge');checks.inclusiveRangeClipsMatchContextAndTerminators=true;
 const both=await probe('A','ascii,utf16le',C+299n,C+305n,['--limit','1']);assert.equal(both.matches[0].encoding,'ascii');const resumed=await call(f,['ghidra','strings','anchors',...f.select,'--cursor',both.cursor,'--max-bytes','32768']);assert.equal(resumed.value.matches[0].encoding,'utf16le');assert.equal(resumed.value.matches[0].matchAddress,H(C+301n));checks.encodingFrontier=true;
 const long=await probe('Widget','ascii',C+65536n,C+115535n,['--max-string-bytes','8192','--max-bytes','32768','--limit','1']);assert.equal(long.matches[0].literalCandidate.complete,true);assert.equal(long.matches[0].literalCandidate.byteLength,8006);checks.maximumCandidateMinimumBudget=true;
 const preview=await probe('Widget','ascii',C+65536n,C+115535n);assert.equal(preview.matches[0].literalCandidate.textByteLength,1024);assert.equal(preview.matches[0].literalCandidate.start,null);assert.equal(preview.matches[0].literalCandidate.reason,'string_limit');checks.boundedPartialPreview=true;
 const empty=await probe('Widget','ascii',C+16384n,C+20479n);assert.equal(empty.scan.complete,true);assert.equal(empty.scan.bytesRead,0);assert.equal(empty.matches.length,0);checks.uninitializedEmptyDomain=true;
 const paged=[];let page=await probe('Widget','ascii,utf16le',B,B+BigInt(size-1),['--max-bytes','32768','--limit','1']);for(let i=0;;i++){paged.push(...page.matches);if(page.scan.complete)break;assert.ok(i<20);page=(await call(f,['ghidra','strings','anchors',...f.select,'--cursor',page.cursor,'--max-bytes','32768','--limit','1'])).value;}assert.deepEqual(paged,expected);checks.pagedUnpagedEquivalenceAndMinimumBudgetProgress=true;
 await workload(fixtures[0],'warmup',-1);await workload(fixtures[1],'warmup',-1);checks.matchedRawPairsAndFullContext=true;
 for(let round=0;round<rounds;round++)for(const f of round%2?[...fixtures].reverse():fixtures)await workload(f,'measured',round);
 for(const f of fixtures){assert.equal((await call(f,['ghidra','functions','inspect',...f.select,'--functions','180001000','--fields','entry_point','--include-call-context','false'])).value.view.identity,f.nativeView,'Independent native view fingerprint unchanged');checks[f.label+'NativeView']=true;assert.deepEqual(checkpoint(f),f.initial);checks[f.label+'ReadOnlyState']=true;await writeFile(join(root,f.label,'requests.json'),JSON.stringify(f.receipts,null,2));await writeFile(join(root,f.label,'timings.json'),JSON.stringify(await traces(f)));}
 const summary=Object.fromEntries(fixtures.map(f=>{const a=rows.filter(x=>x.label===f.label);return [f.label,{workloads:a.length,requests:a.reduce((s,x)=>s+x.requests,0),elapsedMs:quantile(a.map(x=>x.elapsedMs)),nativeHttpMs:quantile(a.map(x=>x.nativeHttpMs)),nativeHttp:a.reduce((s,x)=>s+x.nativeHttp,0),bytesRead:a.reduce((s,x)=>s+x.bytesRead,0),pages:a.reduce((s,x)=>s+x.pages,0)}];}));
 await writeFile(join(root,'result.json'),JSON.stringify({schema:1,state:'passed',checks,rounds,inputSha256:digest(await readFile(input)),corpusSha256:digest(corpus),builds:await Promise.all([before,after].map(async p=>({package:p,manifest:JSON.parse(await readFile(join(p,'.cli-package-build.json'),'utf8'))}))),summary,rows,warmups,method:{clock:'performance.now over retained client workflow; includes identical raw receipt persistence and test-side reconstruction/assertions, excludes trace-file reads/setup/warmup',order:'alternating AB/BA, no overlap',baseline:'two old byte-pattern searches, then bounded per-hit memory read and independent test-side literal reconstruction',after:'one precompiled raw string-anchors call',domain:'same last contiguous initialized 65536-byte block; exact same 6 address/encoding pairs and full contexts. Adjacent/hole/edge cases tested separately.',limitations:'One generated sparse PE, warm persistent clients on shared host. Combined workflow and native transport/precompilation gain; cannot attribute improvement to fusion alone. No cold startup or agent reasoning timing.'}},null,2));console.log(JSON.stringify({checks,summary}));
}finally{
 for(const f of fixtures.reverse()){try{await f.call(['permissions','grant','Update']);if(f.scope)await f.call(['ghidra','close',...f.select]);await f.call(['ghidra','server','stop']);}catch(e){cleanup.push(f.label+': '+e.message);}try{if(f.client)await f.client.close();await f.cleanup();}catch(e){cleanup.push(f.label+': '+e.message);}await writeFile(join(root,f.label,'requests.json'),JSON.stringify(f.receipts,null,2));}
 await writeFile(join(root,'cleanup.json'),JSON.stringify({cleanup},null,2));assert.deepEqual(cleanup,[]);
}
