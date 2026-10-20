// Opt-in installed CLI proof and matched route benchmark. Generated input/profile only.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
assert.equal(o['ack-disposable'],true);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const root=resolve(o.root);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const exec=promisify(execFile),checks={},cleanup=[],measurements=[];let opened,f;
const B=0x180000000n,T=B+0x80000n,hex=n=>n.toString(16),forms=['call-rel32','lea-rip','mov-rip','call-rip-slot'];
const scoped=(args,options)=>f.call(['ghidra',...args,'--session',opened.session,'--target',opened.target],options);
const journal=()=>{const db=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{const c=JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(opened.session,opened.target).data);return {generation:c.generation,snapshot:c.workingSnapshot,requests:db.prepare('SELECT count(*) AS n FROM requests WHERE context=?').get(c.id).n};}finally{db.close();}};
const runScript=async(source,args,request)=>scoped(['scripts','run-inline','--code',source,'--args',args??'','--request-id',request]);
const query=async(extra=[],targets=[T,T+8n,B-0x100n],from=B,through=B+0x2101fn)=> (await scoped(['analysis','code-references','--to',targets.map(hex).join(','),'--forms',forms.join(','),'--scan-from',hex(from),'--scan-through',hex(through),'--limit','1000',...extra])).value;
const failureText=()=>readFile(join(root,f.calls.at(-1).id+'.stderr'),'utf8');
const resume=async(cursor,extra=[])=> (await scoped(['analysis','code-references','--cursor',cursor,...extra])).value;
const helper=await readFile(join(resolve(o.package),'references/native/InsightCodeReferences.java'),'utf8');
const setup=`import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.util.*;
public class OwnedReferenceFixture extends GhidraScript {
 long base=0x180000000L,target=base+0x80000;
 void put(byte[] b,int offset,String prefix,long to){byte[] p=HexFormat.of().parseHex(prefix);System.arraycopy(p,0,b,offset,p.length);int d=(int)(to-(base+offset+p.length+4));for(int j=0;j<4;j++)b[offset+p.length+j]=(byte)(d>>(j*8));}
 Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
 void block(String name,long address,byte[] data,boolean executable)throws Exception{var m=currentProgram.getMemory();var b=m.createInitializedBlock(name,at(address),data.length,(byte)0,monitor,false);m.setBytes(at(address),data);b.setExecute(executable);}
 public void run()throws Exception{
 byte[] b=new byte[0x21020];Arrays.fill(b,(byte)0x90);
 put(b,0,"e8",target);put(b,16,"488d05",target);put(b,32,"8b05",target);put(b,48,"668905",target);put(b,64,"8a05",target);put(b,80,"488b05",base-0x100);put(b,96,"ff15",target+8);
 put(b,112,"c705",target-4);b[122]=(byte)0x90;
 put(b,128,"678b05",target);put(b,144,"648b05",target);put(b,160,"658b05",target);put(b,176,"f38b05",target);
 b[192]=(byte)0xb8;put(b,193,"e8",target);put(b,208,"48668d05",target);put(b,224,"66488d05",target);put(b,256,"e8",base-0x100);put(b,300,"e8",target);put(b,65535,"488d05",target);put(b,0x2101b,"e8",target);
 block("owned-sparse",base,b,true);
 new DisassembleCommand(at(base+192),new AddressSet(at(base+192),at(base+196)),false).applyTo(currentProgram,monitor);
 new DisassembleCommand(at(base+300),new AddressSet(at(base+300),at(base+304)),false).applyTo(currentProgram,monitor);
 byte[] dense=new byte[16384];Arrays.fill(dense,(byte)0x90);for(int i=0;i<dense.length;i+=32){int d=(int)(target+(i/32%64)*8-(base+0x100000+i+5));dense[i]=(byte)0xe8;for(int j=0;j<4;j++)dense[i+1+j]=(byte)(d>>(8*j));}block("owned-dense",base+0x100000,dense,true);
 byte[] crossing=new byte[7];byte[] prefix=HexFormat.of().parseHex("488d05");System.arraycopy(prefix,0,crossing,0,3);int d=(int)(target-(base+0x200000+7));for(int j=0;j<4;j++)crossing[3+j]=(byte)(d>>(8*j));block("owned-adj-a",base+0x200000,Arrays.copyOfRange(crossing,0,5),true);block("owned-adj-b",base+0x200005,Arrays.copyOfRange(crossing,5,7),true);
 block("owned-gap-a",base+0x300000,Arrays.copyOfRange(crossing,0,4),true);block("owned-gap-b",base+0x300005,Arrays.copyOfRange(crossing,4,7),true);
 block("owned-nonexec",base+0x400000,Arrays.copyOfRange(b,0,16),false);
 currentProgram.getMemory().createUninitializedBlock("owned-uninitialized",at(base+0x500000),4096,false).setExecute(true);
 block("owned-mode32",base+0x600000,Arrays.copyOfRange(b,0,16),true);
 currentProgram.getProgramContext().setValue(currentProgram.getRegister("longMode"),at(base+0x600000),at(base+0x60000f),java.math.BigInteger.ZERO);
 byte[] slow=new byte[8*1024*1024];Arrays.fill(slow,(byte)0x66);block("owned-timeout",base+0x1000000,slow,true);
 println("OWNED_REFERENCE_FIXTURE_READY");
 }
}`;
// Compile fixture setup and scanner offline before entering any potentially uncertain script lane.
const clockHelper=helper.replace('public class InsightCodeReferences extends GhidraScript {','public class OwnedReferenceDeadline extends GhidraScript { long fixtureTicks; long fixtureClock(){return fixtureTicks+=200000L;}').replaceAll('System.nanoTime()','fixtureClock()');
const compileRoot=join(root,'compile');await mkdir(compileRoot);await writeFile(join(compileRoot,'OwnedReferenceFixture.java'),setup);await writeFile(join(compileRoot,'InsightCodeReferences.java'),helper);await writeFile(join(compileRoot,'OwnedReferenceDeadline.java'),clockHelper);
const {stdout:jars}=await exec('python3',['-c','from pathlib import Path;import sys;print(":".join(str(p) for p in Path(sys.argv[1]).rglob("*.jar")))',join(resolve(o['ghidra-home']),'Ghidra')]);
await exec(resolve(o.java).replace(/java$/,'javac'),['-proc:none','-cp',jars.trim(),'-d',compileRoot,join(compileRoot,'OwnedReferenceFixture.java'),join(compileRoot,'InsightCodeReferences.java'),join(compileRoot,'OwnedReferenceDeadline.java')]);
f=await createPublicFixture(resolve(o.package),root);
try{
 await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);
 const source=join(root,'fixture.c'),input=join(root,'fixture.exe'),obj=join(root,'fixture.obj');await writeFile(source,'int main(void){return 0;}\n');
 await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,obj]);
 const inputHash=digest(await readFile(input));opened=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);
 await runScript(setup,'','owned-reference-fixture');await f.call(['permissions','revoke','Update']);const initial=journal();
 const nav=(await scoped(['analysis','navigation'])).value;assert.equal(nav.initialAnalysis,'none');assert.ok(nav.instructions.sampled<=2);checks.sparseFixture=true;
 const all=await query();assert.equal(all.scan.complete,true);assert.equal(all.scan.tested_starts,0x21020);checks.fullCoverage=true;
 for(const [offset,form,bits]of [[0,'call-rel32',64],[16,'lea-rip',64],[32,'mov-rip',32],[48,'mov-rip',16],[64,'mov-rip',8],[80,'mov-rip',64],[96,'call-rip-slot',64],[209,'lea-rip',16],[224,'lea-rip',64]])assert.ok(all.matches.some(r=>r.from===hex(B+BigInt(offset))&&r.form===form&&r.operand_bits===bits),String(offset));
 assert.equal(all.matches.find(r=>r.from===hex(B+96n)).to,hex(T+8n));assert.equal(all.matches.find(r=>r.from===hex(B+96n)).target_role,'pointer-slot');checks.formsWidthsAndNegativeDisplacements=true;
 for(const offset of [112,128,144,160,176])assert.ok(!all.matches.some(r=>r.from===hex(B+BigInt(offset))));checks.excludedEncodings=true;
 const prefixDecode=(await scoped(['functions','decode','--address',hex(B+208n),'--max-bytes','8','--max-instructions','1'])).value;
 assert.ok(!all.matches.some(r=>r.from===hex(B+208n)));assert.equal(prefixDecode.instructions.length,0);checks.nativePrefixAgreement=true;
 assert.equal(all.matches.find(r=>r.from===hex(B+193n)).boundary,'listing-conflict');assert.equal(all.matches.find(r=>r.from===hex(B+300n)).boundary,'listing-confirmed');assert.equal(all.matches.find(r=>r.from===hex(B)).boundary,'unconfirmed');checks.boundaryEvidence=true;
 assert.ok(all.matches.some(r=>r.from===hex(B+16n))&&all.matches.some(r=>r.from===hex(B+17n)));checks.overlappingStarts=true;
 const selected=(await query(['--forms','call-rip-slot'])).matches;assert.ok(selected.length>0&&selected.every(r=>r.form==='call-rip-slot'));checks.formSelection=true;
 let part=await query(['--max-bytes','65550']),pages=[part],seen=[...part.matches];assert.equal(part.scan.reason,'byte_limit');assert.equal(part.scan.next_start,hex(B+65536n));
 while(part.cursor){part=await resume(part.cursor);pages.push(part);seen.push(...part.matches);assert.ok(pages.length<8);}assert.deepEqual(seen,all.matches);checks.bytePaginationNoLossOrDuplicates=true;
 const limited=await query(['--limit','1']);assert.equal(limited.scan.reason,'result_limit');assert.equal(limited.scan.next_start,hex(B+1n));assert.deepEqual([...limited.matches,...(await resume(limited.cursor,['--limit','1000'])).matches],all.matches);checks.resultPagination=true;
 const candidate=await query(['--max-candidates','1']);assert.equal(candidate.scan.reason,'candidate_limit');assert.equal(candidate.scan.visited_candidates,1);assert.deepEqual([...candidate.matches,...(await resume(candidate.cursor,['--max-candidates','200000'])).matches],all.matches);checks.candidatePagination=true;
 const adjacent=await query([], [T],B+0x200000n,B+0x200006n);assert.ok(adjacent.matches.some(r=>r.from===hex(B+0x200000n)));assert.equal(adjacent.scan.tested_starts,7);
 const gap=await query([], [T],B+0x300000n,B+0x500fffn);assert.equal(gap.matches.length,0);assert.equal(gap.scan.tested_starts,7);checks.adjacentBlocksGapsAndIneligibleMemory=true;
 const truncated=await query([], [T],B+0x2101bn,B+0x2101en);assert.equal(truncated.matches.length,0);assert.equal(truncated.scan.complete,true);checks.inclusiveEndRequiresWholeInstruction=true;
 const noMatch=await query(['--timeout-seconds','1','--max-bytes','16777216'],[T],B+0x1000000n,B+0x17fffffn);assert.ok(['timeout','exhausted'].includes(noMatch.scan.reason));assert.equal(noMatch.matches.length,0);if(noMatch.scan.complete)assert.equal(noMatch.scan.tested_starts,8*1024*1024);else assert.equal(BigInt('0x'+noMatch.scan.next_start),B+0x1000000n+BigInt(noMatch.scan.tested_starts));checks.noMatchWallClockCoverage=true;
 const wrongScope=await scoped(['analysis','code-references','--cursor',limited.cursor,'--to',hex(T)],{allowFailure:true});assert.notEqual(wrongScope.code,0);checks.cursorSelectorConflict=true;
 const mode32=await scoped(['analysis','code-references','--to',hex(T),'--scan-from',hex(B+0x600000n),'--scan-through',hex(B+0x60000fn)],{allowFailure:true});assert.notEqual(mode32.code,0);assert.match(await failureText(),/64-bit decode mode/);checks.non64ModeRejected=true;
 assert.deepEqual(journal(),initial);checks.readsPreserveSnapshotGenerationAndJournal=true;
 // Deterministic native deadline branch: same scanner with only its monotonic clock replaced.
 // This is an explicit Update fixture script, excluded from read-only invariants and timings.
 await f.call(['permissions','grant','Update']);
 const deadlineReply=await runScript(clockHelper,Buffer.from(JSON.stringify({operation:'/code_references',parameters:{targets:[hex(T)],forms,scan_from:hex(B+0x1000000n),scan_through:hex(B+0x17fffffn),max_bytes:16777216,max_candidates:1000000,timeout_seconds:1,limit:1000}})).toString('base64'),'owned-deadline-clock');
 const timeout=JSON.parse(deadlineReply.value.output.match(/^INSIGHT_QUERY:(.+)$/m)[1]).value;
 assert.equal(timeout.scan.reason,'timeout');assert.equal(timeout.scan.complete,false);assert.equal(timeout.matches.length,0);assert.ok(timeout.scan.tested_starts>0);assert.equal(BigInt('0x'+timeout.scan.next_start),B+0x1000000n+BigInt(timeout.scan.tested_starts));checks.deterministicNativeDeadlineAndFrontier=true;
 // Same scanner, byte range and targets on both routes; only facade routing/verification differs.
 const timed=async action=>{const start=performance.now(),v=await action();return {value:v,wallMs:performance.now()-start};};
 const legacy=async parameters=>{const name='OwnedReferenceBaseline_'+randomUUID().replaceAll('-',''),code=helper.replace('public class InsightCodeReferences ','public class '+name+' '),reply=await runScript(code,Buffer.from(JSON.stringify({operation:'/code_references',parameters})).toString('base64'),'baseline-'+randomUUID());const lines=reply.effect?.output??reply.value?.output??reply.output;assert.equal(typeof lines,'string',JSON.stringify(reply).slice(0,1000));return JSON.parse(lines.match(/^INSIGHT_QUERY:(.+)$/m)[1]).value;};
 for(let repetition=0;repetition<2;repetition++)for(const density of ['sparse','dense'])for(const targetCount of [1,16,64]){
  const targets=Array.from({length:targetCount},(_,i)=>T+BigInt(i*8)),from=density==='sparse'?B:B+0x100000n,through=density==='sparse'?B+0x2101fn:B+0x103fffn;
  const parameters={targets:targets.map(hex),forms,scan_from:hex(from),scan_through:hex(through),max_bytes:4194304,max_candidates:200000,timeout_seconds:5,limit:1000};
  await f.call(['permissions','grant','Update']);const beforeState=journal();let before,after;
  if(repetition===0){before=await timed(()=>legacy(parameters));after=await timed(()=>query([],targets,from,through));}
  else{after=await timed(()=>query([],targets,from,through));before=await timed(()=>legacy(parameters));}
  assert.equal(before.value.scan.complete,true);assert.equal(after.value.scan.complete,true);assert.deepEqual(before.value.matches,after.value.matches);assert.equal(before.value.scan.tested_starts,after.value.scan.tested_starts);assert.equal(before.value.scan.visited_candidates,after.value.scan.visited_candidates);
  const afterState=journal();assert.equal(afterState.requests,beforeState.requests+1);
  measurements.push({density,targetCount,repetition,order:repetition===0?'script-first':'api-first',matches:after.value.matches.length,testedStarts:after.value.scan.tested_starts,visitedCandidates:after.value.scan.visited_candidates,beforeMs:before.wallMs,afterMs:after.wallMs,beforeScanMs:before.value.scan.elapsed_ms,afterScanMs:after.value.scan.elapsed_ms});
 }
 checks.matchedWorkloads=true;
 await f.call(['permissions','revoke','Update']);const page=await query(['--limit','1']);await f.call(['permissions','grant','Update']);await scoped(['close']);await f.call(['permissions','revoke','Update']);const stale=await scoped(['analysis','code-references','--cursor',page.cursor],{allowFailure:true});assert.notEqual(stale.code,0);assert.match(await failureText(),/changed_view|view changed/);checks.cursorRejectsRestoredIncarnation=true;
 assert.equal(digest(await readFile(input)),inputHash);checks.inputUnchanged=true;
 const spans=await readFile(join(f.appdata,'insight-cli',f.profile,'workspace/diagnostics/timings.jsonl'),'utf8');await writeFile(join(root,'timings.jsonl'),spans);
 await writeFile(join(root,'observations.json'),JSON.stringify({all,pages,limited,candidate,adjacent,gap,truncated,noMatch,timeout,stale},null,2)+'\n');
}finally{
 try{await f.call(['permissions','grant','Update']);}catch{cleanup.push('permission');}
 if(opened)try{await scoped(['close']);}catch{cleanup.push('close');}
 try{await f.call(['ghidra','server','stop']);}catch{cleanup.push('server');}
 try{await f.cleanup();}catch{cleanup.push('owner');}
 await writeFile(join(root,'report.json'),JSON.stringify({checks,cleanup,measurements,calls:f.calls},null,2)+'\n');console.log(JSON.stringify({checks,cleanup,measurements}));assert.deepEqual(cleanup,[]);
}
