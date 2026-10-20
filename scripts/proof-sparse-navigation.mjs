// Opt-in installed public CLI proof; generated PE and invocation-owned profile only.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
assert.equal(o['ack-disposable'],true);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const root=resolve(o.root);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const f=await createPublicFixture(resolve(o.package),root),exec=promisify(execFile),checks={},cleanup=[];let opened;
const scoped=(args,options)=>f.call(['ghidra',...args,'--session',opened.session,'--target',opened.target],options);
const journal=()=>{const db=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{
 const context=JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(opened.session,opened.target).data);
 return {generation:context.generation,snapshot:context.workingSnapshot,requests:db.prepare('SELECT count(*) AS n FROM requests WHERE context=?').get(context.id).n};
}finally{db.close();}};
try{
 await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);
 const source=join(root,'fixture.c'),input=join(root,'fixture.exe'),obj=join(root,'fixture.obj');
 await writeFile(source,'__declspec(noinline) int second(int x){return x+17;}\n__declspec(noinline) int first(int x){return second(x)+1;}\nint main(void){return first(2);}\n');
 await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);
 await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:first','/export:second','/export:main','/out:'+input,obj]);
 const inputHash=digest(await readFile(input));opened=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);
 // Known executable bytes with no function, and an undefined literal. This is fixture setup,
 // not a script or an automatic mutation on the navigation path being tested.
 const bytes=Buffer.alloc(0x120);Buffer.from('b82a000000c3','hex').copy(bytes);Buffer.from('SPARSE_ANCHOR\0').copy(bytes,0x100);
 await scoped(['memory','create-block','--name','owned-sparse','--address','180000000','--size','4096','--bytes-hex',bytes.toString('hex'),'--execute','--request-id','owned-sparse-bytes']);
 await f.call(['permissions','revoke','Update']);
 const initial=journal(),before=(await scoped(['functions','inspect','--function','first','--fields','entry_point'])).value;
 const at=before.entry_point;assert.match(at,/^[a-f0-9]+$/i);
 const nav=(await scoped(['analysis','navigation'])).value;
 assert.equal(nav.assessment,'sparse-metadata');assert.equal(nav.instructions.sampled,0);assert.equal(nav.functions.entriesWithInstructions,0);checks.seededSparse=true;
 const listing=(await scoped(['functions','disassemble','--address',at])).value;assert.equal(listing.count,0);
 const compact=(await scoped(['functions','inspect','--functions','first,second','--fields','decompiled_code,callees','--include-call-context','false'])).value;
 checks.sparseFilteredBatch=Object.values(compact.functions).every(x=>x.status==='success'&&x.decompiled_code.length>0);
 assert.equal(checks.sparseFilteredBatch,true);
 const forced=(await scoped(['functions','force-decompile','--function',at])).value;
 assert.ok(forced.decompiled.length);assert.equal(forced.scanPolicy.workBound,'not-guaranteed');checks.existingEntryTransientDecompile=true;
 const later=(await scoped(['functions','disassemble','--address',at])).value;assert.equal(later.count,0);
 const after=(await scoped(['functions','inspect','--function','first','--fields','entry_point'])).value;
 assert.equal(after.view.identity,before.view.identity);assert.equal((await scoped(['analysis','navigation'])).value.instructions.sampled,0);checks.decompileDoesNotRepairListing=true;
 const missing=await scoped(['functions','force-decompile','--function','180000000'],{allowFailure:true});assert.notEqual(missing.code,0);
 const decoded=(await scoped(['functions','decode','--address','180000000','--max-bytes','6','--max-instructions','2'])).value;
 assert.equal(decoded.instructions.length,2);assert.equal(decoded.instructions.at(-1).mnemonic.toLowerCase(),'ret');assert.equal(decoded.read_only.modification_unchanged,true);
 const absent=(await scoped(['functions','inspect','--functions','180000000','--fields','decompiled_code'])).value.functions['180000000'];assert.equal(absent.reason,'function_not_found');checks.absentEntryUsesDecode=true;
 const strings=(await scoped(['strings','list','--filter','SPARSE_ANCHOR'])).value;assert.equal(strings.count,0);
 const pattern=Buffer.from('SPARSE_ANCHOR').toString('hex');
 const prefix=(await scoped(['analysis','search-byte-patterns','--pattern',pattern,'--scan-from','180000000','--max-bytes','128'])).value;
 assert.equal(prefix.complete,false);assert.equal(prefix.matches.length,0);assert.ok(prefix.next_address);
 const tail=(await scoped(['analysis','search-byte-patterns','--pattern',pattern,'--scan-from',prefix.next_address,'--max-bytes','4096'])).value;
 assert.ok(tail.matches.some(x=>x.address==='180000100'));checks.undefinedLiteralAndContinuation=true;
 assert.deepEqual(journal(),initial);assert.equal(digest(await readFile(input)),inputHash);checks.readsPreserveSavedViewAndJournal=true;checks.inputUnchanged=true;
 await writeFile(join(root,'observations.json'),JSON.stringify({entry:at,navigation:nav,compact,force:forced,missing,decoded,prefix,tail},null,2)+'\n');
}finally{
 // Re-enable Update only for this fixture's owned save/close/server cleanup.
 try{await f.call(['permissions','grant','Update']);}catch{cleanup.push('permission');}
 if(opened)try{await scoped(['close']);}catch{cleanup.push('close');}
 try{await f.call(['ghidra','server','stop']);}catch{cleanup.push('server');}
 try{await f.cleanup();}catch{cleanup.push('owner');}
 await writeFile(join(root,'report.json'),JSON.stringify({checks,cleanup,calls:f.calls,limits:['One generated x86-64 PE; no claim of successful decompilation of all sparse bodies.','Force-decompile retains its pinned upstream work limits; it is not a bounded decode or persistent Listing repair.','AppData isolation is the existing test-only Factory seam; product code and IPC ownership are unchanged.']},null,2)+'\n');
 console.log(JSON.stringify({checks,cleanup}));assert.deepEqual(cleanup,[]);
}
