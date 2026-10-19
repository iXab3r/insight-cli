// Public generic fixtures only. Every process/profile/file belongs to this invocation.
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {homedir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
const {values:o}=parseArgs({options:{cli:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
assert.equal(o['ack-disposable'],true);for(const k of ['cli','java','ghidra-home','root'])assert.ok(o[k],k);
assert.ok(!process.env.CI||process.env.INSIGHT_NATIVE_PERFORMANCE==='owned');const root=resolve(o.root),cli=resolve(o.cli),profile='bounded-'+randomUUID(),exec=promisify(execFile);
await mkdir(root);await mkdir(join(root,'appdata'));await mkdir(join(root,'local'));
const env={...process.env,APPDATA:join(root,'appdata'),LOCALAPPDATA:join(root,'local'),XDG_DATA_HOME:join(root,'appdata')};
let sequence=0,scope;const checks={},calls=[],scopes=[];
const sha=b=>createHash('sha256').update(b).digest('hex');
async function call(args,{failure=false,global=false}={}){
 let r,code=0;try{r=await exec(process.execPath,[cli,...(global?[]:['--profile',profile]),...args,'--json'],{env,cwd:root,timeout:1200000,maxBuffer:4*1024**2});}catch(error){r=error;code=error.code;}
 const n=++sequence;await writeFile(join(root,n+'.stdout'),r.stdout??'');await writeFile(join(root,n+'.stderr'),r.stderr??'');calls.push({operation:args.slice(0,3).join(' '),code});
 assert.equal(code===0,!failure,'Inspect private transcript '+n);const result=JSON.parse(r.stdout);
 if(failure){for(const line of String(r.stderr).trim().split('\n')){try{const parsed=JSON.parse(line);if(parsed.error)result.failure=parsed.error;}catch{}}}
 return result;
}
const scoped=(args,options)=>call(['ghidra',...args,'--session',scope.session,'--target',scope.target],options);
async function rpc(argv){
 const child=spawn(process.execPath,[cli,'--json-rpc'],{env,cwd:root,stdio:['pipe','pipe','pipe']});let output='',errors='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>errors+=b);
 child.stdin.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'cli.execute',params:{argv:['--profile',profile,...argv]}})+'\n');
 const code=await new Promise(ok=>child.once('close',ok));await writeFile(join(root,'rpc.stdout'),output);await writeFile(join(root,'rpc.stderr'),errors);assert.equal(code,0);return output.trim().split('\n').map(line=>JSON.parse(line)).find(r=>r.id===1);
}
try{
 await call(['profile','create',profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])],{global:true});await call(['permissions','grant','Update']);
 const bytes=Buffer.alloc(256,0x90);Buffer.from('b801000000c3','hex').copy(bytes,0);Buffer.from('b80200000083c003c3','hex').copy(bytes,0x10);bytes[0x80]=0xc3;Buffer.from('e96bffffff','hex').copy(bytes,0x90);Buffer.from('ffe0','hex').copy(bytes,0xa0);Buffer.from('0f04','hex').copy(bytes,0xb0);bytes[0xff]=0xe9;
 const input=join(root,'owned-x86.bin');await writeFile(input,bytes);
 scope=await call(['ghidra','open',input,'--session','new','--language','x86:LE:64:default','--compiler-spec','windows','--image-base','1000','--no-analysis']);
 scopes.push(scope);
 const state=()=>call(['sessions','status',scope.session,'--target',scope.target]);const before=await state();assert.equal(before.ghidra.pendingChanges,0);
 // Raw loader permissions differ by version. Explicitly enable execute once in this owned fixture.
 const setup='import ghidra.app.script.GhidraScript; public class OwnedDecodeSetup extends GhidraScript {public void run() throws Exception {currentProgram.getMemory().getBlock(toAddr("1000")).setExecute(true);}}';
 await scoped(['scripts','run-inline','--code',setup,'--request-id','owned-execute']);await scoped(['merge','--request-id','owned-setup-merge']);
 const clean=await state();assert.equal(clean.ghidra.pendingChanges,0);
 const storage=process.platform==='darwin'?join(homedir(),'Library','Application Support'):join(root,'appdata');
 const savedContext=()=>{const db=new DatabaseSync(join(storage,'insight-cli',profile,'workspace','workspace.sqlite'),{readOnly:true});try{return JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(scope.session,scope.target).data);}finally{db.close();}};
 const decode=(at,b=16,n=8)=>scoped(['functions','decode','--address',at,'--max-bytes',String(b),'--max-instructions',String(n)]);
 const leaf=(await decode('1080',1)).value;assert.equal(leaf.instructions[0].mnemonic.toLowerCase(),'ret');assert.equal(leaf.input_bytes,'c3');assert.equal(leaf.stop_reason,'terminal_flow');assert.equal(leaf.read_only.modification_unchanged,true);
 const snapshotBefore=savedContext();
 const branch=(await decode('1090',5)).value;assert.equal(branch.instructions[0].direct_targets[0].replace(/^0+/,''),'1000');assert.equal(branch.stop_reason,'control_flow');
 const indirect=(await decode('10a0',2)).value;assert.equal(indirect.instructions[0].computed_flow,true);assert.deepEqual(indirect.instructions[0].direct_targets,[]);
 const partial=(await decode('10ff',1)).value;assert.equal(partial.stop_reason,'truncated_instruction');assert.equal(partial.consumed_bytes,0);
 const invalid=(await decode('10b0',2)).value;assert.equal(invalid.stop_reason,'undecodable');
 const bounded=(await decode('10c0',16,2)).value;assert.equal(bounded.instructions.length,2);assert.equal(bounded.stop_reason,'instruction_limit');
 const absent=await scoped(['functions','decompile','--address','1080'],{failure:true});assert.equal(absent.reason,'function_not_found');assert.match(absent.nativeDiagnostic,/no function|not found/i);
 const after=await state();assert.equal(after.ghidra.pendingChanges,0);assert.equal(after.ghidra.baseRevision,clean.ghidra.baseRevision);checks.undefinedDecodeAndNoPendingChanges=true;
 const snapshotAfter=savedContext();assert.equal(snapshotAfter.generation,snapshotBefore.generation);assert.deepEqual(snapshotAfter.workingSnapshot,snapshotBefore.workingSnapshot);checks.savedSnapshotUnchanged=true;
 const message=await rpc(['ghidra','functions','decompile','--session',scope.session,'--target',scope.target,'--address','1080']);assert.equal(message.error.data.result.reason,'function_not_found');checks.rpcDiagnostic=true;
 const define='import ghidra.app.script.GhidraScript; public class OwnedFunctions extends GhidraScript {public void run() throws Exception {disassemble(toAddr("1000"));createFunction(toAddr("1000"),"owned_one");disassemble(toAddr("1010"));createFunction(toAddr("1010"),"owned_two");}}';
 await scoped(['scripts','run-inline','--code',define,'--request-id','owned-define']);await scoped(['merge','--request-id','owned-functions-merge']);
 const args=['functions','inspect','--functions','1000,1010,1080','--fields','entry_point,signature,decompiled_code','--include-call-context','false','--limit-chars','8','--total-chars','12'];
 const first=(await scoped(args)).value;assert.equal(first.functions['1080'].reason,'function_not_found');assert.equal(first.textBudget.returnedCharacters,12);
 const page=(await scoped([...args,'--offset-chars','8','--expect-view',first.view.identity])).value;assert.equal(page.functions['1000'].text.textSha256,first.functions['1000'].text.textSha256);
 const directory=join(root,'saved');const saved=(await scoped([...args,'--save-owner-directory',directory])).value;
 for(const at of ['1000','1010']){const item=saved.functions[at],text=await readFile(item.savedText.file,'utf8');assert.equal(sha(text),item.savedText.textSha256);assert.equal(Array.from(text).length,item.savedText.totalCharacters);assert.ok(!('decompiled_code'in item));}
 const manifest=JSON.parse(await readFile(join(directory,'manifest.json'),'utf8'));assert.deepEqual(manifest.value,saved);checks.bulkNativePagingAndManifest=true;
 await scoped(['comments','set','--address','1000','--kind','plate','--text','Owned changed view','--request-id','owned-change']);
 const changed=await scoped([...args,'--expect-view',first.view.identity],{failure:true});assert.equal(changed.reason,'changed_view');checks.changedView=true;
 const verified=await scoped(['functions','create','--address','1080','--name','owned_verified','--request-id','owned-saved-function']);assert.equal(verified.state,'applied');assert.equal(verified.value.exists,true);assert.equal(verified.value.name,'owned_verified');
 assert.deepEqual(await scoped(['functions','create','--address','1080','--name','owned_verified','--request-id','owned-saved-function']),verified);checks.independentSavedFunctionAndReplay=true;
 assert.equal(sha(await readFile(input)),sha(bytes));checks.inputUnchanged=true;
 const armInput=join(root,'owned-arm.bin');await writeFile(armInput,Buffer.from('1eff2fe1','hex'));
 scope=await call(['ghidra','open',armInput,'--session','new','--language','ARM:LE:32:v8','--compiler-spec','default','--no-analysis']);scopes.push(scope);
 const unsupported=await scoped(['functions','decode','--address','0','--max-bytes','4','--max-instructions','1'],{failure:true});assert.match(JSON.stringify(unsupported),/unsupported|x86/i);assert.equal((await state()).ghidra.pendingChanges,0);checks.unsupportedLanguage=true;
}finally{
 const cleanup=[];for(const selected of scopes.reverse()){scope=selected;try{await scoped(['close']);}catch(error){cleanup.push('close');}}
 try{await call(['ghidra','server','stop']);}catch(error){cleanup.push('server');}
 checks.ownedCleanup=cleanup.length===0;
 await writeFile(join(root,'report.json'),JSON.stringify({schema:1,checks,calls,cleanup},null,2)+'\n');
 console.log(JSON.stringify({checks,cleanup}));
 assert.deepEqual(cleanup,[]);
}
