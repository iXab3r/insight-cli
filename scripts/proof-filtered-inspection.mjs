// Opt-in public CLI proof. Only generated PE bytes and invocation-owned profiles are used.
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
const {values:o}=parseArgs({options:{cli:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'expect-broken':{type:'boolean'},'ack-disposable':{type:'boolean'}}});
assert.equal(o['ack-disposable'],true);for(const key of ['cli','java','ghidra-home','root'])assert.ok(o[key],key);
const root=resolve(o.root),cli=resolve(o.cli),exec=promisify(execFile),profile='filtered-proof';
await mkdir(root);await mkdir(join(root,'appdata'));await mkdir(join(root,'local'));
// Use the same test-only Factory storage seam as toolbox/public-fixture.mjs on every OS.
let factory;
for(const base of createRequire(cli).resolve.paths('@eyeauras/cli-factory')??[]){try{const path=join(base,'@eyeauras/cli-factory'),manifest=JSON.parse(await readFile(join(path,'package.json'),'utf8'));factory=join(path,manifest.main);break;}catch(error){if(error.code!=='ENOENT')throw error;}}
assert.ok(factory);const preload=join(root,'fixture-environment.mjs');
await writeFile(preload,`import{AppArguments}from ${JSON.stringify(pathToFileURL(factory).href)};const original=AppArguments.CurrentEnvironment;AppArguments.CurrentEnvironment=()=>({...original(),EnvironmentAppData:${JSON.stringify(join(root,'appdata'))},EnvironmentLocalAppData:${JSON.stringify(join(root,'local'))}});`);
const env={...process.env,NODE_OPTIONS:'--import '+pathToFileURL(preload).href};
let scope,sequence=0;const calls=[],checks={};
const sha=b=>createHash('sha256').update(b).digest('hex');
async function call(args,{failure=false,global=false}={}){
 const started=performance.now();let r,code=0;
 try{r=await exec(process.execPath,[cli,...(global?[]:['--profile',profile]),...args,'--json'],{env,cwd:root,timeout:600000,maxBuffer:4*1024**2});}catch(error){r=error;code=error.code;}
 const n=++sequence;await writeFile(join(root,n+'.stdout'),r.stdout??'');await writeFile(join(root,n+'.stderr'),r.stderr??'');calls.push({n,args,code,milliseconds:performance.now()-started});
 assert.equal(code===0,!failure,'Inspect private transcript '+n);return JSON.parse(r.stdout);
}
const scoped=(args,options)=>call(['ghidra',...args,'--session',scope.session,'--target',scope.target],options);
async function rpc(args){
 const child=spawn(process.execPath,[cli,'--json-rpc'],{env,cwd:root,stdio:['pipe','pipe','pipe']});let output='',errors='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>errors+=b);
 child.stdin.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'cli.execute',params:{argv:['--profile',profile,'ghidra',...args,'--session',scope.session,'--target',scope.target]}})+'\n');
 const code=await new Promise(ok=>child.once('close',ok));await writeFile(join(root,'rpc.stdout'),output);await writeFile(join(root,'rpc.stderr'),errors);assert.equal(code,0);return output.trim().split('\n').map(line=>JSON.parse(line)).find(r=>r.id===1);
}
try{
 const source=join(root,'fixture.c'),obj=join(root,'fixture.obj'),input=join(root,'fixture.exe');
 await writeFile(source,'__declspec(noinline) int second(int x){return x+17;}\n__declspec(noinline) int first(int x){return second(x)+1;}\nint main(void){return first(2);}\n');
 await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);
 await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:first','/export:second','/export:main','/out:'+input,obj]);
 const inputHash=sha(await readFile(input));
 await call(['profile','create',profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])],{global:true});await call(['permissions','grant','Update']);
 scope=await call(['ghidra','open',input,'--session','new']);assert.equal(scope.state,'ready');
 const entry=(await scoped(['functions','inspect','--function','first','--fields','entry_point'])).value;
 assert.match(entry.entry_point,/^[a-f0-9]+$/i);checks.requestedEntryPoint=true;
 const direct=await scoped(['functions','decompile','--address',entry.entry_point]);
 assert.ok(direct.code.length);checks.directDecompile=true;
 const args=['functions','inspect','--functions','first,second,missing','--fields','decompiled_code,callees','--limit-chars','8'];
 const first=(await scoped(args)).value;
 if(o['expect-broken']){
  for(const name of ['first','second'])assert.equal(first.functions[name].reason,'invalid_native_shape');checks.reproducedInvalidNativeShape=true;
 }else{
  for(const name of ['first','second']){assert.equal(first.functions[name].status,'success');assert.ok(first.functions[name].decompiled_code.length);assert.equal(first.functions[name].entry_point,undefined);}
  assert.equal(first.functions.missing.reason,'function_not_found');assert.ok(first.functions.first.callees.some(row=>JSON.stringify(row).includes('second')));checks.filteredMixedBatchAndCallEdge=true;
  const single=(await scoped(['functions','inspect','--function','first','--fields','decompiled_code,callees'])).value;
  assert.equal(single.status,'success');assert.equal(single.decompiled_code,direct.code);checks.single=true;
  const next=(await scoped([...args,'--offset-chars','8','--expect-view',first.view.identity])).value;
  assert.equal(next.functions.first.text.textSha256,first.functions.first.text.textSha256);assert.equal(first.functions.first.decompiled_code+next.functions.first.decompiled_code,Array.from(single.decompiled_code).slice(0,16).join(''));checks.paging=true;
  const message=await rpc(args);assert.deepEqual(message.result.value,first);checks.rpc=true;
  const directory=join(root,'saved');const saved=(await scoped([...args,'--save-owner-directory',directory])).value;
  for(const name of ['first','second']){const row=saved.functions[name];assert.equal(sha(await readFile(row.savedText.file)),row.savedText.textSha256);assert.equal(row.entry_point,undefined);}
  assert.deepEqual(JSON.parse(await readFile(join(directory,'manifest.json'),'utf8')).value,saved);checks.savedManifest=true;
  const setup='import ghidra.app.script.GhidraScript; import ghidra.program.model.data.ByteDataType; public class OwnedSparseNavigation extends GhidraScript {public void run() throws Exception {var at=toAddr("180000000");var memory=currentProgram.getMemory();var block=memory.createInitializedBlock("owned-navigation",at,4096,(byte)0,monitor,false);block.setExecute(true);for(int i=0;i<32;i++)createData(at.add(i),ByteDataType.dataType);memory.setBytes(at.add(0x200),"OWNED_LATE_STRING\\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));createAsciiString(at.add(0x200));memory.setBytes(at.add(0x250),"OWNED_UNDEFINED\\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));memory.setByte(at.add(0x300),(byte)0xc3);}}';
  await scoped(['scripts','run-inline','--code',setup,'--request-id','owned-sparse-navigation']);
  const strings=['strings','list','--filter','OWNED_LATE_STRING'];
  const incomplete=(await scoped([...strings,'--max-scan','1'])).value;
  assert.equal(incomplete.strings.length,0);assert.equal(incomplete.total_known,false);assert.equal(incomplete.truncated,true);assert.equal(incomplete.scan.complete,false);
  const offset=(await scoped([...strings,'--max-scan','1','--offset','10'])).value;assert.equal(offset.strings.length,0);assert.equal(offset.scan.visited,1);
  const complete=(await scoped([...strings,'--max-scan','200000'])).value;assert.equal(complete.scan.complete,true);assert.ok(complete.strings.some(row=>row.value==='OWNED_LATE_STRING'));checks.lateStringAndIncompleteZero=true;
  const undefinedString=(await scoped(['strings','list','--filter','OWNED_UNDEFINED'])).value;assert.equal(undefinedString.strings.length,0);
  const bytes=(await scoped(['analysis','search-byte-patterns','--pattern',Buffer.from('OWNED_UNDEFINED').toString('hex'),'--scan-from','180000000','--max-bytes','4096'])).value;
  assert.ok(JSON.stringify(bytes).includes('180000250'));checks.undefinedLiteralByteSearch=true;
  const before=(await scoped(['functions','inspect','--function','first','--fields','entry_point'])).value;
  const absent=await scoped(['functions','decompile','--address','180000300'],{failure:true});assert.equal(absent.reason,'function_not_found');
  assert.match(await readFile(join(root,sequence+'.stderr'),'utf8'),/functions decode/);
  const decoded=(await scoped(['functions','decode','--address','180000300','--max-bytes','1','--max-instructions','1'])).value;
  assert.equal(decoded.instructions[0].mnemonic.toLowerCase(),'ret');assert.equal(decoded.read_only.modification_unchanged,true);
  const after=(await scoped(['functions','inspect','--function','first','--fields','entry_point'])).value;assert.equal(after.view.identity,before.view.identity);
  const stillAbsent=(await scoped(['functions','inspect','--functions','180000300','--fields','decompiled_code'])).value.functions['180000300'];assert.equal(stillAbsent.reason,'function_not_found');assert.match(stillAbsent.error,/functions decode/);checks.unseededDecodeReadOnlyGuidance=true;
 }
 assert.equal(sha(await readFile(input)),inputHash);checks.inputUnchanged=true;
}finally{
 const cleanup=[];
 if(scope)try{await scoped(['close']);}catch{cleanup.push('close');}
 try{await call(['ghidra','server','stop']);}catch{cleanup.push('server');}
 try{await call(['ipc-server','stop'],{global:true});}catch{cleanup.push('owner');}
 await writeFile(join(root,'report.json'),JSON.stringify({checks,calls,cleanup},null,2)+'\n');console.log(JSON.stringify({checks,cleanup}));assert.deepEqual(cleanup,[]);
}
