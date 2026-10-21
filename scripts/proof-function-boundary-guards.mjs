// Native guard controls over a disposable PE and the installed candidate; Factory testing seam only.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,readFile,writeFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {existsSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {nativeProofGuard} from './native-proof-guard.mjs';
import {digest} from './toolbox/public-fixture.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const pkg=resolve(o.package),root=resolve(o.root);await mkdir(root);const exec=promisify(execFile),load=p=>import(pathToFileURL(join(pkg,p)).href),values={java:resolve(o.java),ghidraHome:resolve(o['ghidra-home'])};
const input=join(root,'fixture.exe'),source=join(root,'fixture.c'),object=join(root,'fixture.obj');
await writeFile(source,'int main(void){return 7;}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);await exec('lld-link',['/base:0x180000000','/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,object]);
const setupSource='import ghidra.app.script.GhidraScript; import ghidra.program.model.address.AddressSet; import ghidra.program.model.symbol.SourceType; public class OwnedBoundaryEntry extends GhidraScript { public void run() throws Exception { var at=toAddr("180001000"); var manager=currentProgram.getFunctionManager(); var function=manager.getFunctionAt(at); if(function==null)manager.createFunction("owned_entry",null,at,new AddressSet(at),SourceType.USER_DEFINED); else function.setBody(new AddressSet(at)); } }';
const compile=join(root,'compile'),jars=[];await mkdir(compile);await writeFile(join(compile,'OwnedBoundaryEntry.java'),setupSource);
async function walk(dir){for(const e of await readdir(dir,{withFileTypes:true})){const p=join(dir,e.name);if(e.isDirectory())await walk(p);else if(e.name.endsWith('.jar'))jars.push(p);}}
await walk(join(values.ghidraHome,'Ghidra'));await exec(values.java.replace(/java$/,'javac'),['-proc:none','-cp',jars.join(':'),'-d',compile,join(compile,'OwnedBoundaryEntry.java')],{maxBuffer:262144});
const require=createRequire(join(pkg,'package.json')),factoryRoot=require.resolve.paths('@eyeauras/cli-factory').map(p=>join(p,'@eyeauras/cli-factory')).find(p=>existsSync(join(p,'package.json'))),manifest=JSON.parse(await readFile(join(factoryRoot,'package.json'),'utf8'));
const factory=await import(pathToFileURL(join(factoryRoot,manifest.exports['./testing'].import)).href),fixture=await factory.createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
const {createInsightCli}=await load('dist/src/cli.js'),{GhidraContexts}=await load('dist/src/contexts.js'),{nativeInputs}=await load('dist/src/native-inputs.js'),{GhidraServer}=await load('dist/src/server.js');
let backend,workspace,context,selected,mode,stage;const counts={},checks={},cleanup=[];
const lookup='/insight/function-boundaries/v1';
const app=fixture.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const path=new URL(args[0]).pathname,response=await fetch(...args);counts[path]=(counts[path]??0)+1;
 if(path===lookup&&mode){stage='lookup';
  if(mode==='editLookup'){mode=undefined;await backend.call(selected,'/set_comment',{address:'180001000',type:'eol',comment:'Owned edit after entry lookup'});}
  else if(mode==='editLostLookup'){await response.clone().text();mode=undefined;await backend.call(selected,'/set_comment',{address:'180001000',type:'eol',comment:'Owned edit before lost boundary reply'});throw Error('Owned changed and lost lookup response');}
  else if(mode==='lostLookup'){await response.clone().text();mode=undefined;throw Error('Owned lost lookup response');}
  else if(mode==='malformedLookup'){mode=undefined;return Response.json({protocol:'insight-function-boundaries-v1',modification:42});}
 }
 if(path==='/get_functions'&&mode){stage='read';
  if(mode==='wrongEntry'){const data=await response.json();mode=undefined;for(const row of Object.values(data.functions))row.entry_point='180001001';return Response.json(data);}
 }
 if(stage==='read'&&mode==='pid'&&path==='/mcp/instance_info'){const data=await response.json();mode=undefined;return Response.json({...data,pid:data.pid+100000});}
 if(stage==='read'&&mode==='program'&&path==='/get_program_options'){const data=await response.json();mode=undefined;return Response.json({...data,options:data.options.map(x=>x.name==='Executable SHA256'?{...x,value:'0'.repeat(64)}:x)});}
 if(stage==='read'&&mode==='lostView'&&path==='/insight/research-view/v1'){await response.clone().text();mode=undefined;throw Error('Owned lost final view');}
 return response;
}},backend:async(w,c)=>{workspace=w;context=c;backend=new GhidraContexts(w,await nativeInputs(values,w.directory,c),c);return backend;}}));
try{
 selected=await fixture.json(app,['ghidra','open',input,'--session','new','--no-analysis']);const selectors=['--session',selected.session,'--target',selected.target],argv=['ghidra','functions','inspect',...selectors,'--functions','180001000','--resolve-address','containing-or-pe-runtime','--max-unwind-bytes','4194304','--fields','entry_point','--include-call-context','false'];
 await fixture.json(app,['ghidra','scripts','run-inline',...selectors,'--request-id','owned-boundary-entry','--code',setupSource]);
 const good=await fixture.json(app,argv);await writeFile(join(root,'initial-inspect.json'),JSON.stringify(good,null,2));assert.equal(good.value.functions['180001000'].entry_point,'180001000');assert.equal(good.value.functions['180001000'].resolution.kind,'pe-runtime-range');assert.equal(good.value.functions['180001000'].resolution.database.kind,'exact-entry');assert.equal(good.value.boundaryLookup.state,'validated');
 checks.explicitDbAndRuntimeAgreement=true;
 const saved=workspace.context(selected),hash=saved.workingSnapshot.sha256,generation=saved.generation;
 for(const fault of ['editLookup','lostLookup','editLostLookup','malformedLookup','wrongEntry','pid','program','lostView']){
  const before={...counts};mode=fault;stage=undefined;const save=join(root,'rejected-'+fault),result=await fixture.run(app,[...argv,'--save-owner-directory',save,'--json']);assert.notEqual(result.exitCode,0,fault);assert.equal(existsSync(save),false,'Guard rejects before owner save');
  assert.equal((counts[lookup]??0)-(before[lookup]??0),1,'Lookup never replays');assert.ok((counts['/get_functions']??0)-(before['/get_functions']??0)<=1,'Function read never replays');
  if(['editLookup','editLostLookup','wrongEntry'].includes(fault))assert.equal(JSON.parse(result.stdout).reason,fault!=='wrongEntry'?'changed_view':'selector_mismatch');
  if(fault==='editLostLookup')assert.ok((counts['/insight/research-view/v1']??0)>(before['/insight/research-view/v1']??0),'Independent observation after lost dispatch');
  mode=undefined;stage=undefined;assert.equal((await fixture.json(app,argv)).value.functions['180001000'].status,'success');checks[fault]=true;
 }
 assert.equal(workspace.context(selected).workingSnapshot.sha256,hash);assert.equal(workspace.context(selected).generation,generation);checks.savedContextAvailableAndUnchanged=true;
 const record=await backend.selected(selected),endpoint=new URL(lookup,record.binding.endpoint);endpoint.searchParams.set('program',record.binding.program);endpoint.searchParams.set('addresses','180001000');endpoint.searchParams.set('max_unwind_bytes','4194304');
 assert.equal((await fetch(endpoint)).status,401);const headers={Authorization:'Bearer '+await context.secrets.require(record.binding.tokenSecret)},missing=new URL(endpoint);missing.searchParams.set('program','/not-open.exe');const response=await fetch(missing,{headers}),body=await response.json();assert.ok(!response.ok||body.error||body.success===false);checks.authAndExplicitAlreadyOpenProgram=true;
 const old=await fixture.json(app,argv);await fixture.json(app,['ghidra','close',...selectors]);await fixture.json(app,['ghidra','open',...selectors]);const count=counts[lookup],changed=await fixture.run(app,[...argv,'--expect-view',old.value.view.identity,'--json']);assert.notEqual(changed.exitCode,0);assert.equal(JSON.parse(changed.stdout).reason,'changed_view');assert.equal(counts[lookup],count,'Stale view fails before lookup');checks.restartRejectsOldViewBeforeLookup=true;
 await fixture.json(app,['ghidra','close',...selectors]);
}finally{
 try{await app.dispose();}catch(e){cleanup.push(e.message);}
 try{if(context)await new GhidraServer(workspace.directory,await nativeInputs(values),context).stop();}catch(e){cleanup.push(e.message);}
 await writeFile(join(root,'cleanup.json'),JSON.stringify({cleanup},null,2));
}
assert.deepEqual(cleanup,[]);await writeFile(join(root,'report.json'),JSON.stringify({schema:1,passed:true,checks,cleanup,inputSha256:digest(await readFile(input)),limits:['Factory testing/fetch seam over a real isolated native bridge; PID/source/reply faults are injected facts, actual comment edit and restart use owned native fixtures.','Generated AMD64 PE, metadata-only inspection with matching DB and runtime entry; full runtime range/decompile workload has separate native proof.']},null,2));console.log('Function-boundary native guards PASS');
