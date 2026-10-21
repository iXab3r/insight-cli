// Real disposable native endpoint with Factory testing/fetch seam for explicit guard faults.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
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
await writeFile(source,'const char anchor[]="Widget"; int main(void){return anchor[0];}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,object]);
const require=createRequire(join(pkg,'package.json')),factoryRoot=require.resolve.paths('@eyeauras/cli-factory').map(p=>join(p,'@eyeauras/cli-factory')).find(p=>existsSync(join(p,'package.json'))),manifest=JSON.parse(await readFile(join(factoryRoot,'package.json'),'utf8'));
const factory=await import(pathToFileURL(join(factoryRoot,manifest.exports['./testing'].import)).href),fixture=await factory.createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
const {createInsightCli}=await load('dist/src/cli.js'),{GhidraContexts}=await load('dist/src/contexts.js'),{nativeInputs}=await load('dist/src/native-inputs.js'),{GhidraServer}=await load('dist/src/server.js');
let backend,workspace,context,selected,mode,stage;const counts={},checks={},cleanup=[],endpoint='/insight/string-anchors/v1';
const app=fixture.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const path=new URL(args[0]).pathname,response=await fetch(...args);counts[path]=(counts[path]??0)+1;
 if(path===endpoint&&mode){stage='scan';
  if(mode==='edit'||mode==='editAndReject'){const reject=mode==='editAndReject';mode=undefined;await backend.call(selected,'/set_comment',{address:'140001000',type:'eol',comment:'Owned guard edit '+Date.now()});if(reject){await response.clone().text();throw Error('Native refused changed program');}}
  else if(mode==='lost'){await response.clone().text();mode=undefined;throw Error('Owned lost scan response');}
  else if(mode==='malformed'){mode=undefined;return Response.json({algorithm:'raw-string-anchors-v1',modification:42});}
  else if(mode==='frontier'){const value=await response.json();mode=undefined;value.scan.complete=false;value.scan.reason='byte_limit';value.scan.next=value.scan.from;return Response.json(value);}
 }
 if(stage==='scan'&&mode==='pid'&&path==='/mcp/instance_info'){const value=await response.json();mode=undefined;return Response.json({...value,pid:value.pid+100000});}
 if(stage==='scan'&&mode==='program'&&path==='/get_program_options'){const value=await response.json();mode=undefined;return Response.json({...value,options:value.options.map(x=>x.name==='Executable SHA256'?{...x,value:'0'.repeat(64)}:x)});}
 if(stage==='scan'&&mode==='lostView'&&path==='/insight/research-view/v1'){await response.clone().text();mode=undefined;throw Error('Owned lost final view');}
 return response;
}},backend:async(w,c)=>{workspace=w;context=c;backend=new GhidraContexts(w,await nativeInputs(values,w.directory,c),c);return backend;}}));
try{
 selected=await fixture.json(app,['ghidra','open',input,'--session','new','--no-analysis']);const selectors=['--session',selected.session,'--target',selected.target],argv=['ghidra','strings','anchors',...selectors,'--text','Widget','--encodings','ascii','--scan-from','140000000','--scan-through','14000ffff','--limit','1'];
 await fixture.profileStore.setPermissions('default',['ReadOnly']);
 const good=await fixture.json(app,argv);assert.equal(good.value.matches.length,1);await writeFile(join(root,'initial.json'),JSON.stringify(good,null,2));
 const saved=workspace.context(selected),hash=saved.workingSnapshot.sha256,generation=saved.generation;
 for(const fault of ['edit','editAndReject','lost','malformed','frontier','pid','program','lostView']){
  const before=counts[endpoint];mode=fault;stage=undefined;const result=await fixture.run(app,[...argv,'--json']);assert.notEqual(result.exitCode,0,fault);assert.equal(counts[endpoint]-before,1,'Read never replays');
  if(['edit','editAndReject'].includes(fault))assert.equal(JSON.parse(result.stdout).reason,'changed_view');
  mode=undefined;stage=undefined;assert.equal((await fixture.json(app,argv)).value.matches.length,1);checks[fault]=true;
 }
 assert.equal(workspace.context(selected).workingSnapshot.sha256,hash);assert.equal(workspace.context(selected).generation,generation);checks.savedContextAvailableAndUnchanged=true;
 const record=await backend.selected(selected),url=new URL(endpoint,record.binding.endpoint);for(const [k,v]of Object.entries({program:record.binding.program,text:'Widget',encodings:'ascii',scan_from:'140000000',scan_through:'14000ffff',resume_address:'140000000',resume_encoding:'ascii',max_string_bytes:1024,max_bytes:32768,max_candidates:100,timeout_seconds:5,limit:1}))url.searchParams.set(k,String(v));
 assert.equal((await fetch(url)).status,401);const headers={Authorization:'Bearer '+await context.secrets.require(record.binding.tokenSecret)},missing=new URL(url);missing.searchParams.set('program','/not-open.exe');const response=await fetch(missing,{headers}),body=await response.json();assert.ok(!response.ok||body.error||body.success===false);checks.authAndExplicitAlreadyOpenProgram=true;
 const stale=await fixture.json(app,argv);assert.ok(stale.value.cursor);await fixture.profileStore.setPermissions('default',['ReadOnly','Update']);await fixture.json(app,['ghidra','close',...selectors]);await fixture.json(app,['ghidra','open',...selectors]);const before=counts[endpoint],changed=await fixture.run(app,['ghidra','strings','anchors',...selectors,'--cursor',stale.value.cursor,'--json']);assert.notEqual(changed.exitCode,0);assert.equal(JSON.parse(changed.stdout).reason,'changed_view');assert.equal(counts[endpoint],before);checks.restartRejectsCursorBeforeScan=true;
 await fixture.json(app,['ghidra','close',...selectors]);
}finally{
 try{await app.dispose();}catch(e){cleanup.push(e.message);}
 try{if(context)await new GhidraServer(workspace.directory,await nativeInputs(values),context).stop();}catch(e){cleanup.push(e.message);}
 await writeFile(join(root,'cleanup.json'),JSON.stringify({cleanup},null,2));
}
assert.deepEqual(cleanup,[]);await writeFile(join(root,'report.json'),JSON.stringify({schema:1,passed:true,checks,cleanup,inputSha256:digest(await readFile(input)),limits:['Factory testing/fetch seam over real isolated bridge. Reply/PID/source failures and native rejection are injected; actual comment edits and restart use owned context.','Matched read-only timings use the separate public installed workload proof.']},null,2));console.log('String-anchor native guards PASS');
