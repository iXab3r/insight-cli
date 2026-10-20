// Installed public client + native fault controls. All programs/profiles/processes are disposable.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {existsSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
import {nativeProofGuard} from './native-proof-guard.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},gui:{type:'boolean'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const pkg=resolve(o.package),root=resolve(o.root);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const load=file=>import(pathToFileURL(join(pkg,file)).href),{connectInsight,InsightCommandError}=await load('dist/src/persistent-client.js');
const exec=promisify(execFile),input=join(root,'fixture.exe'),source=join(root,'fixture.c'),obj=join(root,'fixture.obj');
await writeFile(source,'int main(void){return 7;}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,obj]);
const checks={},cleanup=[],values={java:resolve(o.java),ghidraHome:resolve(o['ghidra-home'])};
const f=await createPublicFixture(pkg,join(root,'public'));let scope,client;
try{
 await f.call(['profile','set',f.profile,'--java',values.java,'--ghidra-home',values.ghidraHome]);scope=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);
 client=await connectInsight({executable:process.execPath,arguments:[f.cli],cwd:f.project,env:f.environment});
 const selected=['--session',scope.session,'--target',scope.target],argv=['ghidra','functions','inspect',...selected,'--function','main','--fields','entry_point','--include-call-context','false'];
 const one=await f.call(argv);assert.equal(one.value.entry_point,'140001000');assert.deepEqual(await client.execute(argv),one);assert.deepEqual(await client.execute(argv),one);checks.installedPublicClientMatchesOneShot=true;
 const spans=(await readFile(join(f.appdata,'insight-cli',f.profile,'workspace/diagnostics/timings.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),traces=spans.filter(x=>x.phase==='facade.command'&&x.command==='ghidra functions inspect').slice(-3).map(x=>x.trace);
 for(const trace of traces){const calls=spans.filter(x=>x.trace===trace&&x.phase==='native.http');assert.equal(calls.filter(x=>x.operation==='/insight/research-view/v1').length,2);assert.equal(calls.filter(x=>x.operation==='/run_script_inline').length,0);}checks.twoFastReadsWithoutInlineScripts=true;
 await assert.rejects(client.execute(['ghidra','scripts','run-inline',...selected,'--code','currentProgram.getFunctionManager().getFunctionBefore(currentAddress);','--request-id','client-owned-compile-failure']),e=>e instanceof InsightCommandError&&e.rpc.data.result.state==='rejected'&&e.rpc.data.result.contextState==='ready');
 assert.deepEqual(await client.execute(argv),one);checks.typedCompileErrorAndNextRead=true;
 await client.close();client=undefined;assert.equal((await f.call(['ipc-server','status'])).running,true);checks.closeKeepsOwner=true;
}finally{
 if(client)try{await client.close();}catch(e){cleanup.push(e.message);}
 if(scope)try{await f.call(['ghidra','close','--session',scope.session,'--target',scope.target]);await f.call(['ghidra','server','stop']);}catch(e){cleanup.push(e.message);}
 try{await f.cleanup();}catch(e){cleanup.push(e.message);}
}

// Standard Factory test runtime gives a fetch seam; no copied host or altered Factory code.
const require=createRequire(join(pkg,'package.json')),factoryRoot=require.resolve.paths('@eyeauras/cli-factory').map(p=>join(p,'@eyeauras/cli-factory')).find(p=>existsSync(join(p,'package.json'))),manifest=JSON.parse(await readFile(join(factoryRoot,'package.json'),'utf8'));
const factory=await import(pathToFileURL(join(factoryRoot,manifest.exports['./testing'].import)).href),fixture=await factory.createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
const {createInsightCli}=await load('dist/src/cli.js'),{GhidraContexts}=await load('dist/src/contexts.js'),{nativeInputs}=await load('dist/src/native-inputs.js'),{GhidraServer}=await load('dist/src/server.js');
let backend,workspace,context,selected,mode,afterRead=false;const counts={};
const app=fixture.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const path=new URL(args[0]).pathname,response=await fetch(...args);counts[path]=(counts[path]??0)+1;
 if(path==='/get_functions'&&mode){afterRead=true;
  if(mode==='edit'){mode=undefined;await backend.call(selected,'/set_comment',{address:'140001000',type:'eol',comment:'Owned modification during inspection'});}
 }
 if(afterRead&&mode==='pid'&&path==='/mcp/instance_info'){const data=await response.json();mode=undefined;return Response.json({...data,pid:data.pid+100000});}
 if(afterRead&&mode==='program'&&path==='/get_program_options'){const data=await response.json();mode=undefined;return Response.json({...data,options:data.options.map(x=>x.name==='Executable SHA256'?{...x,value:'0'.repeat(64)}:x)});}
 if(afterRead&&mode==='lost'&&path==='/insight/research-view/v1'){await response.clone().text();mode=undefined;throw Error('Owned lost read reply');}
 if(afterRead&&mode==='malformed'&&path==='/insight/research-view/v1'){mode=undefined;return Response.json({protocol:'insight-research-view-v1',modification:42});}
 return response;
}},backend:async(w,c)=>{workspace=w;context=c;backend=new GhidraContexts(w,await nativeInputs(values,w.directory,c),c);return backend;}}));
try{
 selected=await fixture.json(app,['ghidra','open',input,'--session','new','--no-analysis',...(o.gui?['--mode','gui']:[])]);const selectors=['--session',selected.session,'--target',selected.target],argv=['ghidra','functions','inspect',...selectors,'--function','main','--fields','entry_point','--include-call-context','false'];
 const before=workspace.context(selected),hash=before.workingSnapshot.sha256,generation=before.generation;
 for(const fault of ['edit','pid','program','lost','malformed']){
  mode=fault;afterRead=false;const count=counts['/get_functions']??0,result=await fixture.run(app,[...argv,'--json']);assert.notEqual(result.exitCode,0);assert.equal((counts['/get_functions']??0)-count,1,'No native read replay');
  if(fault==='edit')assert.equal(JSON.parse(result.stdout).reason,'changed_view');
  mode=undefined;afterRead=false;assert.equal((await fixture.json(app,argv)).value.status,'success');checks['nativeFault_'+fault]=true;
 }
 assert.equal(workspace.context(selected).workingSnapshot.sha256,hash);assert.equal(workspace.context(selected).generation,generation);checks.readFailuresKeepSavedContext=true;
 const old=await fixture.json(app,argv),record=await backend.selected(selected),endpoint=new URL('/insight/research-view/v1',record.binding.endpoint);endpoint.searchParams.set('program',record.binding.program);
 assert.equal((await fetch(endpoint)).status,401);const headers={Authorization:'Bearer '+await context.secrets.require(record.binding.tokenSecret)};
 const missing=new URL(endpoint);missing.searchParams.set('program','/not-open.exe');const missingResult=await fetch(missing,{headers});const missingBody=await missingResult.json();assert.ok(!missingResult.ok||missingBody.error||missingBody.success===false);checks.authAndExplicitOpenProgram=true;
 await fixture.json(app,['ghidra','close',...selectors]);await fixture.json(app,['ghidra','open',...selectors]);const changed=await fixture.run(app,[...argv,'--expect-view',old.value.view.identity,'--json']);assert.notEqual(changed.exitCode,0);assert.equal(JSON.parse(changed.stdout).reason,'changed_view');checks.actualRestartRejectsOldView=true;
}finally{await app.dispose();if(context)await new GhidraServer(workspace.directory,await nativeInputs(values),context).stop();}
assert.equal(cleanup.length,0);await writeFile(join(root,'report.json'),JSON.stringify({schema:1,passed:true,faultMode:o.gui?'gui':'headless',checks,cleanup,inputSha256:digest(await readFile(input)),limits:['PID and source mismatch are injected native response facts over a real disposable bridge; restart and concurrent native comment edit are actual native operations.','Fault controls use Factory testing/fetch seam; ordinary transport/client checks use the installed public executable.']},null,2)+'\n',{mode:0o600});console.log('Persistent client and fast inspect native proof PASS');
