// Real native compile rejection with a deliberately lost HTTP reply; normal Factory API, owned fixture only.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {existsSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {nativeProofGuard} from './native-proof-guard.mjs';
const {values:o}=parseArgs({options:{package:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},root:{type:'string'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['package','java','ghidra-home','root'])assert.ok(o[k],k);
const root=resolve(o.root),pkg=resolve(o.package);await mkdir(root);
const require=createRequire(join(pkg,'package.json')),factoryRoot=require.resolve.paths('@eyeauras/cli-factory').map(p=>join(p,'@eyeauras/cli-factory')).find(p=>existsSync(join(p,'package.json')));
const manifest=JSON.parse(await readFile(join(factoryRoot,'package.json'),'utf8'));
const factory=await import(pathToFileURL(join(factoryRoot,manifest.exports['./testing'].import)).href);
const {createInsightCli}=await import(pathToFileURL(join(pkg,'dist/src/cli.js')).href),{GhidraContexts}=await import(pathToFileURL(join(pkg,'dist/src/contexts.js')).href);
const {nativeInputs}=await import(pathToFileURL(join(pkg,'dist/src/native-inputs.js')).href),{GhidraServer}=await import(pathToFileURL(join(pkg,'dist/src/server.js')).href);
const values={java:resolve(o.java),ghidraHome:resolve(o['ghidra-home'])};
const f=await factory.createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
let workspace,c,dispatches=0,lost=false,requestFile,selected,passed=false,unknownRetained=null;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const response=await fetch(...args);
 if(new URL(args[0]).pathname==='/run_script_inline'){
  const p=JSON.parse(args[1].body);if(p.code?.includes('InsightInlineExecutor.execute')){
   dispatches++;requestFile=Buffer.from(p.args,'base64').toString('utf8');await response.clone().json();lost=true;throw Error('Owned fixture lost completed native inline acknowledgement');
  }
 }
 return response;
}},backend:async(w,context)=>{workspace=w;c=context;return new GhidraContexts(w,await nativeInputs(values,w.directory,context),context);}}));
const exec=promisify(execFile),source=join(root,'fixture.c'),object=join(root,'fixture.obj'),input=join(root,'fixture.exe');
await writeFile(source,'int main(void){return 9;}\n');await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/out:'+input,object]);
try{
 selected=await f.json(app,['ghidra','open',input,'--session','new','--no-analysis']);
 const scope=['--session',selected.session,'--target',selected.target],argv=['ghidra','scripts','run-inline',...scope,'--code','currentProgram.getFunctionManager().getFunctionBefore(currentAddress);','--request-id','lost-compile-reply'];
 const result=await f.run(app,[...argv,'--json']);await writeFile(join(root,'failure.stdout'),result.stdout);await writeFile(join(root,'failure.stderr'),result.stderr);
 assert.notEqual(result.exitCode,0);assert.equal(lost,true);assert.equal(dispatches,1);
 const receipt=JSON.parse(await readFile(join(requestFile,'..','receipt.json'),'utf8'));assert.equal(receipt.execution.userCode,'not_started');assert.equal(receipt.execution.stage,'compile');
 assert.equal(workspace.scopedRequest(selected,'lost-compile-reply').state,'unknown');
 assert.notEqual((await f.run(app,[...argv,'--json'])).exitCode,0);assert.equal(dispatches,1);
 assert.notEqual((await f.run(app,['ghidra','analysis','navigation',...scope,'--json'])).exitCode,0);
 assert.equal((await f.json(app,['sessions','status',selected.session,'--target',selected.target])).ghidra.state,'needs_recovery');passed=true;
}finally{
 unknownRetained=selected?workspace.scopedRequest(selected,'lost-compile-reply')?.state==='unknown':null;
 await app.dispose();if(c)await new GhidraServer(workspace.directory,await nativeInputs(values),c).stop();
 const report={passed,lost,dispatches,unknownRetained,limits:['The native receipt exists, but the facade did not receive its completion acknowledgement. No automatic adoption or replay.','Only a generated PE and this fixture profile; journals preserved after native worker/server disposal.']};
 await writeFile(join(root,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}
