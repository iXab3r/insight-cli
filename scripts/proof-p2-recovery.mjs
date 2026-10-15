// Actual SDK mutation reply loss: reconcile immutable saved bytes, never dispatch the edit twice.
import {nativeProofGuard} from './native-proof-guard.mjs';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {writeFile,readFile,mkdir} from 'node:fs/promises';import {join} from 'node:path';
import {createHash} from 'node:crypto';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];if(key==='--ack-disposable')options.ack=true;else if(key.startsWith('--')&&process.argv[i+1])options[key.slice(2)]=process.argv[++i];else throw Error('Invalid proof argument');}
nativeProofGuard(options.ack);for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key]);
const names=['src/research.ts','src/contexts.ts','src/sdk.ts','src/mutation-effects.ts','references/native/InsightSdkTools.java','references/native/InsightSdkScript.java','references/native/InsightSnapshotInspect.java'];
const sha=data=>createHash('sha256').update(data).digest('hex'),hashes=async()=>Object.fromEntries(await Promise.all(names.map(async name=>[name,sha(await readFile(new URL('../skills/ghidra-coordinator/'+name,import.meta.url)))])));
const sourceHashes=await hashes(),runnerSha256=sha(await readFile(new URL(import.meta.url))),values={java:options.java,ghidraHome:options['ghidra-home']};
const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});let context,lost=true,dispatches=0,receipt;
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const response=await fetch(...args);if(new URL(args[0]).pathname==='/run_script_inline'){
  let p;try{p=JSON.parse(Buffer.from(JSON.parse(args[1]?.body??'{}').args??'','base64').toString());}catch{}
  if(p?.operation==='/sdk/patch-bytes'&&p.parameters?.bytes_hex==='9192'){dispatches++;if(lost){lost=false;await response.clone().json();throw Error('Owned lost completed SDK mutation reply');}}
 }return response;
}},backend:async(w,c)=>{context=c;return new GhidraContexts(w,await nativeInputs(values),c);}}));
const exec=promisify(execFile),input=join(f.root,'input');await mkdir(input);const source=join(input,'fixture.c'),object=join(input,'fixture.obj'),exe=join(input,'fixture.exe');
await writeFile(source,'int main(void){return 7;}\n');await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/out:'+exe,object]);
try{
 const selected=await f.json(app,['ghidra','open',exe,'--session','new']),scope=['--session',selected.session,'--target',selected.target];
 await f.json(app,['ghidra','memory','create-block',...scope,'--name','OwnedRecovery','--address','0x180000000','--bytes-hex','9090']);
 const args=['ghidra','memory','patch-bytes',...scope,'--address','0x180000000','--expect-hex','9090','--bytes-hex','9192','--request-id','lost-sdk'];
 assert.notEqual((await f.run(app,args)).exitCode,0);assert.equal(lost,false);assert.equal(dispatches,1);
 await f.json(app,['ghidra','open',...scope]);const recovered=await f.json(app,args);assert.equal(recovered.state,'applied');assert.equal(recovered.value.bytes_hex,'9192');
 assert.deepEqual(await f.json(app,args),recovered);assert.equal(dispatches,1);assert.equal((await f.json(app,['ghidra','memory','block-state',...scope,'--name','OwnedRecovery'])).value.sha256,sha(Buffer.from('9192','hex')));
 assert.deepEqual(await hashes(),sourceHashes);receipt={schema:1,state:'passed',scope:'owned real SDK mutation response-loss recovery',cases:['Lost completed SDK patch reconciles from independently inspected immutable saved bytes without a second native edit'],dispatches,runnerSha256,sourceHashes,ghidra:'12.1.2',node:process.versions.node,mcpJarSha256:pinnedMcpJar};
}catch(error){console.error('Owned SDK recovery diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
