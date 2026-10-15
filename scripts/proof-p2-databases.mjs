import {nativeProofGuard} from './native-proof-guard.mjs';
// Owned genuine FID and BSim/H2 build/query, no-match, immutable database and lost-reply proofs.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {writeFile,readFile,mkdir} from 'node:fs/promises';import {join} from 'node:path';import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];if(key==='--ack-disposable')options.ack=true;else if(key.startsWith('--')&&process.argv[i+1])options[key.slice(2)]=process.argv[++i];else throw Error('Invalid proof option');}
nativeProofGuard(options.ack);for(const key of ['java','ghidra-home','clang','lld'])assert.ok(options[key]);
const values={java:options.java,ghidraHome:options['ghidra-home']},f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let native,context,receipt,lost=true,lostBuildCalls=0;const cases=[];
const app=f.createApplication(runtime=>createInsightCli({runtime,backend:async(w,c)=>{context=c;native=new GhidraContexts(w,await nativeInputs(values),c);
 const fork=native.fork.bind(native);native.fork=(context)=>{const scoped=fork(context),sdk=scoped.sdkFile.bind(scoped);scoped.sdkFile=async(operation,p)=>{const value=await sdk(operation,p);if(operation==='fid-build'&&p.library==='OwnedLostFID'){lostBuildCalls++;if(lost){lost=false;throw Error('Owned lost reply after native completed database receipt');}}return value;};return scoped;};return native;}}));
const exec=promisify(execFile),input=join(f.root,'inputs');await mkdir(input);
async function compile(name,code,exported){const source=join(input,name+'.c'),object=join(input,name+'.obj'),exe=join(input,name+'.exe');await writeFile(source,code);
 await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',object]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:'+exported,'/out:'+exe,object]);return exe;}
const library=await compile('library','__declspec(noinline) unsigned first(unsigned value){return value*7+3;}\nint main(void){return first(2);}\n','first'),
 different=await compile('different','__declspec(noinline) unsigned unrelated(const unsigned char *s){unsigned h=0x1234;for(unsigned i=0;i<64&&s[i];i++)h=(h<<5)^((h>>7)+(unsigned)s[i]);return h;}\nconst unsigned char input[]={1,2,3,0};int main(void){return unrelated(input);}\n','unrelated');
const select=s=>['--session',s.session,'--target',s.target],sha=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
async function run(s,path,args=[]){const command=['ghidra',...path.split(' '),...select(s),...args,'--json'],result=await f.run(app,command);
 if(result.exitCode){await writeFile(join(f.root,'failure.json'),JSON.stringify({command,...result}),{mode:0o600});throw Error('Native database case failed '+path+': '+result.stderr);}return JSON.parse(result.stdout);}
function passed(name){cases.push(name);console.log('Native database passed:',name);}
try{
 const a=await f.json(app,['ghidra','open',library,'--session','new']),b=await f.json(app,['ghidra','open',different,'--session',a.session]);
 const at=(await native.call(a,'/get_functions',{functions:'first',fields:'entry_point',include_call_context:false})).functions.first.entry_point,
  other=(await native.call(b,'/get_functions',{functions:'unrelated',fields:'entry_point',include_call_context:false})).functions.unrelated.entry_point;
 const fidFolder=join(f.root,'fid'),fid=await run(a,'libraries build-fid',['--library','OwnedFID','--library-version','1','--output-directory',fidFolder,'--request-id','fid-build']);
 assert.equal(fid.value.format,'FID');assert.ok(fid.value.included>=1);assert.equal(fid.value.library.version,'1');const fidFile=join(fidFolder,'database.fidb'),fidHash=await sha(fidFile);
 const match=await run(a,'libraries fid-query',['--database',fidFile,'--function',at,'--threshold','1']);assert.equal(match.databaseSha256,fidHash);assert.equal(match.value.complete,true);assert.equal(match.value.no_match,false);assert.ok(match.value.items.some(row=>row.name==='first'&&row.library.name==='OwnedFID'&&row.score>0));
 const absent=(await run(b,'libraries fid-query',['--database',fidFile,'--function',other,'--threshold','1'])).value;assert.equal(absent.no_match,true);assert.equal(absent.complete,true);assert.equal(await sha(fidFile),fidHash);passed('Genuine FID build/version/provenance, scored match, no-match and immutable query database');
 const bsimFolder=join(f.root,'bsim'),bsim=await run(a,'libraries build-bsim',['--library','OwnedBSim','--output-directory',bsimFolder]);assert.equal(bsim.value.format,'BSim/H2');assert.ok(bsim.value.database.signature_major>0);
 const bsimFile=join(bsimFolder,'database.mv.db'),bsimHash=await sha(bsimFile),nearest=await run(a,'libraries bsim-query',['--database',bsimFile,'--function',at,'--similarity','0.99']);
 assert.equal(nearest.databaseSha256,bsimHash);assert.ok(nearest.value.items.some(row=>row.name==='first'&&row.similarity>=0.99&&row.significance>=0));assert.equal(nearest.value.no_match,false);
 const noSimilar=(await run(b,'libraries bsim-query',['--database',bsimFile,'--function',other,'--similarity','0.99'])).value;assert.equal(noSimilar.queried_functions,1);assert.equal(noSimilar.no_match,true);assert.equal(noSimilar.complete,true);assert.equal(await sha(bsimFile),bsimHash);passed('Genuine BSim/H2 signature generation, native nearest scores/no-match and immutable query database');
 const lostFolder=join(f.root,'lost-fid'),args=['ghidra','libraries','build-fid',...select(a),'--library','OwnedLostFID','--library-version','1','--output-directory',lostFolder,'--request-id','lost-fid'];
 assert.notEqual((await f.run(app,[...args,'--json'])).exitCode,0);assert.equal(lost,false);const recovered=await f.json(app,args);assert.equal(recovered.state,'exported');assert.equal(recovered.value.library.name,'OwnedLostFID');assert.equal(lostBuildCalls,1);
 assert.deepEqual(await f.json(app,args),recovered);assert.equal(lostBuildCalls,1);passed('Lost native database-build reply reconciles completed hashed outputs without another build');
 receipt={schema:1,state:'passed',scope:'owned real native FID and BSim/H2 workflows',cases,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,
  limitations:['Owned tiny static PE libraries and local embedded H2 only; no external server provisioning or universal similarity claims.','Native scores are not calibrated probabilities; at most 1000 functions per input and bounded output.']};
}catch(error){console.error('Owned database diagnostics:',f.root);throw error;}
finally{await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
