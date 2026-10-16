import {p3Inputs} from './native-p3-inputs.mjs';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {nativeProofGuard} from './native-proof-guard.mjs';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,copyFile,readdir} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const k=process.argv[i];if(k==='--ack-disposable')options.ack=true;else if(k.startsWith('--')&&process.argv[i+1])options[k.slice(2)]=process.argv[++i];else throw Error('Invalid option');}
nativeProofGuard(options.ack);const sourceHashes=await p3Inputs();
const packageRoot=options['installed-package']??fileURLToPath(new URL('../skills/ghidra-coordinator/',import.meta.url));
const load=name=>import(pathToFileURL(join(packageRoot,'dist','src',name+'.js')).href);
const {createInsightCli}=await load('cli'),{GhidraContexts}=await load('contexts'),{GhidraServer}=await load('server'),{nativeInputs,pinnedMcpJar,nativeJvmDirectories}=await load('native-inputs');
const {createCliFixture}=await import(options['installed-package']?pathToFileURL(join(packageRoot,'..','..','@eyeauras','cli-factory','dist','src','testing.js')).href:'@eyeauras/cli-factory/testing');
for(const [path,sha]of Object.entries(sourceHashes))if(/^skills\/ghidra-coordinator\/(dist\/src|references)\//.test(path))assert.equal(createHash('sha256').update(await readFile(join(packageRoot,path.replace('skills/ghidra-coordinator/','')))).digest('hex'),sha,'Installed executable resource differs: '+path);
const packageSha256=options['installed-tarball']?createHash('sha256').update(await readFile(options['installed-tarball'])).digest('hex'):undefined;for(const k of ['java','ghidra-home','clang','lld'])assert.ok(options[k]);
const values={java:options.java,ghidraHome:options['ghidra-home']},f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
const directory=join(f.appArguments.AppDataDirectory,'workspace'),exec=promisify(execFile),cases=[];let app,native,context,inputs,workspace,receipt;
let publications=0,losePublication=false;
function wrap(real){return new Proxy(real,{get(target,key){if(key==='fork')return c=>wrap(target.fork(c));const value=target[key];if(key==='publish')return async(...args)=>{publications++;const result=await value.apply(target,args);if(losePublication){losePublication=false;throw Error('Owned native publication response loss');}return result;};return typeof value==='function'?value.bind(target):value;}});}
function start(){app=f.createApplication(runtime=>createInsightCli({runtime,backend:async(w,c)=>{workspace=w;context=c;inputs=await nativeInputs(values,w.directory);native=new GhidraContexts(w,inputs,c);return wrap(native);}}));return app;}
function passed(name){cases.push(name);console.log('Native P3 passed:',name);}
const sel=s=>['--session',s.session,'--target',s.target];
async function command(args){const r=await f.run(app,[...args,'--json']);if(r.exitCode){await writeFile(join(f.root,'failure.json'),JSON.stringify({args,...r}),{mode:0o600});throw Error('Native P3 command failed: '+args.slice(0,3).join(' ')+': '+r.stderr);}return JSON.parse(r.stdout);}
const run=(s,path,args=[])=>command(['ghidra',...path.split(' '),...sel(s),...args]);
const policy=(s,publish,refresh='manual')=>run(s,'sync-policy set',['--publish',publish,'--refresh',refresh]);
const set=(s,at,kind,text,extra=[])=>run(s,'comments set',['--address',at,'--kind',kind,'--text',text,...extra]);
const get=async(s,at,kind)=>(await run(s,'comments get',['--address',at,'--kind',kind])).text;
try{
 const base=await nativeInputs(values),module=join(f.root,'OwnedP3');await mkdir(join(module,'lib'),{recursive:true});await mkdir(join(module,'data','languages'),{recursive:true});await mkdir(join(module,'ghidra_scripts'));
 await writeFile(join(module,'Module.manifest'),'');await writeFile(join(module,'extension.properties'),'name=OwnedP3\nversion=12.1.2\ndescription=Disposable P3 acceptance\nauthor=insight-cli\ncreatedOn=2026-10-15\n');
 const fixture=new URL('./fixtures/p3/',import.meta.url),classes=join(f.root,'classes');await mkdir(classes);
 await exec(join(dirname(base.java),'javac'),['-proc:none','-cp',base.classpath,'-d',classes,...['OwnedP3Analyzer.java','OwnedP3Plugin.java'].map(n=>fileURLToPath(new URL(n,fixture)))]);
 await exec(join(dirname(base.java),'jar'),['--create','--file',join(module,'lib','OwnedP3.jar'),'-C',classes,'.']);
 for(const name of ['owned.slaspec','owned.ldefs','owned.pspec','owned.cspec'])await copyFile(new URL(name,fixture),join(module,'data','languages',name));
 await exec(base.java,[...nativeJvmDirectories(f.root),'-cp',base.classpath,'ghidra.pcodeCPort.slgh_compile.SleighCompile',join(module,'data','languages','owned.slaspec'),join(module,'data','languages','owned.sla')]);
 await copyFile(new URL('OwnedP3Script.java',fixture),join(module,'ghidra_scripts','OwnedP3Script.java'));
 start();const inspected=await command(['ghidra','extensions','inspect','--directory',module]);await command(['ghidra','extensions','install','--directory',module,'--sha256',inspected.sha256]);
 const installed=await command(['ghidra','extensions','list']);assert.equal(installed.items[0].sha256,inspected.sha256);passed('N10 immutable profile module consumes compiled analyzer, GUI plugin, Sleigh processor and script');
 for(const [kind,needle]of [['languages','OwnedP3:LE:16:default'],['analyzers','ownedp3.OwnedP3Analyzer'],['plugins','ownedp3.OwnedP3Plugin']]){
  const found=await command(['ghidra','extensions','capabilities','--kind',kind,'--filter','OwnedP3']);assert.ok(found.items.some(r=>r.id===needle));if(kind!=='languages')assert.ok(found.items.find(r=>r.id===needle).managed);
 }
 passed('N10 actual SDK discovers the managed language/compiler, analyzer and plugin');
 const input=join(f.root,'inputs');await mkdir(input);const src=join(input,'owned.c'),obj=join(input,'owned.obj'),exe=join(input,'owned.exe');
 await writeFile(src,'__declspec(noinline) int first(int x){return x*7+3;}\nint main(void){return first(2);}\n');await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',src,'-o',obj]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/out:'+exe,obj]);
 const a=await command(['ghidra','open',exe,'--session','new']),b=await command(['ghidra','open',exe,'--session','new']);
 const fn=(await native.call(a,'/get_functions',{functions:'first',fields:'entry_point',include_call_context:false})).functions.first.entry_point;
 const min=fn,originalPre=await get(b,min,'pre');
 await run(a,'analysis configure-analyzer',['--name','OwnedP3 marker','--enabled','true']);await run(a,'analysis reanalyze');assert.equal(await get(a,min,'pre'),'OwnedP3 analyzer ran');assert.equal(await get(b,min,'pre'),originalPre);
 const scripts=await run(a,'scripts list',['--filter','OwnedP3Script']);assert.ok(scripts.value.items.some(r=>r.script==='extension:OwnedP3/OwnedP3Script.java'));
 await run(a,'scripts run',['--script-name','extension:OwnedP3/OwnedP3Script.java']);assert.equal(await get(a,min,'post'),'OwnedP3 script ran');
 await run(a,'merge');await run(b,'refresh');assert.equal(await get(b,min,'pre'),'OwnedP3 analyzer ran');passed('N10 managed analyzer configuration/run and explicit extension script; independent saved state and shared publication');
 const raw=join(input,'owned.raw');await writeFile(raw,Buffer.from([0,1,0,1]));const language=await command(['ghidra','open',raw,'--session','new','--loader','BinaryLoader','--language','OwnedP3:LE:16:default','--compiler-spec','default','--no-analysis','--loader-options','{"Base Address":"0x0"}']);
 const assembly=(await run(language,'assembly preview',['--address','0','--instructions','["NOP"]'])).value;assert.equal(assembly.bytes_hex,'00');await run(language,'close');passed('N10 real custom Sleigh language imports and assembles an instruction');
 await run(a,'plugins set',['--plugin','ownedp3.OwnedP3Plugin','--enabled','true','--request-id','p3-plugin-enable']);assert.ok((await run(a,'plugins list')).value.items.some(r=>r.id==='ownedp3.OwnedP3Plugin'));
 await run(a,'plugins set',['--plugin','ownedp3.OwnedP3Plugin','--enabled','false']);assert.equal((await run(a,'plugins list')).value.items.length,0);await run(a,'close');passed('N10 owned GUI plugin enable/readback/disable; no shared GUI context');
 await policy(a,'after-edit');const edited=await set(a,fn,'eol','A automatic',['--request-id','p3-auto-a']);assert.equal(edited.automatic.publication.state,'merged');assert.equal(edited.pendingChanges,0);assert.equal(await get(b,fn,'eol'),null);
 await policy(b,'after-edit','before-edit');const refreshed=await set(b,fn,'pre','B automatic');assert.equal(refreshed.automatic.refresh.state,'updated');assert.equal(await get(b,fn,'eol'),'A automatic');assert.equal(refreshed.pendingChanges,0);
 const count=publications;assert.deepEqual(await set(a,fn,'eol','A automatic',['--request-id','p3-auto-a']),edited);assert.equal(publications,count);passed('Automatic after-edit publication and before-edit refresh; manual reads stay private and request replay does not publish again');
 await policy(b,'manual');await set(b,fn,'eol','B retained conflict');await set(b,fn,'plate','B disjoint retained');await set(a,fn,'eol','A newer');await policy(b,'after-save');
 const conflict=await f.run(app,['ghidra','save',...sel(b),'--request-id','p3-auto-conflict','--json']);assert.notEqual(conflict.exitCode,0);assert.equal(await get(b,fn,'eol'),'B retained conflict');assert.equal(await get(b,fn,'plate'),'B disjoint retained');passed('Automatic after-save conflict publishes nothing and retains the complete local snapshot');
 await run(b,'close');const c=await command(['ghidra','open',exe,'--session','new']);await policy(c,'after-edit');losePublication=true;
 const lost=['ghidra','comments','set',...sel(c),'--address',fn,'--kind','post','--text','lost native reply','--request-id','p3-auto-lost'];assert.notEqual((await f.run(app,[...lost,'--json'])).exitCode,0);const once=publications;
 await app.dispose();start();await run(c,'open');const recovered=await command(lost);assert.equal(recovered.automatic.publication.state,'merged');assert.equal(publications,once);assert.equal((await run(c,'sync-policy get')).publish,'after-edit');assert.equal(await get(c,fn,'post'),'lost native reply');passed('Lost native publication reply and owner replacement reconcile one actual check-in; policy/local work survive');
 await command(['ghidra','extensions','disable','--name','OwnedP3']);assert.notEqual((await f.run(app,['ghidra','comments','get',...sel(c),'--address',fn,'--kind','post','--json'])).exitCode,0);await app.dispose();start();
 assert.equal((await command(['ghidra','extensions','capabilities','--kind','analyzers','--filter','OwnedP3'])).items.length,0);
 await command(['ghidra','extensions','enable','--name','OwnedP3']);await app.dispose();start();await run(c,'open');assert.equal(await get(c,fn,'post'),'lost native reply');passed('Extension enablement changes require owner replacement; saved private state resumes with the original pinned module');
 assert.deepEqual(await p3Inputs(),sourceHashes,'Executable inputs changed during native acceptance');
 receipt={schema:1,state:'passed',sourceHashes,installation:options['installed-package']?'isolated-installed-package':'source-workspace',...(packageSha256?{packageSha256}:{}),scope:'P3 profile extension lifecycle, custom SDK language/analyzer/script/GUI plugin and automatic publication/refresh on owned real Ghidra',cases,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar};
}catch(error){console.error('Owned P3 diagnostics:',f.root);throw error;}
finally{await app?.dispose();if(context)await new GhidraServer(directory,inputs,context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
