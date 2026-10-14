// Local-only, owned disposable server/fixtures. No existing project/configuration is opened.
import assert from 'node:assert/strict';
import {spawn,execFile} from 'node:child_process';import {promisify}from'node:util';
import {mkdir,mkdtemp,readFile,writeFile,readdir,open,realpath,cp,rm}from'node:fs/promises';
import {join,resolve,delimiter}from'node:path';import{tmpdir}from'node:os';import{createHash,randomUUID}from'node:crypto';import{setTimeout as delay}from'node:timers/promises';
import {createServer}from'node:net';
import {AppArguments,ProfileStore,KeyringSecretStore,ProfileSecrets}from'@eyeauras/cli-factory';
import {HttpBridge}from'../skills/ghidra-coordinator/dist/src/transport.js';
import {fileURLToPath} from 'node:url';
const source=fileURLToPath(new URL('../',import.meta.url));
const args=process.argv.slice(2), options={};
for(let i=0;i<args.length;i++){const arg=args[i];if(arg==='--ack-disposable')options.ack=true;else if(arg==='--faults')options.faults=true;else if(arg.startsWith('--')&&args[i+1]&&!args[i+1].startsWith('--'))options[arg.slice(2)]=args[++i];else throw Error('Unsupported acceptance argument');}
if(Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]))throw Error('Real writes are refused in CI');
assert.equal(options.ack,true,'Pass --ack-disposable');
for(const key of ['ghidra-home','java','mcp-jar','python','bridge-directory','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const ghidraHome=resolve(options['ghidra-home']),java=resolve(options.java),jar=resolve(options['mcp-jar']);
const scratch=await realpath(await mkdtemp(join(process.platform==='win32'?tmpdir():'/tmp','ir-')));
const applicationId='ia-'+randomUUID().slice(0,8);
const appArguments=new AppArguments({AppName:applicationId,Profile:'default',Environment:{AppDomainDirectory:scratch,ApplicationExecutablePath:join(scratch,'fixture-bin.mjs'),EnvironmentAppData:scratch,EnvironmentLocalAppData:scratch,ProcessId:process.pid}});
const root=appArguments.AppDataDirectory;await mkdir(root,{recursive:true,mode:0o700});
const exec=promisify(execFile);const jars=[jar];
async function collect(path){for(const item of await readdir(path,{withFileTypes:true})){const child=join(path,item.name);if(item.isDirectory())await collect(child);else if(item.isFile()&&child.endsWith('.jar'))jars.push(child);}}
await collect(join(ghidraHome,'Ghidra'));const classpath=jars.join(delimiter);
async function port(){const s=createServer();await new Promise((ok,bad)=>{s.once('error',bad);s.listen(0,'127.0.0.1',ok);});const p=s.address().port;await new Promise(ok=>s.close(ok));return p;}
let basePort;for(let i=0;i<20;i++){const candidate=20000+Math.floor(Math.random()*20000);const holders=[];try{for(const p of [candidate,candidate+1,candidate+2]){const s=createServer();await new Promise((ok,bad)=>{s.once('error',bad);s.listen(p,'127.0.0.1',ok);});holders.push(s);}basePort=candidate;break;}catch{}finally{for(const s of holders)await new Promise(ok=>s.close(ok));}}assert.ok(basePort);
const serverOrigin=`ghidra://127.0.0.1:${basePort}`,serverData=join(root,'server-data');await mkdir(serverData,{mode:0o700});
const config=join(root,'server-admin.conf');await writeFile(config,'ghidra.repositories.dir='+serverData+'\n',{mode:0o600});
const children=[];let ownerBin;
async function startJava(label,argv,env={}){const path=join(root,label);await mkdir(path,{recursive:true,mode:0o700});const log=await open(join(path,'runtime.log'),'a',0o600);const child=spawn(java,['-Djava.awt.headless=true','-Dghidra.home='+ghidraHome,'-Duser.home='+path,'-Djava.io.tmpdir='+path,'-cp',classpath,...argv],{cwd:path,env:{PATH:process.env.PATH,HOME:path,TMPDIR:path,XDG_RUNTIME_DIR:root,...env},stdio:['ignore',log.fd,log.fd]});await log.close();children.push(child);return child;}
async function waitServer(child,label){for(let i=0;i<1200;i++){if(child.exitCode!==null)throw Error('Owned disposable server exited');try{if((await readFile(join(root,label,'runtime.log'),'utf8')).includes('Command watcher started'))return;}catch{}await delay(100);}throw Error('Disposable server readiness timeout');}
async function stop(child){if(!child||child.exitCode!==null||child.signalCode!==null)return;child.kill('SIGTERM');await Promise.race([new Promise(ok=>child.once('exit',ok)),delay(5000).then(()=>{child.kill('SIGKILL');return new Promise(ok=>child.once('exit',ok));})]);}
async function bootstrap(){const p=await port();const child=await startJava('bootstrap',['-Xmx768m','com.xebyte.headless.GhidraMCPHeadlessServer','--bind','127.0.0.1','--port',String(p)],{GHIDRA_SERVER_HOST:'127.0.0.1',GHIDRA_SERVER_PORT:String(basePort),GHIDRA_SERVER_USER:'publisher',GHIDRA_SERVER_PASSWORD:'changeme',GHIDRA_MCP_SHARED_PROJECT_DIR:join(root,'bootstrap'),GHIDRA_MCP_FILE_ROOT:root,GHIDRA_MCP_ALLOW_SCRIPTS:'0'});const http=new HttpBridge(`http://127.0.0.1:${p}`);for(let i=0;i<600;i++){try{const info=await http.instance();assert.equal(info.pid,child.pid);return {http,child};}catch{if(child.exitCode!==null)throw Error('Bootstrap JVM exited');await delay(100);}}throw Error('Bootstrap readiness timeout');}
const keyring=new KeyringSecretStore(),secrets=new ProfileSecrets(keyring,applicationId,'default');
const store=new ProfileStore({applicationId,appArguments});
const values={server:serverOrigin,readerUser:'reader',publisherUser:'publisher',java,ghidraHome,mcpJar:jar,mcpJarSha256:createHash('sha256').update(await readFile(jar)).digest('hex'),python:resolve(options.python),bridgeDirectory:resolve(options['bridge-directory'])};
await store.set('default',values);await store.setPermissions('default',['ReadOnly','Update']);
ownerBin=join(root,'fixture-bin.mjs');
const artifactDirectory=join(root,'artifacts');await mkdir(artifactDirectory);
const packed=JSON.parse((await exec('npm',['pack','--ignore-scripts','--json','--workspace','@ixab3r/insight-ghidra','--pack-destination',artifactDirectory],{cwd:source})).stdout)[0];
await writeFile(join(root,'package.json'),JSON.stringify({name:'disposable-insight-owner',version:'0.1.0',type:'module',files:['fixture-bin.mjs','fixture-config.json','.cli-package-build.json']}));
await exec('npm',['install','--ignore-scripts','--no-audit','--no-fund',join(artifactDirectory,packed.filename),join(source,'vendor/factory-ipc-a2094fb.tgz')],{cwd:root,timeout:120000,maxBuffer:262144});
await cp(join(source,'scripts/fixtures/native-owner.mjs'),ownerBin);
await writeFile(join(root,'fixture-config.json'),JSON.stringify({applicationId,appArguments:{AppName:applicationId,Profile:'default',Environment:{AppDomainDirectory:scratch,ApplicationExecutablePath:ownerBin,EnvironmentAppData:scratch,EnvironmentLocalAppData:scratch,ProcessId:1}}}),{mode:0o600});
// The actual packaged CLI/Factory dependencies participate in wrapper runtime identity.
const {writePackageBuildManifest}=await import('@eyeauras/cli-factory-ipc/build');await writePackageBuildManifest(root);
const invoke=async(argv)=>{try{const r=await exec(process.execPath,[ownerBin,...argv,'--json'],{cwd:root,timeout:180000,maxBuffer:2*1024*1024});return JSON.parse(r.stdout);}catch(e){let result;try{result=JSON.parse(e.stdout);}catch{}throw Object.assign(Error('Disposable CLI command failed: '+argv.slice(0,2).join(' ')),{result,diagnostic:e.stderr?.slice(0,800),code:e.code});}};
const faultPhases=options.faults?['queue','application','save','checkin','committed','verification']:[];
let server,boot;const targets=[];const findings=[];const sentinels={};
let receipt;
async function waitBarrier(){for(let i=0;i<1800;i++){try{return JSON.parse(await readFile(join(root,'barrier.json'),'utf8'));}catch{}await delay(100);}throw Error('Native fault barrier timeout');}
async function killOwner(pid){
 process.kill(pid,'SIGKILL');
 for(let i=0;i<100;i++){try{process.kill(pid,0);}catch(e){if(e.code==='ESRCH')return;throw e;}await delay(100);}
 throw Error('Killed fixture owner still appears alive');
}
async function runFaults(){
 for(const phase of faultPhases){
  const target=targets.find(t=>t.repository==='fault-'+phase);
  const worker=await invoke(['workers','start',target.id,'reader-'+phase]);
  const inspected=await invoke(['inspect',worker.id,'--functions','first']);
  const finding={requestId:'request-fault-'+phase,findingId:'finding-fault-'+phase,targetId:target.id,identity:target,workerId:worker.id,baselineVersion:worker.version,address:inspected.functions.first.entry_point,kind:'eol',before:null,after:'Synthetic crash '+phase,evidence:'Owned fixture native fault barrier'};
  const file=join(root,'finding-'+phase+'.json');await writeFile(file,JSON.stringify(finding));await invoke(['findings','submit','--file',file]);
  if(phase==='queue'){
   const status=await invoke(['status']);await killOwner(status.ownerPid);
   assert.equal((await invoke(['findings','show',finding.findingId])).state,'queued');
   assert.equal((await invoke(['integrate',target.id])).state,'published_verified');
  }else{
   await rm(join(root,'barrier.json'),{force:true});
   await writeFile(join(root,'fault.json'),JSON.stringify({phase,targetId:target.id}));
   const pending=invoke(['integrate',target.id]).then(()=>({ok:true}),()=>({ok:false}));
   const barrier=await waitBarrier();const status=await invoke(['status']);
   const batch=status.batches.find(b=>b.targetId===target.id);
   assert.ok(batch);assert.equal(barrier.ownerPid,status.ownerPid);
   await assert.rejects(invoke(['recover',batch.id]),'Live executing owner must refuse recovery');
   if(phase==='application'){
    const unauth=await fetch(barrier.binding.endpoint+'/set_comment',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({program:target.programPath,address:finding.address,type:'eol',comment:'Denied synthetic bypass'})});
    assert.equal(unauth.status,401,'Publisher must reject callers without its private token');
   }
   await killOwner(barrier.ownerPid);await pending;await rm(join(root,'fault.json'));
   const restarted=await invoke(['status']);assert.notEqual(restarted.ownerPid,barrier.ownerPid);
   assert.ok(restarted.batches.find(b=>b.id===batch.id));
   if(['committed','verification'].includes(phase)){
    const recovered=await invoke(['recover',batch.id]);assert.equal(recovered.state,'published_verified');assert.equal(recovered.publishedVersion,2);
    assert.equal((await invoke(['integrate',target.id])).state,'empty');
   }else{
    await assert.rejects(invoke(['recover',batch.id]));await assert.rejects(invoke(['integrate',target.id]));
    if(phase==='checkin')await assert.rejects(invoke(['recover',batch.id,'--abandon-staged']));
    const local=new HttpBridge(barrier.binding.endpoint,undefined,undefined,await secrets.require(barrier.binding.bridgeSecret));
    if(['application','save'].includes(phase))assert.equal((await local.call('/get_comment',{program:target.programPath,address:finding.address})).eol,finding.after);
    const history=await local.call('/server/version_history',{path:target.programPath});assert.equal(history.count,1,'A blocked stage must not be checked in');
   }
  }
  console.log('Native owner SIGKILL/restart verified:',phase);
 }
}
async function runLifecycle(){
 const target=targets[0],missingBridge=join(root,'empty-bridge');await mkdir(missingBridge);
 await store.set('default',{...values,bridgeDirectory:missingBridge});
 try{await assert.rejects(invoke(['workers','start',target.id,'failed-setup']));}
 finally{await store.set('default',values);}
 assert.ok(!(await invoke(['workers','list'])).some(w=>w.id==='failed-setup'));
 const entries=await readdir(join(root,'ghidra','processes'));assert.equal(entries.length,1);
 const failed=JSON.parse(await readFile(join(root,'ghidra','processes',entries[0],'process.json'),'utf8'));
 assert.throws(()=>process.kill(failed.pid,0),e=>e.code==='ESRCH','Failed bridge setup must stop its reader JVM');
 const reader=await invoke(['workers','start',target.id,'restart-reader']);
 const http=new HttpBridge(reader.endpoint);
 await assert.rejects(http.call('/set_comment',{program:target.programPath,address:sentinels[target.repository],type:'eol',comment:'Denied synthetic reader write'}));
 assert.equal((await http.call('/get_comment',{program:target.programPath,address:sentinels[target.repository]})).eol,'Untouched synthetic sentinel');
 await invoke(['ipc-server','stop']);
 assert.throws(()=>process.kill(reader.pid,0),e=>e.code==='ESRCH');
 await invoke(['workers','stop','restart-reader']);
 const replacement=await invoke(['workers','start',target.id,'restart-reader']);assert.notEqual(replacement.pid,reader.pid);
 await invoke(['workers','stop','restart-reader']);
 console.log('Native failed bridge cleanup, reader write denial and owner-stop/restart reuse verified');
}
async function cleanupOwnedProcesses(){
 let count=0;const directory=join(root,'ghidra','processes');let entries=[];try{entries=await readdir(directory);}catch{return count;}
 for(const entry of entries){
  let b;try{b=JSON.parse(await readFile(join(directory,entry,'process.json'),'utf8'));process.kill(b.pid,0);}catch(e){if(e.code==='ENOENT'||e.code==='ESRCH')continue;throw e;}
  assert.equal(b.projectDirectory,join(directory,entry));
  const http=new HttpBridge(b.endpoint,undefined,undefined,b.bridgeSecret?await secrets.require(b.bridgeSecret):undefined);
  const actual=await http.instance();assert.equal(actual.pid,b.pid);assert.ok(actual.project_path.startsWith(b.projectDirectory+'/'));
  process.kill(b.pid,'SIGTERM');
  for(let i=0;i<100;i++){try{process.kill(b.pid,0);}catch(e){if(e.code==='ESRCH'){count++;break;}throw e;}await delay(100);if(i===99)throw Error('Owned fixture Ghidra process did not stop');}
 }
 for(const entry of entries){
  let bridge;try{bridge=JSON.parse(await readFile(join(directory,entry,'bridge.json'),'utf8'));}catch(e){if(e.code==='ENOENT')continue;throw e;}
  for(let i=0;i<50;i++){try{process.kill(bridge.pid,0);}catch(e){if(e.code==='ESRCH')break;throw e;}await delay(100);if(i===49)throw Error('Owned fixture MCP bridge remains alive');}
 }
 return count;
}
try{
 console.log('Disposable acceptance root:',root);
 await secrets.set('readerPassword','changeme');await secrets.set('publisherPassword','changeme');
 server=await startJava('server',['-Xmx512m','ghidra.server.remote.GhidraServer','-i','127.0.0.1','-ip','127.0.0.1','-p'+basePort,'-a0','-u',serverData]);
 await waitServer(server,'server');
 await exec(java,['-Djava.system.class.loader=ghidra.GhidraClassLoader','-Djava.awt.headless=true','-Dghidra.home='+ghidraHome,'-Duser.home='+root,'-cp',classpath,'ghidra.Ghidra','ghidra.server.ServerAdmin',config,'-add','publisher','-add','reader'],{timeout:30000,maxBuffer:262144});
 for(let i=0;i<100;i++){try{const users=await readFile(join(serverData,'users'),'utf8');if(users.includes('publisher')&&users.includes('reader'))break;}catch{}await delay(100);}
 boot=await bootstrap();await boot.http.call('/server/connect');
 for(const [repository,addition]of[['alpha',17],['beta',29],...faultPhases.map((phase,i)=>['fault-'+phase,41+i])]){
  const dir=join(root,'fixtures',repository);await mkdir(dir,{recursive:true});const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
  await writeFile(c,`__declspec(noinline) int first(int x){return x+${addition};}\n__declspec(noinline) int second(int x){return x*3-${addition};}\nint main(void){return first(2)+second(4);}\n`);
  await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:second','/export:main','/out:'+exe,obj]);
  await boot.http.call('/server/repository/create',{name:repository});await boot.http.call('/server/admin/set_permissions',{repo:repository,user:'reader',access_level:'read_only'});
  const opened=await boot.http.call('/open_project',{path:serverOrigin+'/'+repository});assert.equal(opened.shared,true);assert.equal((await boot.http.call('/get_project_info')).project_server_bound,true);
  await boot.http.call('/import_file',{file_path:exe,auto_analyze:true});const program='/fixture.exe';
  const metadata=await boot.http.call('/get_metadata',{program});
  const functions=await boot.http.call('/get_functions',{functions:'first,second,main',include_call_context:false,program});
  assert.ok(functions.functions.main?.entry_point,'Exported sentinel function is missing');
  sentinels[repository]=functions.functions.main.entry_point;
  await boot.http.call('/set_comment',{program,address:sentinels[repository],type:'eol',comment:'Untouched synthetic sentinel'});
  await boot.http.call('/server/version_control/add',{path:program,comment:'Synthetic analyzed baseline',keep_checked_out:false});
  const identity={profile:'default',server:serverOrigin,repository,programPath:program,binarySha256:createHash('sha256').update(await readFile(exe)).digest('hex'),language:metadata.language,compilerSpec:metadata.compiler,imageBase:metadata.base_address};
  const path=join(root,repository+'-identity.json');await writeFile(path,JSON.stringify(identity));targets.push(await invoke(['targets','register','--file',path]));
 }
 await stop(boot.child);
 console.log('Imported two independent PE EXEs with equal basenames');
 await runLifecycle();
 const matrixTargets=targets.slice(0,2);
 const workers=await Promise.all(matrixTargets.flatMap(t=>[1,2].map(n=>invoke(['workers','start',t.id,t.repository+'-'+n]))));assert.equal(new Set(workers.map(w=>w.pid)).size,4);assert.equal(new Set(workers.map(w=>w.endpoint)).size,4);assert.equal(new Set(workers.map(w=>w.bridgePid)).size,4);
 const inspected=await Promise.all(workers.map(w=>invoke(['inspect',w.id,'--functions',w.id.endsWith('1')?'first':'second'])));
 for(let i=0;i<workers.length;i++){const w=workers[i],ref=w.id.endsWith('1')?'first':'second';const observed=inspected[i];assert.equal(observed.binding.pid,w.pid);const fn=observed.functions[ref];assert.ok(fn.decompiled_code);const expected=w.id.startsWith('alpha')?['17','0x11']:['29','0x1d'];assert.ok(expected.some(x=>fn.decompiled_code.includes(x)),'Wrong fixture decompilation');const target=targets.find(t=>t.id===w.targetId);const proposal={requestId:'request-'+w.id,findingId:'finding-'+w.id,targetId:w.targetId,identity:target,workerId:w.id,baselineVersion:w.version,address:fn.entry_point,kind:'eol',before:null,after:'Accepted synthetic finding '+w.id,evidence:'Disposable PE function decompilation verified'};const file=join(root,w.id+'-finding.json');await writeFile(file,JSON.stringify(proposal));const accepted=await invoke(['findings','submit','--file',file]);assert.deepEqual(await invoke(['findings','submit','--file',file]),accepted);findings.push(proposal);}
 console.log('Four independent bridges inspected and journaled findings');
 const [a,a2,b]=await Promise.all([invoke(['integrate',targets[0].id]),invoke(['integrate',targets[0].id]),invoke(['integrate',targets[1].id])]);assert.deepEqual(a,a2);assert.equal(a.state,'published_verified');assert.equal(b.state,'published_verified');
 console.log('Competing CLI callers shared publication; both programs verified');
 // Stop original readers, then reconnect via fresh processes after a clean server restart.
 for(const w of workers)await invoke(['workers','stop',w.id]);await stop(server);
 server=await startJava('server-restart',['-Xmx512m','ghidra.server.remote.GhidraServer','-i','127.0.0.1','-ip','127.0.0.1','-p'+basePort,'-a0','-u',serverData]);await waitServer(server,'server-restart');
 for(const target of matrixTargets){const reader=await invoke(['workers','start',target.id,target.repository+'-fresh']);const http=new HttpBridge(reader.endpoint);for(const f of findings.filter(f=>f.targetId===target.id)){const r=await http.call('/get_comment',{program:target.programPath,address:f.address});assert.equal(r.eol,f.after);}assert.equal((await http.call('/get_comment',{program:target.programPath,address:sentinels[target.repository]})).eol,'Untouched synthetic sentinel');const h=await http.call('/server/version_history',{path:target.programPath});assert.equal(h.count,2);await invoke(['workers','stop',reader.id]);}
 await runFaults();
 receipt={schema:1,scope:'disposable PE scoped comments',ghidra:'12.1.2',mcpJarSha256:values.mcpJarSha256,targets:2,readers:4,independentBridges:4,findings:4,concurrentCallers:3,publishedBatches:2,serverRestartVerified:true,sentinelPreserved:true,nativeKeyring:true,readerLifecycleVerified:true,nativeFaultPhases:faultPhases,limitations:['tiny fixtures only','no native DB merge','recoverable staged calls, no atomic remote batch',...(options.faults?['pre-intent checkouts retained for explicit operator cleanup']:['native fault injection not requested'])]};
}finally{
 if(ownerBin){try{await invoke(['ipc-server','stop']);}catch{}}
 const cleaned=await cleanupOwnedProcesses();if(receipt){receipt.retainedOwnedProcessesStopped=cleaned;receipt.bridgeCleanupVerified=true;}
 for(const child of [...children].reverse())await stop(child);
 const keys=[{service:'ai-cli-factory:'+applicationId,account:'default:readerPassword'},{service:'ai-cli-factory:'+applicationId,account:'default:publisherPassword'}];
 try{keys.push(...(await readFile(join(root,'secret-keys.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(x=>JSON.parse(x)));}catch{}
 for(const {service,account} of keys)await keyring.delete(service,account);
}
await writeFile(join(root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
