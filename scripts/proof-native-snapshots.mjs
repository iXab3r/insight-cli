// Owned native fixture only: initial private-state/full-DB publication proof.
import assert from 'node:assert/strict';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,readFile,writeFile,readdir,open,realpath} from 'node:fs/promises';
import {join,resolve,delimiter,dirname,basename} from 'node:path';
import {createServer} from 'node:net';
import {randomUUID,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
import {HttpBridge} from '../skills/ghidra-coordinator/dist/src/transport.js';
const options={}; const argv=process.argv.slice(2);
for(let i=0;i<argv.length;i++){if(argv[i]==='--ack-disposable')options.ack=true;else if(argv[i].startsWith('--')&&argv[i+1])options[argv[i].slice(2)]=argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]),'Native proof is local only');
for(const key of ['ghidra-home','java','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const home=resolve(options['ghidra-home']),java=resolve(options.java),jar=resolve(options['mcp-jar']);
const root=await realpath(await mkdtemp('/tmp/insight-proof-'));const children=[];const rawExec=promisify(execFile);
async function exec(...args){try{return await rawExec(...args);}catch(error){throw Object.assign(Error('Native fixture command failed'),{stdout:error.stdout,stderr:error.stderr,code:error.code});}}
const jars=[jar];async function collect(dir){for(const e of await readdir(dir,{withFileTypes:true})){const p=join(dir,e.name);if(e.isDirectory()&&e.name!=='data')await collect(p);else if(e.isFile()&&p.endsWith('.jar')&&basename(dir)==='lib')jars.push(p);}}
await collect(join(home,'Ghidra'));const classpath=jars.join(delimiter);
const classes=join(root,'helper-classes');await mkdir(classes);
const helperSource=fileURLToPath(new URL('./fixtures/InsightSnapshotPublisher.java',import.meta.url));
const blockSource=fileURLToPath(new URL('./fixtures/InsightBlockTransfer.java',import.meta.url));
const guiSource=fileURLToPath(new URL('./fixtures/InsightGuiFixture.java',import.meta.url));
await exec(join(dirname(java),'javac'),['-proc:none','-cp',classpath,'-d',classes,helperSource,blockSource,guiSource],{timeout:30000,maxBuffer:262144});
async function port(){const s=createServer();await new Promise((ok,bad)=>{s.once('error',bad);s.listen(0,'127.0.0.1',ok);});const p=s.address().port;await new Promise(ok=>s.close(ok));return p;}
let basePort;
for(let attempt=0;attempt<30;attempt++){const candidate=20000+Math.floor(Math.random()*30000),holders=[];try{for(let p=candidate;p<candidate+3;p++){const s=createServer();await new Promise((ok,bad)=>{s.once('error',bad);s.listen(p,'127.0.0.1',ok);});holders.push(s);}basePort=candidate;break;}catch{}finally{for(const s of holders)await new Promise(ok=>s.close(ok));}}
assert.ok(basePort);const serverOrigin=`ghidra://127.0.0.1:${basePort}`;
async function launch(label,args,extra={}){const dir=join(root,label);await mkdir(dir,{recursive:true});const log=await open(join(dir,'runtime.log'),'a',0o600);const child=spawn(java,['-Djava.awt.headless=true','-Dghidra.home='+home,'-Duser.home='+dir,'-Djava.io.tmpdir='+dir,'-cp',classpath,...args],{cwd:dir,env:{PATH:process.env.PATH,HOME:dir,TMPDIR:dir,XDG_RUNTIME_DIR:root,...extra},stdio:['ignore',log.fd,log.fd]});await log.close();children.push(child);return child;}
async function stop(child){if(child.exitCode!==null||child.signalCode!==null)return;child.kill('SIGTERM');await Promise.race([new Promise(ok=>child.once('exit',ok)),delay(5000).then(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');})]);}
const credentials={GHIDRA_SERVER_HOST:'127.0.0.1',GHIDRA_SERVER_PORT:String(basePort),GHIDRA_SERVER_USER:'publisher',GHIDRA_SERVER_PASSWORD:'changeme'};
async function backend(label){const p=await port();const child=await launch(label,['-Xmx768m','com.xebyte.headless.GhidraMCPHeadlessServer','--bind','127.0.0.1','--port',String(p)],{...credentials,GHIDRA_MCP_FILE_ROOT:root,GHIDRA_MCP_SHARED_PROJECT_DIR:join(root,label),GHIDRA_MCP_ALLOW_SCRIPTS:'0'});const diagnosticFetch=async(...args)=>{const response=await fetch(...args);let value;try{value=await response.clone().json();}catch{}if(!response.ok||value?.error||value?.success===false)await writeFile(join(root,'failed-operation.json'),JSON.stringify({operation:new URL(args[0]).pathname,status:response.status,result:value}),{mode:0o600});return response;};const http=new HttpBridge(`http://127.0.0.1:${p}`,diagnosticFetch);for(let i=0;i<900;i++){try{const info=await http.instance();assert.equal(info.pid,child.pid);return{child,http};}catch{assert.equal(child.exitCode,null,'Owned backend exited');await delay(100);}}throw Error('Owned backend readiness timeout');}
async function publish(file,expected,marker){const dir=join(root,'publish-'+randomUUID());await mkdir(dir);try{const {stdout}=await exec(java,['-Djava.awt.headless=true','-Dghidra.home='+home,'-Duser.home='+dir,'-Djava.io.tmpdir='+dir,'-cp',classes+delimiter+classpath,'db.InsightSnapshotPublisher','owned','/fixture.exe',file,String(expected),marker,join(dir,'intent.json')],{cwd:dir,env:{PATH:process.env.PATH,HOME:dir,TMPDIR:dir,...credentials},timeout:120000,maxBuffer:262144});return JSON.parse(stdout);}catch(e){throw Object.assign(Error('Owned snapshot publisher failed'),{result:e.stdout,diagnostic:e.stderr});}}
async function gui(){const p=await port();const child=await launch('gui',['-Djava.awt.headless=false','-cp',classes+delimiter+classpath,'InsightGuiFixture',join(root,'private'),'private',String(p)],{GHIDRA_MCP_FILE_ROOT:root,GHIDRA_MCP_ALLOW_SCRIPTS:'0'});const http=new HttpBridge(`http://127.0.0.1:${p}`);for(let i=0;i<900;i++){try{const info=await http.instance();assert.equal(info.pid,child.pid);assert.equal(info.tcp_port,p);return{child,http};}catch{assert.equal(child.exitCode,null,'Owned GUI exited');await delay(100);}}throw Error('Owned GUI readiness timeout');}
let receipt;
try {
 const serverData=join(root,'server-data');await mkdir(serverData);const config=join(root,'admin.conf');await writeFile(config,'ghidra.repositories.dir='+serverData+'\n');
 const keystore=join(root,'owned-cert.p12');
 await exec(join(dirname(java),'keytool'),['-genkeypair','-alias','owned','-keyalg','RSA','-keysize','2048','-dname','CN=GhidraServer','-ext','SAN=IP:127.0.0.1','-ext','KU=digitalSignature,keyEncipherment','-validity','2','-keystore',keystore,'-storetype','PKCS12','-storepass:env','INSIGHT_FIXTURE_STOREPASS'],{env:{PATH:process.env.PATH,INSIGHT_FIXTURE_STOREPASS:'changeme'},timeout:30000});
 const server=await launch('server',['-Dghidra.keystore='+keystore,'-Dghidra.password=changeme','-Xmx512m','ghidra.server.remote.GhidraServer','-i','127.0.0.1','-ip','127.0.0.1','-p'+basePort,'-a0','-u',serverData]);
 for(let i=0;i<1200;i++){assert.equal(server.exitCode,null);try{if((await readFile(join(root,'server/runtime.log'),'utf8')).includes('Command watcher started'))break;}catch{}if(i===1199)throw Error('Owned server readiness timeout');await delay(100);}
 await exec(java,['-Djava.system.class.loader=ghidra.GhidraClassLoader','-Djava.awt.headless=true','-Dghidra.home='+home,'-Duser.home='+root,'-cp',classpath,'ghidra.Ghidra','ghidra.server.ServerAdmin',config,'-add','publisher'],{timeout:30000});
 for(let i=0;i<100;i++){try{if((await readFile(join(serverData,'users'),'utf8')).includes('publisher'))break;}catch{}await delay(100);}
 const dir=join(root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');await writeFile(c,'__declspec(noinline) int first(int x){return x+17;}\nint main(void){return first(2);}\n');
 await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);
 const boot=await backend('bootstrap');await boot.http.call('/server/connect');await boot.http.call('/server/repository/create',{name:'owned'});await boot.http.call('/open_project',{path:serverOrigin+'/owned'});await boot.http.call('/import_file',{file_path:exe,auto_analyze:true});
 const functions=await boot.http.call('/get_functions',{functions:'first',include_call_context:false,program:'/fixture.exe'});const address=functions.functions.first.entry_point;
 await boot.http.call('/server/version_control/add',{path:'/fixture.exe',comment:'Owned baseline',keep_checked_out:false});
 const snapshots=join(root,'snapshots');await mkdir(snapshots);await boot.http.call('/export_program',{program_name:'/fixture.exe',output_dir:snapshots,output_name:'base.gzf'});await stop(boot.child);
 const local=await backend('private');await local.http.call('/create_project',{parentDir:join(root,'private'),name:'private'});await local.http.call('/import_program',{gzf_path:join(snapshots,'base.gzf'),target_folder:'/',target_name:'fixture.exe',overwrite:false});await local.http.call('/open_program',{path:'/fixture.exe'});
 await local.http.call('/set_comment',{program:'/fixture.exe',address,type:'eol',comment:'Private full-state proof'});
 await local.http.call('/rename_function',{program:'/fixture.exe',old_name:address,new_name:'LoadFixtureConfig',strict_mode:'off'});
 await local.http.call('/create_struct',{program:'/fixture.exe',name:'ProofRecord',fields:[{name:'count',type:'uint'}]});
 await local.http.call('/set_function_prototype',{program:'/fixture.exe',function_address:address,prototype:'unsigned int LoadFixtureConfig(unsigned int count)'});
 await local.http.call('/create_memory_block',{program:'/fixture.exe',name:'ProofMemory',address:'0x150000000',size:64,read:true,write:true,execute:false});
 await local.http.call('/save_program',{program:'/fixture.exe'});await local.http.call('/close_program',{name:'/fixture.exe',save:true});await local.http.call('/open_program',{path:'/fixture.exe'});
 assert.equal((await local.http.call('/get_comment',{program:'/fixture.exe',address})).eol,'Private full-state proof');await local.http.call('/export_program',{program_name:'/fixture.exe',output_dir:snapshots,output_name:'edited.gzf'});await stop(local.child);
 const browser=await gui();await browser.http.call('/open_program',{path:'/fixture.exe'});assert.equal((await browser.http.call('/get_comment',{program:'/fixture.exe',address})).eol,'Private full-state proof');
 await browser.http.call('/set_comment',{program:'/fixture.exe',address,type:'eol',comment:'Private full-state proof after GUI'});await browser.http.call('/save_program',{program:'/fixture.exe'});await browser.http.call('/exit_ghidra');await stop(browser.child);
 const resumed=await backend('resumed');await resumed.http.call('/open_project',{path:join(root,'private/private.gpr')});await resumed.http.call('/open_program',{path:'/fixture.exe'});assert.equal((await resumed.http.call('/get_comment',{program:'/fixture.exe',address})).eol,'Private full-state proof after GUI');await resumed.http.call('/export_program',{program_name:'/fixture.exe',output_dir:snapshots,output_name:'gui-edited.gzf'});await stop(resumed.child);
 const result=await publish(join(snapshots,'gui-edited.gzf'),1,'insight-proof-'+randomUUID());assert.equal(result.state,'published');assert.equal(result.version,2);
 const verify=await backend('verify');await verify.http.call('/server/connect');await verify.http.call('/open_project',{path:serverOrigin+'/owned'});await verify.http.call('/open_program',{path:'/fixture.exe'});
 assert.equal((await verify.http.call('/get_comment',{program:'/fixture.exe',address})).eol,'Private full-state proof after GUI');const observed=await verify.http.call('/get_functions',{functions:address,include_call_context:false,program:'/fixture.exe'});assert.ok(JSON.stringify(observed).includes('LoadFixtureConfig'));assert.ok(JSON.stringify(observed).includes('uint'),'Unsigned prototype was not independently preserved');
 const types=await verify.http.call('/find_data_types',{program:'/fixture.exe',pattern:'ProofRecord',limit:10});assert.ok(JSON.stringify(types).includes('ProofRecord'));
 const identity=await verify.http.call('/get_program_options',{program:'/fixture.exe',group:'Program Information'});
 assert.equal(identity.options.find(item=>item.name==='Executable SHA256')?.value,createHash('sha256').update(await readFile(exe)).digest('hex'),'Published source identity changed');
 const metadata=await verify.http.call('/get_metadata',{program:'/fixture.exe'});const memory=await verify.http.call('/list_program_items',{program:'/fixture.exe',kind:'segments',limit:100});assert.ok(JSON.stringify(memory).includes('ProofMemory'));
 await assert.rejects(publish(join(snapshots,'edited.gzf'),1,'insight-proof-'+randomUUID()),error=>{const result=JSON.parse(error.result);return result.state==='conflict'&&result.applied===0;});const history=await verify.http.call('/server/version_history',{path:'/fixture.exe'});assert.equal(history.count,2);
 receipt={schema:1,scope:'owned native full-state publication proof',binarySha256:createHash('sha256').update(await readFile(exe)).digest('hex'),privateSaveReopen:true,comments:true,names:true,types:true,prototype:true,memory:true,publishedVersion:2,staleBaseRejected:true,historyCount:2,snapshotDatabaseIdPreserved:result.snapshotDatabaseIdPreserved,guiInteroperability:true,limitations:['tiny fixture only','conservative native change set; no native automatic database merge']};
 console.log(JSON.stringify(receipt));
} catch(error){console.error(error.message);if(error.diagnostic||error.stderr)console.error(String(error.diagnostic??error.stderr).slice(-6000));try{console.error(await readFile(join(root,'failed-operation.json'),'utf8'));}catch{}console.error('Owned fixture retained for diagnostics:',root);process.exitCode=1;}
finally{for(const child of [...children].reverse())await stop(child);}
if(receipt)await writeFile(join(root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));
