import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir,stat,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {spawn} from 'node:child_process';
import {launchProcess as startProcess,type TrackedChild,processStatus,listProcesses,terminateProcess} from '../src/tool-runtime/supervisor.js';
import {atomicWrite,assertUnused} from '../src/tool-runtime/store.js';
const children=new Map<string,TrackedChild[]>();
async function launchProcess(...args:Parameters<typeof startProcess>){const child=await startProcess(...args);children.set(args[0],[...(children.get(args[0])??[]),child]);return child;}
async function fixture(t:test.TestContext){const root=await mkdtemp(join(tmpdir(),'tool-supervisor-'));t.after(async()=>{for(const child of children.get(root)??[]){if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await child.toolClosed.catch(()=>{});}children.delete(root);await rm(root,{recursive:true,force:true});});return root;}
test('persistent tool is durably registered before execution and stop/kill verify ownership',async t=>{
 const root=await fixture(t),marker=join(root,'started');
 const child=await launchProcess(root,{tool:'fixture',role:'service',installation:'fixture',session:'s_a',target:'t_a'},process.execPath,['-e','require("node:fs").writeFileSync(process.argv[1],"started");setInterval(()=>{},1000)',marker],{detached:process.platform!=='win32',stdio:'ignore'});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 for(let i=0;i<100;i++){try{await stat(marker);break;}catch{await delay(20);}}
 assert.equal(await readFile(marker,'utf8'),'started');const record=await processStatus(root,child.toolProcessId);assert.equal(record.state,'running');assert.equal(record.pid,child.pid);assert.ok(record.identity);assert.equal((await listProcesses(root,{session:'s_a'})).length,1);
 await assert.rejects(terminateProcess(root,'../foreign',true),/Invalid/);
 const path=join(root,'runtime/processes',record.id+'.json');await atomicWrite(path,{...record,identity:'synthetic-reused-birth'});
 await assert.rejects(terminateProcess(root,record.id,true),/unverified/);await assert.rejects(assertUnused(root,'fixture'),/active or unverified/);assert.equal(child.exitCode,null);
 await atomicWrite(path,record);assert.equal((await terminateProcess(root,record.id,true)).state,'killed');await child.toolClosed;assert.equal((await processStatus(root,record.id)).state,'exited');
});
test('a parent crash before exec authorization cannot start the requested program',async t=>{
 if(process.platform==='win32'){t.skip('POSIX exec gate; Windows reports direct-child-only recovery.');return;}
 const root=await fixture(t),marker=join(root,'must-not-run');
 const module=new URL('../src/tool-runtime/supervisor.js',import.meta.url).href;
 const source=`import {launchProcess} from ${JSON.stringify(module)};await launchProcess(${JSON.stringify(root)},{tool:'fixture',role:'crash',installation:'fixture'},process.execPath,['-e',${JSON.stringify('require("node:fs").writeFileSync('+JSON.stringify(marker)+',"wrong")')}],{detached:true,stdio:'ignore'},{onSpawn(){process.kill(process.pid,'SIGKILL')}});`;
 const parent=spawn(process.execPath,['--input-type=module','-e',source],{stdio:'ignore'});await new Promise<void>(ok=>parent.once('close',()=>ok()));
 await delay(250);await assert.rejects(stat(marker));const records=await listProcesses(root);assert.equal(records.length,1);assert.equal(records[0]!.state,'failed');await assertUnused(root,'fixture');
});
test('replacement owner verifies a live tool identity without replaying execution',async t=>{
 const root=await fixture(t),marker=join(root,'identity.json'),token='synthetic-'+Math.random().toString(16).slice(2),module=new URL('../src/tool-runtime/supervisor.js',import.meta.url).href;
 const server='const h=require("node:http"),f=require("node:fs");const s=h.createServer((q,r)=>{if(q.headers.authorization!=="Bearer "+process.env.TOOL_TOKEN){r.writeHead(403);r.end();return;}r.setHeader("content-type","application/json");r.end(JSON.stringify({pid:process.pid}));});s.listen(0,"127.0.0.1",()=>f.writeFileSync(process.argv[1],JSON.stringify({pid:process.pid,port:s.address().port})));';
 const source=`import {launchProcess} from ${JSON.stringify(module)};const c=await launchProcess(${JSON.stringify(root)},{tool:'fixture',role:'recover',installation:'fixture'},process.execPath,['-e',${JSON.stringify(server)},${JSON.stringify(marker)}],{detached:process.platform!=='win32',stdio:'ignore',env:{PATH:process.env.PATH,TOOL_TOKEN:process.env.FIXTURE_TOKEN}});c.unref();console.log(JSON.stringify({id:c.toolProcessId,pid:c.pid}));setTimeout(()=>process.exit(0),10);`;
 const parent=spawn(process.execPath,['--input-type=module','-e',source],{env:{...process.env,FIXTURE_TOKEN:token},stdio:['ignore','pipe','pipe']});let output='';parent.stdout.on('data',b=>output+=b);let errors='';parent.stderr.on('data',b=>errors+=b);
 const code=await new Promise<number|null>(ok=>parent.once('close',ok));assert.equal(code,0,errors);const result=JSON.parse(output);
 let identity:{pid:number;port:number}|undefined;for(let i=0;i<200;i++){try{identity=JSON.parse(await readFile(marker,'utf8'));break;}catch{await delay(25);}}
 assert.ok(identity);assert.equal(identity.pid,result.pid);
 const verify=async(record:{pid?:number})=>{try{const r=await fetch('http://127.0.0.1:'+identity!.port,{headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(1000)});return r.ok&&(await r.json() as {pid:number}).pid===record.pid;}catch{return false;}};
 t.after(async()=>{try{await terminateProcess(root,result.id,true,verify);}catch{try{process.kill(result.pid,'SIGKILL');}catch{}}});
 const before=await readFile(marker,'utf8');assert.equal((await processStatus(root,result.id,verify)).state,'running');assert.equal((await processStatus(root,result.id,async()=>false)).state,'unverified');assert.equal(await readFile(marker,'utf8'),before);
 await assert.rejects(terminateProcess(root,result.id,true,async()=>false),/unverified/);
 assert.equal((await terminateProcess(root,result.id,true,verify)).state,'killed');
});
test('public process list/show/stop/kill use the Factory command tree and permission gates',async t=>{
 const {createCli}=await import('@eyeauras/cli-factory'),{createCliFixture}=await import('@eyeauras/cli-factory/testing');const {toolProcessCommands}=await import('../src/tool-runtime/commands.js');
 const f=await createCliFixture(t,{applicationId:'tool-cli-fixture'}),app=f.createApplication(runtime=>createCli({name:'tool-cli-fixture',description:'Process fixture',runtime,permissions:{categories:[{name:'Destructive',description:'Kill an owned process',enabledByDefault:false}]},commands:toolProcessCommands()}));
 assert.equal((await f.json(app,['tools','processes']) as any).items.length,0);
 const child=await launchProcess(f.appArguments.AppDataDirectory,{tool:'fixture',role:'cli',installation:'fixture'},process.execPath,['-e','setInterval(()=>{},1000)'],{detached:process.platform!=='win32',stdio:'ignore'});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 const replies=await f.rpc(app,[['tools','processes'],['tools','processes','show',child.toolProcessId]]);assert.equal((replies[0] as any).result.items[0].id,child.toolProcessId);assert.equal((replies[1] as any).result.state,'running');
 const denied=await f.run(app,['tools','processes','kill',child.toolProcessId,'--json']);assert.notEqual(denied.exitCode,0);assert.equal(child.exitCode,null);
 await f.run(app,['permissions','grant','Destructive']);assert.equal((await f.json(app,['tools','processes','kill',child.toolProcessId]) as any).state,'killed');
});
test('a copied process record cannot grant another profile control of the original child',async t=>{
 const root=await fixture(t),other=await fixture(t),child=await launchProcess(root,{tool:'fixture',role:'profile',installation:'fixture'},process.execPath,['-e','setInterval(()=>{},1000)'],{detached:process.platform!=='win32',stdio:'ignore'});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 const record=await processStatus(root,child.toolProcessId);await atomicWrite(join(other,'runtime/processes',record.id+'.json'),{...record,root:join(other,'runtime/runs',record.id)});
 await assert.rejects(terminateProcess(other,record.id,true),/unverified/);assert.equal(child.exitCode,null);await terminateProcess(root,record.id,true);
});

test('adapter launch binding completes durably before execution is authorized',async t=>{
 const root=await fixture(t),marker=join(root,'started'),binding=join(root,'adapter-binding.json');let release!:()=>void,entered!:()=>void;const held=new Promise<void>(ok=>release=ok),ready=new Promise<void>(ok=>entered=ok);
 const launch=launchProcess(root,{tool:'fixture',role:'adapter',installation:'fixture'},process.execPath,['-e','require("node:fs").writeFileSync(process.argv[1],"started");setInterval(()=>{},1000)',marker],{detached:process.platform!=='win32',stdio:'ignore'},{onSpawn:async child=>{entered();await held;await atomicWrite(binding,{pid:child.pid,id:child.toolProcessId});}});
 await ready;await delay(100);
 if(process.platform!=='win32')await assert.rejects(stat(marker));release();const child=await launch;
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 for(let i=0;i<100;i++){try{await stat(marker);break;}catch{await delay(20);}}
 assert.equal(JSON.parse(await readFile(binding,'utf8')).pid,child.pid);assert.equal(await readFile(marker,'utf8'),'started');await terminateProcess(root,child.toolProcessId,true);
});
