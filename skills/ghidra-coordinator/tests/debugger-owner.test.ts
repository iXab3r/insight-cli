import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {mkdtemp,realpath,mkdir,writeFile,readdir,readFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {terminateProcess,listProcesses} from '../src/tool-runtime/supervisor.js';
const enabled=process.platform==='darwin'&&process.env.INSIGHT_NATIVE_LLDB==='1';
for(const earlyStop of [false,true])test(earlyStop?'native LLDB owner defers an early stop until its tracked child exists':'native LLDB owner accepts a profile alias and observes a child that exits during startup', {skip:enabled?false:'Opt-in real macOS LLDB lifecycle check: INSIGHT_NATIVE_LLDB=1',timeout:20000},async t=>{
 const profile=await realpath(await mkdtemp(join(tmpdir(),'insight-lldb-owner-'))),root=join(profile,'workspace/ghidra-native/context/fixture'),python=join(root,'debug-python-'+randomUUID()),token=randomUUID(),request=randomUUID();await mkdir(python,{recursive:true});await mkdir(join(root,'debugger-run'),{recursive:true});
 const aliasRoot=await mkdtemp(join(tmpdir(),'insight-lldb-alias-')),profileAlias=join(aliasRoot,'profile');await symlink(profile,profileAlias,'dir');const processProfile=earlyStop?profile:profileAlias;
 const gui=createServer((req,res)=>{if(req.headers.authorization!=='Bearer '+token){res.writeHead(403).end();return;}res.setHeader('Content-Type','application/json');res.end(JSON.stringify({pid:process.pid,tcp_port:(gui.address() as {port:number}).port,project_path:root+'/view'}));});await new Promise<void>(ok=>gui.listen(0,'127.0.0.1',ok));
 const binding={root,mode:'gui',pid:process.pid,endpoint:'http://127.0.0.1:'+(gui.address() as {port:number}).port,context:'c_fixture',target:'t_fixture',tokenSecret:'fixture',runtimeFingerprint:'f'.repeat(64)};
 await writeFile(join(root,'process.json'),JSON.stringify(binding));await writeFile(join(root,'debugger-run/current.json'),JSON.stringify({context:binding.context,target:binding.target,request,executable:join(root,'debugger-run',request,'never-executed')}));
 const child=spawn(process.execPath,[fileURLToPath(new URL('../src/debugger-supervisor.js',import.meta.url)),root,...(earlyStop?['-o','script import time; time.sleep(0.2)']:['--insight-invalid-option'])],{env:{PATH:'/usr/bin:/bin',GHIDRA_MCP_AUTH_TOKEN:token,INSIGHT_TOOL_APPDATA:processProfile,INSIGHT_DEBUGGER_PYTHON:python},stdio:['pipe','pipe','pipe']});
 let stderr='';child.stdout.on('data',()=>{});child.stderr.on('data',b=>stderr+=b);const ended=new Promise<void>(ok=>child.once('close',()=>ok()));
 t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');for(const name of (await readdir(join(profile,'runtime/processes')).catch(()=>[])).filter(n=>/^[a-f0-9-]{36}\.json$/.test(n))){const r=JSON.parse(await readFile(join(profile,'runtime/processes',name),'utf8'));if(r.role==='debugger')try{await terminateProcess(processProfile,r.id,true,async()=>true);}catch{}}await new Promise<void>(ok=>gui.close(()=>ok()));await rm(aliasRoot,{recursive:true,force:true});await rm(profile,{recursive:true,force:true});});
 if(earlyStop){let observed=false;for(let i=0;i<1000;i++){
  const rows=await readdir(join(profile,'runtime/processes')).catch(()=>[]);for(const name of rows.filter(n=>/^[a-f0-9-]{36}\.json$/.test(n))){const r=JSON.parse(await readFile(join(profile,'runtime/processes',name),'utf8'));if(r.role==='debugger'&&r.state==='starting')observed=true;}
  if(observed){child.kill('SIGTERM');break;}if(child.exitCode!==null)break;await delay(2);
 }assert.equal(observed,true,'Did not observe the owned launch intent before execution');}
 await Promise.race([ended,delay(12000,undefined,{ref:false}).then(()=>{throw Error('LLDB owner did not finish: '+stderr);})]);
 assert.doesNotMatch(stderr,/before initialization|ReferenceError/);const names=(await readdir(join(root,'debugger-supervisors'))).filter(name=>/^[a-f0-9-]{36}\.json$/.test(name));assert.equal(names.length,1);
 const receipt=JSON.parse(await readFile(join(root,'debugger-supervisors',names[0]!),'utf8'));assert.equal(receipt.state,earlyStop?'closed':'failed');assert.equal(receipt.inferiorTerminated,earlyStop);assert.ok(receipt.childPid>0);
 const inventory=await listProcesses(processProfile,{tool:'ghidra'},async()=>false);assert.ok(inventory.length>=2);assert.ok(inventory.every(row=>['exited','failed'].includes(row.state)),'Final public process state must use the original Factory profile binding, including aliases');
 if(!earlyStop){
  const rejected=spawn(process.execPath,[fileURLToPath(new URL('../src/debugger-supervisor.js',import.meta.url)),root,'--insight-invalid-option'],{env:{PATH:'/usr/bin:/bin',GHIDRA_MCP_AUTH_TOKEN:token,INSIGHT_TOOL_APPDATA:aliasRoot,INSIGHT_DEBUGGER_PYTHON:python},stdio:['ignore','ignore','pipe']});rejected.stderr.resume();
  const closed=new Promise<void>(ok=>rejected.once('close',()=>ok()));await Promise.race([closed,delay(12000,undefined,{ref:false}).then(()=>{rejected.kill('SIGKILL');throw Error('Unowned profile rejection did not finish');})]);assert.equal(rejected.exitCode,1);
  assert.deepEqual((await readdir(join(root,'debugger-supervisors'))).filter(name=>/^[a-f0-9-]{36}\.json$/.test(name)),names,'An authenticated GUI context must still be rejected outside the declared profile');
 }
});
