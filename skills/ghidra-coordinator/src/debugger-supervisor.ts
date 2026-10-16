/** Internal LLDB child owner. It has no public command or independent product IPC host. */
import {launchProcess,registerExistingProcess} from './tool-runtime/supervisor.js';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdir,open,rename,realpath} from 'node:fs/promises';
import {join,resolve,delimiter} from 'node:path';
import {randomUUID} from 'node:crypto';
import {HttpBridge} from './transport.js';

async function main(){
  const root=await realpath(process.argv[2]!),binding=JSON.parse(await readFile(join(root,'process.json'),'utf8'));
  if(root!==resolve(root)||binding.root!==root||binding.mode!=='gui'||!Number.isSafeInteger(binding.pid))throw Error('Invalid GUI owner');
  const token=process.env.GHIDRA_MCP_AUTH_TOKEN;if(!token)throw Error('Missing GUI authority');
  const url=new URL(binding.endpoint);if(url.hostname!=='127.0.0.1'||url.protocol!=='http:'||!url.port)throw Error('Invalid GUI endpoint');
  const info=await new HttpBridge(binding.endpoint,fetch,undefined,token,5000).instance();
  if(info.pid!==binding.pid||info.tcp_port!==Number(url.port)||!String(info.project_path??'').startsWith(root+'/'))throw Error('GUI identity changed');
  const launch=JSON.parse(await readFile(join(root,'debugger-run/current.json'),'utf8'));
  if(launch.context!==binding.context||launch.target!==binding.target||!String(launch.executable).startsWith(root+'/debugger-run/'+launch.request+'/'))throw Error('Launch identity changed');
  const directory=join(root,'debugger-supervisors');await mkdir(directory,{recursive:true,mode:0o700});if(await realpath(directory)!==directory)throw Error('Supervisor directory changed');
  const id=randomUUID(),path=join(directory,id+'.json'),resultPath=join(directory,id+'.result.json');
  const receipt={schema:1,id,root,guiPid:binding.pid,ownerToken:binding.tokenSecret,context:binding.context,target:binding.target,supervisorPid:process.pid,childPid:0,state:'starting',inferiorTerminated:false};
  async function saved(){const temporary=path+'.new',file=await open(temporary,'w',0o600);try{await file.writeFile(JSON.stringify(receipt));await file.sync();}finally{await file.close();}await rename(temporary,path);const parent=await open(directory,'r');try{await parent.sync();}finally{await parent.close();}}
  const appData=process.env.INSIGHT_TOOL_APPDATA;if(!appData||!root.startsWith(resolve(appData)+'/workspace/ghidra-native/'))throw Error('Invalid tool profile');
  const authority=createServer((req,res)=>{if(req.url!=='/identity'||req.headers.authorization!=='Bearer '+token){res.writeHead(403).end();return;}res.setHeader('Content-Type','application/json');res.end(JSON.stringify({id,pid:process.pid,childPid:receipt.childPid,state:receipt.state}));});
  await new Promise<void>(ok=>authority.listen(0,'127.0.0.1',ok));authority.unref();const address=authority.address();if(!address||typeof address==='string')throw Error('No debugger identity port');Object.assign(receipt,{identityPort:address.port});
  const processSpec={tool:'ghidra',installation:binding.runtimeFingerprint,target:binding.target,metadata:{debuggerReceipt:path,contextRoot:root}};
  const helperProcess=await registerExistingProcess(appData,{...processSpec,role:'debugger-supervisor'},process.execPath,process.pid,async()=>true);
  await saved();const environment={...process.env};delete environment.GHIDRA_MCP_AUTH_TOKEN;delete environment.GHIDRA_SERVER_PASSWORD;
  // Ghidra's launcher prepends its source tree to PYTHONPATH. Restore the owned wheel
  // copy first, including the pinned SBProcess compatibility adapter, before LLDB imports it.
  const python=await realpath(environment.INSIGHT_DEBUGGER_PYTHON??'');
  if(!python.startsWith(root+'/debug-python-')||python!==environment.INSIGHT_DEBUGGER_PYTHON)throw Error('Owned debugger Python identity changed');
  environment.PYTHONPATH=python+delimiter+(environment.PYTHONPATH??'');delete environment.INSIGHT_DEBUGGER_PYTHON;
  let closing=false,finished=false;
  process.once('SIGHUP',close);process.once('SIGTERM',close);
  // A separate session keeps the GUI terminal's SIGHUP from bypassing our orderly kill.
  const child=await launchProcess(appData,{...processSpec,role:'debugger'},'/usr/bin/lldb',['--no-lldbinit','-o','settings set auto-confirm true',...process.argv.slice(3)],{env:environment,detached:true,stdio:['pipe','pipe','pipe']});
  const exited=new Promise<void>((ok,bad)=>{child.once('error',bad);child.once('exit',()=>{finished=true;ok();});});
  void exited.catch(()=>{});receipt.childPid=child.pid??0;receipt.state='running';
  let diagnostics='';const capture=(chunk:Buffer)=>{diagnostics=(diagnostics+chunk.toString()).slice(-65536);};child.stdout!.on('data',capture);child.stderr!.on('data',capture);
  process.stdout.on('error',()=>{});process.stderr.on('error',()=>{});child.stdin!.on('error',()=>{});
  child.stdout!.pipe(process.stdout,{end:false});child.stderr!.pipe(process.stderr,{end:false});
  process.stdin.on('data',data=>{if(!closing)child.stdin!.write(data);});
  const code=[
    'import lldb,json,pathlib,os',
    'p=lldb.debugger.GetSelectedTarget().GetProcess()',
    'pid=p.GetProcessID() if p.IsValid() else 0',
    'state=p.GetState() if p.IsValid() else lldb.eStateInvalid',
    'done=state in (lldb.eStateInvalid,lldb.eStateUnloaded,lldb.eStateExited)',
    'error=None',
    'if not done:',
    ' e=p.Kill()',
    ' done=e.Success() and p.GetState()==lldb.eStateExited',
    ' error=None if done else str(e)',
    'path=pathlib.Path('+JSON.stringify(resultPath)+')',
    'path.write_text(json.dumps({"id":'+JSON.stringify(id)+',"pid":pid,"inferiorTerminated":done,"error":error}))',
    'os.chmod(str(path),0o600)',
  ].join('\n');
  function close(){if(closing||finished)return;closing=true;process.stdin.pause();child.stdout!.unpipe(process.stdout);child.stderr!.unpipe(process.stderr);child.stdout!.resume();child.stderr!.resume();
    const commands='script exec('+JSON.stringify(code)+')\nquit\n';child.stdin!.write(commands);
    setTimeout(()=>{if(!finished){child.kill('SIGINT');child.stdin!.write(commands);}},3000).unref();}
  process.once('SIGINT',()=>{if(!closing)child.kill('SIGINT');});process.stdin.once('end',close);process.stdin.once('error',close);
  const monitor=setInterval(()=>{try{process.kill(binding.pid,0);}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH')close();}},250);
  try{await saved();await exited;let result;try{result=JSON.parse(await readFile(resultPath,'utf8'));}catch{}
    receipt.inferiorTerminated=result?.id===id&&result.inferiorTerminated===true;receipt.state=receipt.inferiorTerminated?'closed':'failed';Object.assign(receipt,{exitCode:child.exitCode,signalCode:child.signalCode});
    if(!receipt.inferiorTerminated)await writeFile(join(directory,id+'.diagnostic.log'),diagnostics,{mode:0o600});await saved();
  }finally{clearInterval(monitor);process.stdin.pause();authority.close();}
  // Keep a failed child outcome observable; never claim that killing LLDB proves inferior exit.
  process.exitCode=receipt.inferiorTerminated?0:1;
}
await main().catch(()=>{process.stderr.write('Owned debugger supervision failed; its context is retained.\n');process.exitCode=1;});
