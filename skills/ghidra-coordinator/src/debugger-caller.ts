/** Private, profile-owned LLDB completion receipts. No CPU operation is retried. */
import {lstat,open,readFile,realpath,rename} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fail,object} from './model.js';

export interface CallerGoal {schema:1;id:string;pid:number;thread:string;pc:string;sp:string;stop:number;executable:string;breakpoint:number}
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const hex=/^0x[a-fA-F0-9]{1,16}$/;
async function json(path:string):Promise<Record<string,unknown>|undefined>{
  try {const stat=await lstat(path);if(!stat.isFile()||stat.size>16384||await realpath(path)!==resolve(path))fail('binding','Native caller receipt is not an owned regular file.');return object(JSON.parse(await readFile(path,'utf8')));}
  catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
}
async function atomic(path:string,value:unknown){const temporary=path+'.new-'+randomUUID(),file=await open(temporary,'wx',0o600);try{await file.writeFile(JSON.stringify(value));await file.sync();}finally{await file.close();}await rename(temporary,path);}
export async function readCallerGoal(python:string):Promise<CallerGoal|undefined>{
  const value=await json(join(python,'caller-goal.json'));if(!value)return;
  if(value.schema!==1||typeof value.id!=='string'||!uuid.test(value.id)||!Number.isSafeInteger(value.pid)||Number(value.pid)<=0||typeof value.thread!=='string'||!/^\d{1,20}$/.test(value.thread)||BigInt(value.thread)<=0n||typeof value.pc!=='string'||!hex.test(value.pc)||typeof value.sp!=='string'||!hex.test(value.sp)||!Number.isSafeInteger(value.stop)||Number(value.stop)<0||typeof value.executable!=='string'||!Number.isSafeInteger(value.breakpoint)||Number(value.breakpoint)<=0)fail('binding','Native caller goal is malformed.');
  return value as unknown as CallerGoal;
}
export function callerVerified(goal:CallerGoal,value:Record<string,unknown>){
  return value.schema===1&&value.goal===goal.id&&value.state==='verified'&&value.pid===goal.pid&&value.thread===goal.thread&&typeof value.pc==='string'&&hex.test(value.pc)&&BigInt(value.pc)===BigInt(goal.pc)&&typeof value.sp==='string'&&hex.test(value.sp)&&BigInt(value.sp)===BigInt(goal.sp)&&Number.isSafeInteger(value.stop)&&Number(value.stop)>goal.stop;
}
export async function awaitCaller(python:string,goal:CallerGoal,signal?:AbortSignal,budgetMs=12000){
  await atomic(join(python,'caller-armed.json'),{schema:1,id:goal.id});
  const deadline=Date.now()+budgetMs;
  while(Date.now()<deadline){
    signal?.throwIfAborted();const value=await json(join(python,'caller-observation.json'));
    if(value?.goal===goal.id){if(callerVerified(goal,value))return;
      if(value.state==='verified'||value.state==='failed')fail('partial','Native caller observation did not verify the requested return.',{goal:goal.id,observation:value});}
    await delay(Math.min(50,Math.max(1,deadline-Date.now())),undefined,{signal});
  }
  fail('partial','Native caller was not verified within the action budget; execution was not repeated.',{goal:goal.id});
}
/** Runs from the owned LLDB CLI after the MCP action has returned and released its locks. */
export function callerObservationCommand(python:string,goal:CallerGoal,sample:string){
  const code=[
    'import lldb,json,os,pathlib',
    'goal=json.loads('+JSON.stringify(JSON.stringify(goal))+')',
    'output=pathlib.Path('+JSON.stringify(join(python,'caller-observation.json'))+')',
    'value={"schema":1,"goal":goal["id"],"sample":'+JSON.stringify(sample)+',"state":"pending"}',
    'def inspect_caller():',
    ' p=lldb.debugger.GetSelectedTarget().GetProcess()',
    ' if p.GetProcessID()!=goal["pid"]: raise RuntimeError("Native process identity changed")',
    ' state=p.GetState()',
    ' if state in (lldb.eStateExited,lldb.eStateDetached,lldb.eStateInvalid): raise RuntimeError("Native target ended before caller verification")',
    ' if state!=lldb.eStateStopped: return',
    ' stop=p.GetStopID(); t=p.GetThreadByID(int(goal["thread"])); f=t.GetFrameAtIndex(0)',
    ' if not f.IsValid(): return',
    ' pc=f.FindRegister("pc"); sp=f.FindRegister("sp")',
    ' if not pc.IsValid() or not sp.IsValid() or pc.GetError().Fail() or sp.GetError().Fail(): return',
    ' value.update(pid=p.GetProcessID(),thread=str(t.GetThreadID()),pc=hex(pc.GetValueAsUnsigned()),sp=hex(sp.GetValueAsUnsigned()),frame_pc=hex(f.GetPC()),stop=stop)',
    ' if stop<=goal["stop"] or pc.GetValueAsUnsigned()!=int(goal["pc"],16) or sp.GetValueAsUnsigned()!=int(goal["sp"],16) or p.GetState()!=lldb.eStateStopped or p.GetStopID()!=stop: return',
    ' from ghidralldb import commands',
    ' client=commands.STATE.require_client(); batch=client.cur_batch',
    ' value.update(trace_batch_count=batch.count if batch is not None else 0,trace_batch_mutex=client._block.locked())',
    ' if batch is not None or client._block.locked(): return',
    ' result=lldb.SBCommandReturnObject()',
    ' lldb.debugger.GetCommandInterpreter().HandleCommand("ghidra trace sync-synth-stopped",result)',
    ' if not result.Succeeded(): raise RuntimeError("Native stopped trace could not be synchronized")',
    ' batch=client.cur_batch',
    ' value.update(trace_batch_count=batch.count if batch is not None else 0,trace_batch_mutex=client._block.locked())',
    ' if batch is not None or client._block.locked(): return',
    ' f=p.GetThreadByID(int(goal["thread"])).GetFrameAtIndex(0)',
    ' pc=f.FindRegister("pc"); sp=f.FindRegister("sp")',
    ' if p.GetState()==lldb.eStateStopped and p.GetStopID()==stop and f.IsValid() and pc.IsValid() and sp.IsValid() and pc.GetError().Success() and sp.GetError().Success() and pc.GetValueAsUnsigned()==int(goal["pc"],16) and sp.GetValueAsUnsigned()==int(goal["sp"],16): value["state"]="verified"',
    'try: inspect_caller()',
    'except Exception as error: value.update(state="failed",error=str(error)[:1024])',
    'temporary=str(output)+".new-"+value["sample"]',
    'fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)',
    'try: os.write(fd,json.dumps(value).encode("utf-8")); os.fsync(fd)',
    'finally: os.close(fd)',
    'os.replace(temporary,output)',
  ].join('\n');return 'script exec('+JSON.stringify(code)+')\n';
}
export function callerMonitor(python:string,send:(command:string)=>void){
  let goalId='',sample='',inflight=false,terminal=false,deadline=0;
  return async()=>{
    const armed=await json(join(python,'caller-armed.json'));if(!armed||typeof armed.id!=='string'||!uuid.test(armed.id))return;
    const goal=await readCallerGoal(python);if(!goal||goal.id!==armed.id)return;
    if(goalId!==goal.id){goalId=goal.id;inflight=false;terminal=false;deadline=Date.now()+15000;}
    if(terminal||Date.now()>=deadline)return;
    if(inflight){const value=await json(join(python,'caller-observation.json'));if(value?.goal!==goal.id||value.sample!==sample)return;inflight=false;if(value.state==='verified'||value.state==='failed'){terminal=true;return;}}
    sample=randomUUID();inflight=true;send(callerObservationCommand(python,goal,sample));
  };
}
