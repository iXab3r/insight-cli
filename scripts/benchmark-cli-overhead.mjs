// Opt-in matched public transports. No host implementation or production instrumentation.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {spawn,execFile} from 'node:child_process';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {DatabaseSync} from 'node:sqlite';
import {createPublicFixture,digest} from './toolbox/public-fixture.mjs';
import {nativeProofGuard} from './native-proof-guard.mjs';

const {values:o}=parseArgs({options:{package:{type:'string'},root:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},rounds:{type:'string',default:'24'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);
for(const key of ['package','root','java','ghidra-home'])assert.ok(o[key],key);
const rounds=Number(o.rounds);assert.ok(Number.isSafeInteger(rounds)&&rounds>=4&&rounds<=100);
const root=resolve(o.root);await mkdir(root);process.env.INSIGHT_NATIVE_DISPOSABLE='1';
const f=await createPublicFixture(resolve(o.package),root),exec=promisify(execFile),rows=[],warmups=[],cleanup=[];
const traceFile=join(f.appdata,'insight-cli',f.profile,'workspace/diagnostics/timings.jsonl');
let scope,rpc,passed=false;
const now=()=>performance.now();
const checkpoint=()=>{const db=new DatabaseSync(join(f.appdata,'insight-cli',f.profile,'workspace/workspace.sqlite'),{readOnly:true});try{
 const context=JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(scope.session,scope.target).data);
 return {generation:context.generation,snapshot:context.workingSnapshot,requests:db.prepare('SELECT id,state FROM requests WHERE context=? ORDER BY rowid').all(context.id)};
}finally{db.close();}};
const traceRows=async()=>{try{return (await readFile(traceFile,'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}};
const quantiles=values=>{const a=values.toSorted((x,y)=>x-y),at=p=>a[Math.ceil(p*a.length)-1];return {n:a.length,min:a[0],p50:at(.5),p95:at(.95),max:a.at(-1),mean:a.reduce((x,y)=>x+y,0)/a.length};};
const union=spans=>{let total=0,end=-Infinity;for(const s of spans.toSorted((a,b)=>a.startedMs-b.startedMs)){const stop=s.startedMs+s.durationMs;total+=Math.max(0,stop-Math.max(end,s.startedMs));end=Math.max(end,stop);}return total;};

function persistent(){
 const started=now(),child=spawn(process.execPath,[f.cli,'--json-rpc'],{cwd:f.project,env:f.environment,stdio:['pipe','pipe','pipe']});
 let id=0,stderr='';const pending=new Map();child.stderr.on('data',v=>stderr+=v);
 const lines=createInterface({input:child.stdout});lines.on('line',line=>{try{const response=JSON.parse(line),p=pending.get(response.id);if(!p)return;pending.delete(response.id);clearTimeout(p.timer);response.error?p.reject(Error(JSON.stringify(response.error))):p.resolve({value:response.result,received:now()});}catch(error){for(const p of pending.values())p.reject(error);}});
 child.on('exit',(code,signal)=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('RPC exited '+code+'/'+signal+': '+stderr));}pending.clear();});
 return {started,child,async call(argv){const sent=now(),request=++id;const response=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(request);reject(Error('RPC timeout'));},120000);pending.set(request,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:request,method:'cli.execute',params:{argv}})+'\n');});return {...response,totalMs:response.received-sent};},async stop(){child.stdin.end();await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('RPC did not exit')),20000);child.once('close',code=>{clearTimeout(timer);lines.close();code===0?resolve():reject(Error('RPC close '+code));});});}};
}
async function oneShot(argv){
 const started=now(),child=spawn(process.execPath,[f.cli,...argv,'--json'],{cwd:f.project,env:f.environment,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',firstOutputMs;
 const timer=setTimeout(()=>child.kill('SIGTERM'),120000);
 child.stdout.on('data',v=>{firstOutputMs??=now()-started;stdout+=v;});child.stderr.on('data',v=>stderr+=v);
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});const totalMs=now()-started;clearTimeout(timer);
 assert.equal(code,0,stderr);return {value:JSON.parse(stdout),totalMs,firstOutputMs,afterOutputMs:totalMs-firstOutputMs};
}
async function sample(mode,operation,round,phase='measured'){
 const before=await traceRows(),result=await (mode==='one-shot'?oneShot(operation.argv):rpc.call(operation.argv));
 const traces=(await traceRows()).slice(before.length),commands=traces.filter(x=>x.phase==='facade.command');
 if(operation.native)assert.equal(commands.length,1,'Exactly one completed facade trace');else assert.equal(commands.length,0);
 const handlerMs=commands[0]?.durationMs,backendMs=union(traces.filter(x=>x.phase==='backend.operation')),nativeHttpMs=union(traces.filter(x=>x.phase==='native.http'));
 const row={phase,round,mode,operation:operation.name,totalMs:result.totalMs,firstOutputMs:result.firstOutputMs,afterOutputMs:result.afterOutputMs,handlerMs,backendMs,nativeHttpMs,outsideHandlerMs:handlerMs===undefined?undefined:result.totalMs-handlerMs,outputSha256:digest(Buffer.from(JSON.stringify(result.value))),trace:commands[0]?.trace};
 const expected=warmups.find(x=>x.operation===operation.name);if(expected)assert.equal(row.outputSha256,expected.outputSha256,'Full JSON result must match across routes and repetitions');
 (phase==='measured'?rows:warmups).push(row);return result.value;
}
try{
 await f.call(['profile','set',f.profile,'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home'])]);
 const source=join(root,'fixture.c'),input=join(root,'fixture.exe'),obj=join(root,'fixture.obj');await writeFile(source,'int main(void){return 7;}\n');
 await exec('clang',['--target=x86_64-pc-windows-msvc','-O0','-c',source,'-o',obj]);await exec('lld-link',['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/export:main','/out:'+input,obj]);
 const inputHash=digest(await readFile(input));
 scope=await f.call(['ghidra','open',input,'--session','new','--no-analysis']);
 const selected=['--session',scope.session,'--target',scope.target];
 const workload=[{name:'memory-32',native:true,argv:['ghidra','memory','read',...selected,'--address','0x140001000','--length','32']},{name:'inspect-entry',native:true,argv:['ghidra','functions','inspect',...selected,'--function','main','--fields','entry_point','--include-call-context','false']},{name:'context-status',native:false,argv:['sessions','status',scope.session,'--target',scope.target]}];
 const ownerBefore=await f.call(['ipc-server','status']),processesBefore=await f.call(['tools','processes','--tool','ghidra']),before=checkpoint();
 rpc=persistent();const handshake=await rpc.call(['profile','show']);const persistentStartupMs=handshake.received-rpc.started;
 for(const operation of workload)for(const mode of ['one-shot','persistent'])await sample(mode,operation,-1,'warmup');
 // Counterbalance both route and operation order. Requests never overlap; each round is a pair.
 for(let round=0;round<rounds;round++){
  for(const operation of round%2?[...workload].reverse():workload)for(const mode of round%2?['persistent','one-shot']:['one-shot','persistent'])await sample(mode,operation,round);
  await writeFile(join(root,'progress.json'),JSON.stringify({round:round+1,rounds,rows},null,2)+'\n',{mode:0o600});
  console.log('Completed paired round',round+1,'/',rounds);
 }
 const after=checkpoint(),ownerAfter=await f.call(['ipc-server','status']),processesAfter=await f.call(['tools','processes','--tool','ghidra']);assert.deepEqual(after,before);assert.deepEqual(ownerAfter,ownerBefore);assert.deepEqual(processesAfter,processesBefore);assert.equal(digest(await readFile(input)),inputHash);
 const summary={};for(const operation of workload){summary[operation.name]={};for(const mode of ['one-shot','persistent']){const selected=rows.filter(x=>x.operation===operation.name&&x.mode===mode);summary[operation.name][mode]=Object.fromEntries(['totalMs','handlerMs','backendMs','nativeHttpMs','outsideHandlerMs','afterOutputMs'].filter(k=>selected.every(x=>x[k]!==undefined)).map(k=>[k,quantiles(selected.map(x=>x[k]))]));}}
 await writeFile(join(root,'timings.jsonl'),(await readFile(traceFile)),{mode:0o600});
 await writeFile(join(root,'result.json'),JSON.stringify({schema:1,state:'passed',node:process.version,platform:process.platform,architecture:process.arch,rounds,packageRoot:f.packageRoot,packageBuild:JSON.parse(await readFile(join(f.packageRoot,'.cli-package-build.json'),'utf8')),inputHash,persistentStartupMs,scope,workload,ownerBefore,ownerAfter,processesBefore,processesAfter,before,after,warmups,rows,summary,method:{clock:'parent performance.now; spawn-to-close for one-shot, write-to-complete-line for RPC',order:'alternating AB/BA and reversed operation order',warmup:'one of each operation/route excluded',owner:'same pre-existing warm Factory owner; public fixture helper keeps a quiescent second RPC connection',trace:'existing awaited facade spans; backend/native/context spans overlap; no additive phase claims',validation:'exact full result hashes, context generation/snapshot/request journal, input hash, owner and native process records unchanged'}},null,2)+'\n',{mode:0o600});
 passed=true;
}finally{
 if(rpc)try{await rpc.stop();}catch(e){cleanup.push(e.message);}
 if(scope)try{await f.call(['ghidra','close','--session',scope.session,'--target',scope.target]);await f.call(['ghidra','server','stop']);}catch(e){cleanup.push(e.message);}
 try{await f.cleanup();}catch(e){cleanup.push(e.message);}
 await writeFile(join(root,'cleanup.json'),JSON.stringify({passed,cleanup},null,2)+'\n',{mode:0o600});
 assert.equal(cleanup.length,0,'Fixture cleanup failed');
}
