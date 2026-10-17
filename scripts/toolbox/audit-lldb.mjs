// Backend feasibility only. Public facade and crash-safe lifetime gates remain separate.
import assert from 'node:assert/strict';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {readFile,writeFile,mkdir} from 'node:fs/promises';import {join,resolve} from 'node:path';import {digest} from './public-fixture.mjs';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const [root,fixture,output]=process.argv.slice(2);assert.ok(output,'Arguments: reviewed-lldb-root owned-fixture disposable-output');await mkdir(output,{recursive:true,mode:0o700});
const execute=promisify(execFile),executable=join(resolve(root),'bin/lldb'),server=join(resolve(root),'bin/debugserver');
const env={PATH:process.env.PATH,HOME:resolve(output),TMPDIR:resolve(output),LLDB_DEBUGSERVER_PATH:server};
const version=await execute(executable,['--version'],{env,timeout:10000,maxBuffer:65536});assert.match(version.stdout,/lldb version 23\.1\.3/);
const commands=['breakpoint set -n quote_total','process launch','frame variable count','register read pc sp x0','memory read --size 4 --count 4 --format x $sp','bt','process kill','quit'];
const result=await execute(executable,['--no-lldbinit','--batch',...commands.flatMap(c=>['-o',c]),'--',resolve(fixture)],{env,timeout:20000,maxBuffer:1024**2});
await writeFile(join(output,'stdout.txt'),result.stdout,{mode:0o600});await writeFile(join(output,'stderr.txt'),result.stderr,{mode:0o600});
for(const pattern of [/stop reason = breakpoint/,/\(int\) count = 1/,/x0 = 0x0*1\b/,/memory read/,/frame #1:.*main/,/exited with status = 9 .*killed/])assert.match(result.stdout,pattern);
const pid=Number(result.stdout.match(/Process (\d+) launched:/)?.[1]);assert.ok(pid>0);assert.throws(()=>process.kill(pid,0),e=>e.code==='ESRCH','Owned inferior must be absent after process kill and debugger exit');
await writeFile(join(output,'result.json'),JSON.stringify({schema:1,scope:'Pinned LLDB backend feasibility; public adapter and recovery gates remain pending',version:'23.1.3',fixtureSha256:digest(await readFile(fixture)),components:Object.fromEntries(await Promise.all(['bin/lldb','bin/debugserver','lib/liblldb.23.1.3.dylib'].map(async name=>[name,digest(await readFile(join(root,name)))]))),checks:{privateDebugserverSelected:true,initFilesDisabled:true,directArgvLaunch:true,realBreakpoint:true,parameterAndRegisters:true,memoryAndBacktrace:true,normalInferiorTerminationIndependentlyVerified:true},adapterAccepted:false},null,2)+'\n',{mode:0o600});console.log('LLDB native backend feasibility PASS');
