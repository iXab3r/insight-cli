import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runTool,type RunContext} from '../src/tool-runtime/run.js';
async function fixture(t:test.TestContext,controller=new AbortController()){
 const directory=await mkdtemp(join(tmpdir(),'tool-process-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 return {appArguments:{AppDataDirectory:directory},signal:controller.signal,environment:{PATH:process.env.PATH}} as RunContext;
}
test('one-shot preserves argv/cwd, records timing and redacts secrets across output chunks',async t=>{
 const c=await fixture(t),secret='synthetic-private-value';
 const result=await runTool(c,{tool:'fixture',role:'inspect',executable:process.execPath,arguments:['-e','process.stdout.write(process.argv[1]+"\\n"+process.cwd()+"\\n");process.stdout.write(process.env.TOOL_SECRET.slice(0,8));setTimeout(()=>process.stdout.write(process.env.TOOL_SECRET.slice(8)),20)','literal;$()'],environment:{TOOL_SECRET:secret},cwd:c.appArguments.AppDataDirectory});
 assert.match(result.stdout,/literal;\$\(\)/);assert.ok(result.stdout.includes(c.appArguments.AppDataDirectory));assert.ok(!result.stdout.includes(secret));assert.match(result.stdout,/redacted/);assert.equal(result.exitCode,0);assert.ok(result.elapsedMs>0);
 const record=JSON.parse(await readFile(join(c.appArguments.AppDataDirectory,'runtime/processes',result.process+'.json'),'utf8'));assert.equal(record.state,'exited');assert.ok(!JSON.stringify(record).includes(secret));assert.ok(!(await readFile(join(result.diagnostics,'stdout.log'),'utf8')).includes(secret));
});
test('timeout, cancellation, output overflow and launch failure retain terminal process outcomes',async t=>{
 for(const kind of ['timeout','cancelled','output_limit','launch'] as const){
  const controller=new AbortController(),c=await fixture(t,controller);
  const promise=runTool(c,{tool:'fixture',role:'fault',executable:kind==='launch'?join(c.appArguments.AppDataDirectory,'missing'):process.execPath,arguments:['-e',kind==='output_limit'?'process.stdout.write("x".repeat(100000));setInterval(()=>{},1000)':'setInterval(()=>{},1000)'],timeoutMs:kind==='timeout'?80:10000,maxOutputBytes:1024});
  if(kind==='cancelled')setTimeout(()=>controller.abort(),100);
  await assert.rejects(promise,error=>{assert.match((error as {code:string}).code,new RegExp(kind.replaceAll('_','.')));return true;});
  const names=await readdir(join(c.appArguments.AppDataDirectory,'runtime/processes'));const record=JSON.parse(await readFile(join(c.appArguments.AppDataDirectory,'runtime/processes',names[0]!),'utf8'));assert.equal(record.state,'failed');
 }
});
test('failed exits redact diagnostics and a one-shot cannot leave inherited output running',async t=>{
 const c=await fixture(t),secret='synthetic-error-secret';
 await assert.rejects(runTool(c,{tool:'fixture',role:'error',executable:process.execPath,arguments:['-e','process.stderr.write(process.env.TOOL_PASSWORD);process.exitCode=3'],environment:{TOOL_PASSWORD:secret}}),error=>{
  const value=error as {code:string;result:{stderr:string}};assert.equal(value.code,'tool.exit.code');assert.ok(!value.result.stderr.includes(secret));assert.match(value.result.stderr,/redacted/);return true;
 });
 if(process.platform==='win32'){t.diagnostic('Windows descendant process-group cleanup is outside this POSIX check.');return;}
 await assert.rejects(runTool(c,{tool:'fixture',role:'background',executable:process.execPath,arguments:['-e','const p=require("node:child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:["ignore",1,2]});p.unref();process.stdout.write(String(p.pid),()=>process.exit(0));'],timeoutMs:5000}),error=>{
  assert.match((error as {code:string}).code,/background.output/);return true;
 });
});
test('binary stdout export preserves exact bytes, refuses overwrite and leaves no success artifact on failed execution',async t=>{
 const c=await fixture(t),output=join(c.appArguments.AppDataDirectory,'recovered.bin');
 const result=await runTool(c,{tool:'fixture',role:'binary',executable:process.execPath,arguments:['-e','process.stdout.write(Buffer.from([0,255,128,13,10,0]))'],outputFile:output});
 assert.equal(result.exitCode,0);assert.deepEqual(await readFile(output),Buffer.from([0,255,128,13,10,0]));
 await assert.rejects(runTool(c,{tool:'fixture',role:'binary',executable:process.execPath,arguments:['-e','process.stdout.write("overwrite")'],outputFile:output}));
 assert.deepEqual(await readFile(output),Buffer.from([0,255,128,13,10,0]));
 const failed=join(c.appArguments.AppDataDirectory,'failed.bin');
 await assert.rejects(runTool(c,{tool:'fixture',role:'binary',executable:process.execPath,arguments:['-e','process.stdout.write("partial");process.exitCode=3'],outputFile:failed}));
 await assert.rejects(readFile(failed));
});
