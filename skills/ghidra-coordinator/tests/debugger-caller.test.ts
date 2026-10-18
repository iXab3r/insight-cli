import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,symlink,rm,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {awaitCaller,callerMonitor,callerVerified,readCallerGoal,type CallerGoal} from '../src/debugger-caller.js';
const goal=():CallerGoal=>({schema:1,id:randomUUID(),pid:123,thread:'42',pc:'0x100000508',sp:'0x16fdfe250',stop:13,executable:'/owned/image',breakpoint:2});
const observed=(g:CallerGoal)=>({schema:1,goal:g.id,state:'verified',pid:g.pid,thread:g.thread,pc:g.pc.toUpperCase().replace('0X','0x'),sp:g.sp,stop:g.stop+2});
test('caller completion requires matching intent, physical identity, coordinates and a new stop',()=>{
 const g=goal(),valid=observed(g);assert.equal(callerVerified(g,valid),true);
 for(const wrong of [{goal:randomUUID()},{pid:124},{thread:'43'},{pc:'0x100000464'},{sp:'0x16fdfe230'},{stop:13},{state:'pending'},{pc:'unknown'}])assert.equal(callerVerified(g,{...valid,...wrong}),false);
});
test('caller observer does not enter LLDB before the MCP action has armed its exact goal',async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'insight-caller-'))),g=goal(),sent:string[]=[];
 try{
  await writeFile(join(root,'caller-goal.json'),JSON.stringify(g));const poll=callerMonitor(root,v=>sent.push(v));await poll();assert.equal(sent.length,0);
  await writeFile(join(root,'caller-armed.json'),JSON.stringify({id:randomUUID()}));await poll();assert.equal(sent.length,0);
  await writeFile(join(root,'caller-armed.json'),JSON.stringify({id:g.id}));await poll();assert.equal(sent.length,1);await poll();assert.equal(sent.length,1,'No overlapping interpreter commands');
  assert.match(sent[0]!,/sync-synth-stopped/);assert.doesNotMatch(sent[0]!,/\.Continue\(|process launch|StepInstruction|WriteMemory/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('stale caller observation cannot acknowledge another CPU intent or cause another dispatch',async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'insight-caller-'))),g=goal();
 try{await writeFile(join(root,'caller-observation.json'),JSON.stringify(observed({...g,id:randomUUID()})));await assert.rejects(awaitCaller(root,g,undefined,20),/not verified/);
  assert.equal(JSON.parse(await readFile(join(root,'caller-armed.json'),'utf8')).id,g.id);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('caller wait accepts only verified receipt bytes and leaves native execution unchanged',async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'insight-caller-'))),g=goal();
 try{await writeFile(join(root,'caller-observation.json'),JSON.stringify(observed(g)));await awaitCaller(root,g);assert.deepEqual(JSON.parse(await readFile(join(root,'caller-observation.json'),'utf8')),observed(g));
  await writeFile(join(root,'caller-observation.json'),JSON.stringify({...observed(g),pc:'0x100000464'}));await assert.rejects(awaitCaller(root,g),/did not verify/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('caller goals reject redirected or oversized files before reading native state',async()=>{
 const root=await realpath(await mkdtemp(join(tmpdir(),'insight-caller-'))),other=join(root,'other.json');
 try{await writeFile(other,JSON.stringify(goal()));if(process.platform!=='win32'){await symlink(other,join(root,'caller-goal.json'));await assert.rejects(readCallerGoal(root),/owned regular file/);await rm(join(root,'caller-goal.json'));}
  await writeFile(join(root,'caller-goal.json'),' '.repeat(16385));await assert.rejects(readCallerGoal(root),/owned regular file/);
 }finally{await rm(root,{recursive:true,force:true});}
});
