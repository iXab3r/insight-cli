// Owned macOS LLDB target: actual memory/register writes, trace history/objects and uncertain reply.
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {writeFile,mkdir} from 'node:fs/promises';import {join} from 'node:path';
import {execFile} from 'node:child_process';import {promisify} from 'node:util';
const options={};for(let i=2;i<process.argv.length;i++){const key=process.argv[i];if(key==='--ack-disposable')options.ack=true;else if(key.startsWith('--')&&process.argv[i+1])options[key.slice(2)]=process.argv[++i];else throw Error('Invalid proof option');}
assert.equal(options.ack,true);assert.equal(process.platform,'darwin');assert.ok(!Object.keys(process.env).some(k=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(k)&&process.env[k]));for(const key of ['java','ghidra-home'])assert.ok(options[key]);
const values={java:options.java,ghidraHome:options['ghidra-home']},f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update','Destructive']}]});
let native,context,receipt,opened,lose=false,lostCalls=0;const cases=[];
const app=f.createApplication(runtime=>createInsightCli({runtime:{...runtime,fetch:async(...args)=>{
 const response=await fetch(...args);if(new URL(args[0]).pathname==='/run_script_inline'){
  let p;try{p=JSON.parse(Buffer.from(JSON.parse(args[1]?.body??'{}').args??'','base64').toString());}catch{}
  if(p?.operation==='write_memory'&&p.bytes_hex==='0011223344556677'){lostCalls++;if(lose){lose=false;await response.clone().json();throw Error('Owned lost completed live-write reply');}}
 }
 return response;
}},backend:async(w,c)=>{context=c;native=new GhidraContexts(w,await nativeInputs(values),c);return native;}}));
const exec=promisify(execFile),input=join(f.root,'input');await mkdir(input);const source=join(input,'fixture.c'),exe=join(input,'owned-trace-target');
await writeFile(source,'__attribute__((used)) volatile unsigned long fixture_magic=0x1122334455667788UL;volatile unsigned long fixture_counter=0;__attribute__((noinline)) int fixture_step(int value){return value+7;}int main(void){for(;;)fixture_counter+=fixture_step(1);}\n');
await exec('/usr/bin/clang',['-O0','-g',source,'-o',exe]);const nm=(await exec('/usr/bin/nm',['-n',exe])).stdout,
 symbol=name=>{const match=new RegExp('^([a-fA-F0-9]+) [A-Za-z] '+name+'$','m').exec(nm);assert.ok(match);return match[1];},magic=symbol('_fixture_magic');
const select=s=>['--session',s.session,'--target',s.target];
async function run(s,path,args=[]){const command=['ghidra',...path.split(' '),...select(s),...args,'--json'],result=await f.run(app,command);
 if(result.exitCode){await writeFile(join(f.root,'failure.json'),JSON.stringify({command,...result}),{mode:0o600});throw Error('Native trace case failed '+path+': '+result.stderr);}return JSON.parse(result.stdout);}
function passed(name){cases.push(name);console.log('Native trace passed:',name);}
try{
 const a=opened=await f.json(app,['ghidra','open',exe,'--session','new']),b=await f.json(app,['ghidra','open',exe,'--session','new']);
 await run(a,'debugger launch',['--request-id','launch','--timeout-seconds','90']);await run(a,'debugger interrupt');
 const registers=(await run(a,'debugger registers')).value,dynamic=(await run(a,'debugger static-to-dynamic',['--address',magic])).value.dynamic_address,
  original=(await run(a,'debugger read-memory',['--address',dynamic,'--size','8'])).value.hex;
 assert.equal(original,'8877665544332211');
 const rejected=await f.run(app,['ghidra','debugger','write-memory',...select(a),'--address',dynamic,'--expect-hex','0000000000000000','--bytes-hex','0102030405060708','--request-id','rejected','--json']);assert.notEqual(rejected.exitCode,0);
 assert.equal((await run(a,'debugger read-memory',['--address',dynamic,'--size','8'])).value.hex,original);
 const writeArgs=['--address',dynamic,'--expect-hex',original,'--bytes-hex','0102030405060708','--request-id','write-memory'],write=await run(a,'debugger write-memory',writeArgs);
 assert.equal(write.value.verified_from,'live_target_refresh');assert.deepEqual(await run(a,'debugger write-memory',writeArgs),write);
 assert.equal((await run(a,'debugger read-memory',['--address',dynamic,'--size','8'])).value.hex,'0102030405060708');
 await run(a,'debugger write-memory',['--address',dynamic,'--expect-hex','0102030405060708','--bytes-hex',original]);passed('Native stopped-target memory precondition, actual write/refresh, retry and restoration');
 const register=Object.keys(registers).find(name=>/^(x9|r9)$/i.test(name));assert.ok(register,'Owned architecture requires x9/r9 scratch register');
 const before=registers[register],desired=BigInt(before)===0x1234n?'0x1235':'0x1234',registerArgs=['--register',register,'--expect-value',before,'--value',desired,'--request-id','write-register'];
 const changed=await run(a,'debugger write-register',registerArgs);assert.equal(BigInt(changed.value.value),BigInt(desired));assert.deepEqual(await run(a,'debugger write-register',registerArgs),changed);
 assert.equal(BigInt((await run(a,'debugger registers')).value[register]),BigInt(desired));await run(a,'debugger write-register',['--register',register,'--expect-value',desired,'--value',before]);passed('Native target register write, refreshed readback, exact width and restoration');
 const timeline=(await run(a,'debugger timeline',['--limit','5'])).value;assert.ok(timeline.items.length);assert.ok(timeline.items.every(row=>/^-?\d+$/.test(row.snap)));
 const objects=(await run(a,'debugger objects',['--limit','1000','--max-scan','10000'])).value;assert.ok(objects.items.length);assert.ok(objects.items.every(row=>/^\d+$/.test(row.object_id)));
 const limited=(await run(a,'debugger objects',['--limit','5','--max-scan','1'])).value;assert.equal(limited.visited,1);assert.equal(limited.complete,false);
 const processObject=objects.items.find(row=>row.schema==='Process');assert.ok(processObject);
 const attributes=(await run(a,'debugger object-values',['--object-id',processObject.object_id,'--key','_display'])).value;assert.equal(attributes.object_id,processObject.object_id);assert.equal(attributes.complete,true);
 const snap=(await run(a,'debugger status')).value.snap,schedule=(await run(a,'debugger schedule',['--schedule',String(snap)])).value;assert.equal(schedule.executed,false);assert.equal(schedule.validated,true);assert.equal(schedule.snap_only,true);
 passed('Native timeline, stable object IDs, bounded object/value queries and non-executing schedule validation');
 assert.equal((await run(b,'memory read',['--address',magic,'--length','8'])).value.hex.toLowerCase(),original);
 lose=true;const lostArgs=['ghidra','debugger','write-memory',...select(a),'--address',dynamic,'--expect-hex',original,'--bytes-hex','0011223344556677','--request-id','lost-write'];
 assert.notEqual((await f.run(app,[...lostArgs,'--json'])).exitCode,0);assert.equal(lose,false);
 assert.equal((await run(a,'debugger read-memory',['--address',dynamic,'--size','8'])).value.hex,'0011223344556677');
 assert.notEqual((await f.run(app,[...lostArgs,'--json'])).exitCode,0);assert.equal(lostCalls,1);passed('Lost completed live reply remains uncertain and cannot repeat the target write');
 await run(a,'close');await run(a,'open');assert.equal((await run(a,'debugger status')).connectionState,'disconnected');
 assert.equal((await run(a,'debugger read-memory',['--address',dynamic,'--size','8'])).value.hex,'0011223344556677');
 assert.ok((await run(a,'debugger objects',['--limit','1000'])).value.items.some(row=>row.object_id===processObject.object_id));
 assert.notEqual((await f.run(app,[...lostArgs,'--json'])).exitCode,0);assert.equal(lostCalls,1);passed('Saved trace retains changed bytes/object identity after disconnect; execution is not resurrected');
 receipt={schema:1,state:'passed',scope:'owned native macOS LLDB trace and guarded live writes',cases,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,
  limitations:['Owned native macOS process only; register values restored before further execution.','Live read-before-write preconditions are not atomic compare-exchange; no CPU resurrection or automatic retry.','Schedules are parsed/validated, not executed.']};
}catch(error){console.error('Owned trace diagnostics:',f.root);throw error;}
finally{if(opened)try{await native.debuggerStop(opened);}catch{}await app.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
if(receipt){await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
