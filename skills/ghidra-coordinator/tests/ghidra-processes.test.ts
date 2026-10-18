import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,symlink,rm,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import type {CommandContext} from '@eyeauras/cli-factory';
import type {ProcessRecord} from '../src/tool-runtime/supervisor.js';
import {verifyGhidraProcess} from '../src/ghidra-processes.js';

test('authenticated debugger ownership accepts the profile alias and rejects replaced child links',async t=>{
 if(process.platform==='win32'){t.skip('Directory-link privileges are not a Windows unit prerequisite');return;}
 const temporary=await mkdtemp(join(tmpdir(),'debugger-owner-alias-'));t.after(()=>rm(temporary,{recursive:true,force:true}));
 const actual=join(await realpath(temporary),'actual'),alias=join(temporary,'alias');await mkdir(actual);await symlink(actual,alias,'dir');
 const suffix='workspace/ghidra-native/context/fixture',root=join(actual,suffix),rawRoot=join(alias,suffix);await mkdir(root,{recursive:true});
 const receipt=join(root,'debugger.json');await writeFile(join(root,'process.json'),JSON.stringify({root,pid:300,tokenSecret:'fixture-secret'}));await writeFile(receipt,JSON.stringify({id:'fixture-debugger',root,ownerToken:'fixture-secret',guiPid:300,supervisorPid:400,childPid:500,identityPort:1234}));
 let reads=0;
 const c={appArguments:{AppDataDirectory:alias},secrets:{require:async(name:string)=>{assert.equal(name,'fixture-secret');return 'fixture-token';}},fetch:async(url:string,options:RequestInit)=>{reads++;assert.equal(url,'http://127.0.0.1:1234/identity');assert.equal((options.headers as Record<string,string>).Authorization,'Bearer fixture-token');return new Response(JSON.stringify({id:'fixture-debugger',pid:400,childPid:500}));}} as unknown as CommandContext;
 const record:ProcessRecord={schema:1,id:'00000000-0000-4000-8000-000000000001',tool:'ghidra',role:'debugger',installation:'fixture',state:'running',executable:process.execPath,root,ownerPid:process.pid,profileBinding:'fixture',gated:false,createdAt:new Date().toISOString(),pid:500,metadata:{debuggerReceipt:receipt,contextRoot:root}};
 assert.equal(await verifyGhidraProcess(record,c),true);
 assert.equal(await verifyGhidraProcess({...record,metadata:{debuggerReceipt:join(rawRoot,'debugger.json'),contextRoot:rawRoot}},c),true);assert.equal(reads,2);
 assert.equal(await verifyGhidraProcess({...record,pid:501},c),false);
 await symlink(root,join(actual,'redirect'),'dir');assert.equal(await verifyGhidraProcess({...record,metadata:{debuggerReceipt:join(alias,'redirect/debugger.json'),contextRoot:root}},c),false);assert.equal(reads,3,'A replaced child path must reject before authenticated I/O');
});
