import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {inspectFunctions} from '../src/function-inspection.js';
import type {ResearchBackend} from '../src/research.js';
test('bulk result and saved-source limits reject before creating a manifest or directory',async t=>{
 const root=await mkdtemp(join(tmpdir(),'bounded-functions-'));t.after(()=>rm(root,{recursive:true,force:true}));let code='return;',comments='x'.repeat(1048576),calls=0;
 const backend={call:async()=>{calls++;return {functions:{one:{name:'one',entry_point:'1000',decompiled_code:code,comments}}};}} as unknown as ResearchBackend;
 const selected={session:'s_fixture',target:'t_fixture'},parameters={functions:'one',fields:'entry_point,decompiled_code,comments'},options={limit:4,offset:0,total:4,saveDirectory:join(root,'saved')},view={identity:'owned'};
 await assert.rejects(inspectFunctions(backend,selected,parameters,options,view),{code:'coordinator.limit'});await assert.rejects(stat(options.saveDirectory),{code:'ENOENT'});
 comments='';code='x'.repeat(4*1024**2+1);await assert.rejects(inspectFunctions(backend,selected,parameters,options,view),{code:'coordinator.limit'});await assert.rejects(stat(options.saveDirectory),{code:'ENOENT'});
 await assert.rejects(inspectFunctions(backend,selected,{functions:Array.from({length:21},(_,i)=>'f'+i).join(',')},options,view),{code:'coordinator.invalid'});assert.equal(calls,2);
});
