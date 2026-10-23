import test from 'node:test';
import assert from 'node:assert/strict';
import {researchView} from '../src/research-view.js';
import {inspectFunctions} from '../src/function-inspection.js';
import type {ResearchBackend} from '../src/research.js';

const view={protocol:'insight-research-view-v1',modification:'42',language:'x86:LE:64:default',compiler:'windows'};
test('versioned native observations retain existing logical identity inputs and reject malformed facts',()=>{
 assert.deepEqual(researchView(view),{modification:'42',language:'x86:LE:64:default',compiler:'windows'});
 for(const patch of [{protocol:'unknown'},{modification:42},{modification:'NaN'},{language:''},{compiler:'\0'},{modification:'9'.repeat(21)}])assert.throws(()=>researchView({...view,...patch}));
});
test('fast before/after observations detect modification and process/program replacement and do not fall back after errors',async()=>{
 const scope={session:'s_fixture',target:'t_fixture'},before={...researchView(view),incarnation:'one'},opts={limit:16,offset:0,total:16};let calls=0;
 const backend={call:async()=>{calls++;return {functions:{main:{name:'main',entry_point:'140001000'}}};},observation:async()=>{throw Error('Legacy observation must not be used');}} as unknown as ResearchBackend;
 const invoke=(observe:()=>Promise<unknown>)=>inspectFunctions(backend,scope,{function:'main',fields:'entry_point'},opts,{identity:'view'},before,observe);
 assert.equal(((await invoke(async()=>before)).value as Record<string,unknown>).entry_point,'140001000');
 for(const changed of [{...before,modification:'43'},{...before,incarnation:'replacement'},{...before,language:'other'}])await assert.rejects(invoke(async()=>changed),(e:unknown)=>(e as any).result.reason==='changed_view');
 await assert.rejects(invoke(async()=>{throw Error('lost observation');}),/lost observation/);assert.equal(calls,5);
});
