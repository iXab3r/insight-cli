import test from 'node:test';import assert from 'node:assert/strict';import {fridaEvents} from '../src/frida.js';
const runtime={kind:'runtime',version:'17.24.0'},end={kind:'completed',complete:true,scriptUnloaded:true,sessionDetached:true};
test('Frida source errors remain partial independently of successful native cleanup',()=>{
 const stdout=[runtime,{kind:'message',message:{type:'error',description:'owned fixture error'}},{...end,complete:false}].map(v=>JSON.stringify(v)).join('\n');const result=fridaEvents(stdout);assert.equal(result.complete,false);assert.equal(result.cleanup.sessionDetached,true);assert.equal(result.events[1]!.message.description,'owned fixture error');
 assert.equal(fridaEvents([runtime,end].map(v=>JSON.stringify(v)).join('\n')).complete,true);assert.equal(fridaEvents(JSON.stringify(end)).complete,false);assert.equal(fridaEvents([ {...runtime,version:'17.2.0'},end].map(v=>JSON.stringify(v)).join('\n')).complete,false);
});
test('Frida does not acknowledge a collector with malformed output or no cleanup receipt',()=>{
 for(const output of ['','not-json',JSON.stringify(runtime),JSON.stringify({kind:'completed'})])assert.throws(()=>fridaEvents(output));
});
test('Frida summary distinguishes script messages from protocol events and inventory records',()=>{
 const result=fridaEvents([runtime,{kind:'loaded'},{kind:'message',message:{type:'send',payload:{items:[1,2,3]}}},{kind:'message',message:{type:'send',payload:{count:10,result:130}}},{kind:'message',message:{type:'error',description:'partial'}},{kind:'message',message:{type:'log',payload:'diagnostic'}},{...end,complete:false}].map(v=>JSON.stringify(v)).join('\n'));
 assert.deepEqual(result.summary,{totalEvents:7,sendMessages:2,scriptErrors:1,logMessages:1});assert.equal(result.complete,false);
});
