import test from 'node:test';import assert from 'node:assert/strict';import {fridaEvents} from '../src/frida.js';
const runtime={kind:'runtime',version:'17.24.0'},end={kind:'completed',complete:true,scriptUnloaded:true,sessionDetached:true};
test('Frida source errors remain partial independently of successful native cleanup',()=>{
 const stdout=[runtime,{kind:'message',message:{type:'error',description:'owned fixture error'}},{...end,complete:false}].map(v=>JSON.stringify(v)).join('\n');const result=fridaEvents(stdout);assert.equal(result.complete,false);assert.equal(result.cleanup.sessionDetached,true);assert.equal(result.events[1]!.message.description,'owned fixture error');
 assert.equal(fridaEvents([runtime,end].map(v=>JSON.stringify(v)).join('\n')).complete,true);assert.equal(fridaEvents(JSON.stringify(end)).complete,false);assert.equal(fridaEvents([ {...runtime,version:'17.2.0'},end].map(v=>JSON.stringify(v)).join('\n')).complete,false);
});
test('Frida does not acknowledge a collector with malformed output or no cleanup receipt',()=>{
 for(const output of ['','not-json',JSON.stringify(runtime),JSON.stringify({kind:'completed'})])assert.throws(()=>fridaEvents(output));
});
