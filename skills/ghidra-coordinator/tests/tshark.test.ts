import test from 'node:test';import assert from 'node:assert/strict';import {tsharkRows,tsharkStreams,tsharkFollow} from '../src/tshark.js';
test('packet fields preserve repeated nested-layer values and native frame/stream identities',()=>{
 const rows=tsharkRows(JSON.stringify([{_source:{layers:{'frame.number':['4'],'tcp.stream':['0'],'ip.src':['inner','outer'],'ip.dst':['peer'],'http.request.uri':['/1']}}},{_source:{layers:{'frame.number':['10'],'tcp.stream':['0'],'ip.src':['peer'],'ip.dst':['inner']}}}]));
 assert.deepEqual(tsharkStreams(rows),[{transport:'tcp',stream:0,frames:[4,10],sources:['inner','outer','peer'],destinations:['peer','inner']}]);for(const invalid of ['[','{}',JSON.stringify([{_source:{layers:{'frame.number':'4'}}}]),JSON.stringify([{_source:{layers:{'frame.number':['4'],'ip.src':[7]}}}])])assert.throws(()=>tsharkRows(invalid));
});
test('native raw follow preserves ordered directional bytes and refuses a different stream',()=>{
 const raw='\n===\nFollow: tcp,raw\nFilter: tcp.stream eq 0\nNode 0: 10.0.0.1:123\nNode 1: 10.0.0.2:80\n50555420\n\t48545450\n===\n',value=tsharkFollow(raw,'tcp',0);assert.deepEqual(value.chunks,[{node:0,hex:'50555420',bytes:4},{node:1,hex:'48545450',bytes:4}]);assert.equal(value.totalBytes,8);assert.throws(()=>tsharkFollow(raw,'tcp',1));assert.throws(()=>tsharkFollow(raw.replace('50555420','505'),'tcp',0));
});
