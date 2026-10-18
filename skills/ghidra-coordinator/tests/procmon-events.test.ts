import test from 'node:test';import assert from 'node:assert/strict';import {procmonEvents,procmonScope} from '../src/procmon-events.js';
const csv='"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\r\n"12:01","worker.exe","42","ReadFile","C:\\a,b\\Ω.txt","SUCCESS","value ""quoted"",\r\nsecond line"\r\n';
test('native event CSV retains Unicode, commas, escaped quotes and multiline details in both encodings',()=>{
 for(const bytes of [Buffer.from('\uFEFF'+csv),Buffer.concat([Buffer.from([0xff,0xfe]),Buffer.from(csv,'utf16le')])]){const events=procmonEvents(bytes);assert.equal(events.length,1);assert.equal(events[0]!.path,'C:\\a,b\\Ω.txt');assert.equal(events[0]!.detail,'value "quoted",\r\nsecond line');assert.equal(procmonScope(events,42,'c:\\A,B\\Ω.txt').length,1);assert.throws(()=>procmonScope(events,43));}
});
test('incomplete CSV and unsupported rows remain explicit uncertainty',()=>{
 for(const source of ['"Process Name","PID"\r\n"x","1"','"PID","PID"\r\n1,1',csv.slice(0,-4),csv+'"unexpected"'])assert.throws(()=>procmonEvents(Buffer.from(source)));
 assert.throws(()=>procmonEvents(Buffer.from([0xff,0x00,0xfe])));assert.throws(()=>procmonEvents(Buffer.alloc(16*1024**2+1)));
});
