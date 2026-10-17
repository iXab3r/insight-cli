import test from 'node:test';import assert from 'node:assert/strict';import {windbgPlan,windbgSnapshot} from '../src/windbg.js';
test('dump query accepts only bounded typed views and literal runtime addresses',()=>{
 assert.match(windbgPlan({view:'memory',address:'0x1234',count:64},'fixture').commands,/db 0x1234 L0x40/);
 assert.match(windbgPlan({view:'stack',thread:2,frames:12},'fixture').commands,/~2s; kp 0n12/);
 for(const value of [{view:'memory',address:'0x12;.shell evil'},{view:'memory',address:'0x12',count:4097},{view:'.shell'},{view:'modules',address:'0x1'},{view:'threads',frames:5}])assert.throws(()=>windbgPlan(value,'fixture'));
});
test('dump warnings remain partial and incomplete query markers do not become success',()=>{
 const snapshot=windbgSnapshot('header\nINSIGHT_BEGIN_x\nrip=123\nMemory access error\nINSIGHT_END_x\nquit','x');assert.equal(snapshot.complete,false);assert.equal(snapshot.warnings.length,1);assert.throws(()=>windbgSnapshot('failed to open','x'),/did not complete/);
});
