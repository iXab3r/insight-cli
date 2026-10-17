import test from 'node:test';import assert from 'node:assert/strict';import {lldbPlan,lldbSnapshot} from '../src/lldb.js';
test('LLDB owns cleanup, disables init/stdio side channels and treats arguments literally',()=>{
 const plan=lldbPlan({breakpoint:'quote_total',hit:11,arg:['--input','space $HOME (literal)'],memoryAddress:'$sp',memoryBytes:16,stepOut:true});
 assert.ok(plan.includes('settings set target.detach-on-error false'));assert.ok(plan.includes('settings set target.disable-stdio true'));assert.ok(plan.some(c=>c.includes('--ignore-count 10')));assert.ok(plan.some(c=>c.includes('--shell-expand-args false -- "--input" "space $HOME (literal)"')));assert.ok(plan.includes('memory read --format x --size 1 --count 16 $sp'));assert.deepEqual(plan.slice(-4),['thread step-out','register read pc sp x0','process kill','quit']);
 for(const options of [{breakpoint:'evil\nprocess attach -p 1'},{breakpoint:'0xnot-an-address'},{breakpoint:'x',registers:'pc; script evil'},{breakpoint:'x',memoryAddress:'(int)system("bad")'},{breakpoint:'x',memoryBytes:10},{breakpoint:'x',hit:0},{breakpoint:'x',arg:['`(int)7`']},{breakpoint:'x',arg:['a\0b']}])assert.throws(()=>lldbPlan(options));
});
test('LLDB never accepts a pending breakpoint, missing stop or unacknowledged cleanup as a snapshot',()=>{
 const start='Process 1234 launched: "/owned/subject"\n',stop='stop reason = one-shot breakpoint 1\n',end='Process 1234 exited with status = 9 (0x00000009) killed\n';assert.equal(lldbSnapshot(start+stop+end).inferiorPid,1234);
 for(const stdout of [start+end,start+stop,stop+end,start+stop+'Process 5678 exited with status = 9'])assert.throws(()=>lldbSnapshot(stdout));
});
