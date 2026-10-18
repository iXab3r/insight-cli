import test from 'node:test';import assert from 'node:assert/strict';import {stracePlan} from '../src/strace.js';
test('owned syscall capture accepts bounded event groups without arbitrary tracer options',()=>{
 const plan=stracePlan({events:'file,io',arg:['space value','quote"value']});assert.deepEqual(plan.programArguments,['space value','quote"value']);assert.ok(plan.arguments.includes('--kill-on-exit'));assert.ok(plan.arguments.includes('trace=%file,read,write,readv,writev'));
 for(const value of [{events:'file,file'},{events:'all'},{events:'file;inject=execve:error=ENOENT'},{stringBytes:1025},{arg:Array(65).fill('x')}])assert.throws(()=>stracePlan(value));
});
