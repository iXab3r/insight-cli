import test from 'node:test';import assert from 'node:assert/strict';
import {debuggerLaunchArguments} from '../src/debugger-launch.js';
test('entry-stop changes only one pinned LLDB run command and refuses ambiguous launchers',()=>{
 const original=['-o','settings set target.run-args "process launch"','-o','ghidra trace start','-o','process launch','-o','ghidra trace put-all'];
 const stopped=debuggerLaunchArguments(original,true);assert.equal(stopped[5],'process launch --stop-at-entry');assert.deepEqual(stopped.slice(0,5),original.slice(0,5));assert.deepEqual(stopped.slice(6),original.slice(6));assert.equal(original[5],'process launch');assert.deepEqual(debuggerLaunchArguments(original,false),original);assert.deepEqual(debuggerLaunchArguments(stopped,true),stopped);
 assert.throws(()=>debuggerLaunchArguments(['-o','process launch -s'],true),/exactly one/);assert.throws(()=>debuggerLaunchArguments(['-o','process launch','-o','process launch'],true),/exactly one/);assert.throws(()=>debuggerLaunchArguments(['--source','process launch'],true),/exactly one/);assert.throws(()=>debuggerLaunchArguments(['-o','process launch','-o','process launch -s'],true),/exactly one/);
});
test('native bootstrap pins and verifies the actual imported owned adapter before target creation',()=>{
 const result=debuggerLaunchArguments(['-o','script import os, ghidralldb','-o','target create image','-o','process launch'],true,'/private/owned space');
 assert.match(result[1]!,/sys.path.insert\(0,"\/private\/owned space"\)/);assert.match(result[1]!,/ghidralldb.methods.__file__/);assert.match(result[1]!,/os._exit\(253\)/);assert.equal(result[3],'target create image');assert.equal(result[5],'process launch --stop-at-entry');
 assert.throws(()=>debuggerLaunchArguments(['-o','process launch'],true,'/owned'),/adapter import/);
});
