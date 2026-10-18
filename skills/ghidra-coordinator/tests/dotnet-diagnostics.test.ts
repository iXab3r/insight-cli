import test from 'node:test';import assert from 'node:assert/strict';
import {sosReadCommand} from '../src/dotnet-diagnostics.js';
test('SOS inspection admits focused read queries and refuses command chaining, scripts and symbol configuration',()=>{
 assert.equal(sosReadCommand('!dumpheap -type BusinessState'),'dumpheap -type BusinessState');
 assert.equal(sosReadCommand('dumpobj 0x12345678'),'dumpobj 0x12345678');
 for(const query of ['exit','clrstack\nexit','dumpobj 1234; exit','setsymbolserver -ms','script /tmp/code.py','r rax=1','clrstack | shell'])assert.throws(()=>sosReadCommand(query),/supported SOS inspection/);
});
