import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodedInstructions} from '../src/decode-results.js';
test('read-only decoding binds every instruction to the bounded bytes and rejects invented flow',()=>{
 const row={address:'1000',bytes:'c3',length:1,mnemonic:'RET',operands:[],direct_targets:[],computed_flow:false};
 const result={address:'1000',input_bytes:'c3',input_sha256:createHash('sha256').update(Buffer.from('c3','hex')).digest('hex'),instructions:[row],consumed_bytes:1,language:'x86:LE:64:default',stop_reason:'terminal_flow',read_only:{modification_unchanged:true}};
 assert.equal(decodedInstructions(result,'1000',1,1),result);
 for(const patch of [{consumed_bytes:2},{input_bytes:'90'},{instructions:[{...row,address:'1001'}]},{instructions:[{...row,bytes:'90'}]},{instructions:[{...row,computed_flow:true,direct_targets:['1004']}]},{read_only:{modification_unchanged:false}}])assert.throws(()=>decodedInstructions({...result,...patch},'1000',1,1));
 assert.throws(()=>decodedInstructions(result,'1000',1,0));
});
