import test from 'node:test';
import assert from 'node:assert/strict';
import {convertNumber} from '../src/utility.js';
test('stateless conversion preserves 64-bit boundaries, masks width and supports all pinned bases',()=>{
  const wide=convertNumber('18446744073709551615',8);assert.equal(wide.decimal_unsigned,'18446744073709551615');assert.equal(wide.decimal_signed,'-1');assert.equal(wide.hex_padded,'0xFFFFFFFFFFFFFFFF');
  assert.equal(convertNumber('0x80',1).decimal_signed,'-128');assert.equal(convertNumber('0b1010').decimal_unsigned,'10');assert.equal(convertNumber('011').decimal_unsigned,'9');
  assert.equal(convertNumber('008').input_type,'decimal');assert.equal(convertNumber('256',1).decimal_unsigned,'0');
  assert.throws(()=>convertNumber('18446744073709551616',8),/64-bit/);assert.throws(()=>convertNumber('-1'),/64-bit/);assert.throws(()=>convertNumber('1',0),/1–8/);
});
