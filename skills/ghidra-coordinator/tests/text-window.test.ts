import test from 'node:test';
import assert from 'node:assert/strict';
import {textWindow} from '../src/text-window.js';
test('text pages preserve supplementary characters and bind a stable observed source',()=>{
 const a=textWindow('A😀B𝄞C',2,0),b=textWindow('A😀B𝄞C',2,2),c=textWindow('A😀B𝄞C',2,4);
 assert.equal(a.content,'A😀');assert.equal(b.content,'B𝄞');assert.equal(c.content,'C');assert.equal(a.totalCharacters,5);assert.equal(a.textSha256,b.textSha256);assert.equal(c.truncated,false);assert.equal(c.sourceTruncated,false);
 assert.notEqual(textWindow('Changed',2,0).textSha256,a.textSha256);
});
test('native truncation remains explicit even at the end of the observed text',()=>{
 const page=textWindow('observed prefix',100,0,true);assert.equal(page.sourceTruncated,true);assert.equal(page.truncated,true);assert.equal(page.content,'observed prefix');
});
