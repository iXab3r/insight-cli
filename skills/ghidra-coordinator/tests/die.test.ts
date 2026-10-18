import test from 'node:test';import assert from 'node:assert/strict';
import {dieJson,dieFindings} from '../src/die.js';
test('DiE zero-exit JSON followed by signature diagnostics remains explicitly partial',()=>{
 const document={detects:[{filetype:'PE32',offset:'0',parentfilepart:'Header',values:[{name:'.NET Core',type:'library',version:'CLR 4',info:'quoted } { \\"',string:'Library: .NET Core'}]}]};
 const clean=dieJson(JSON.stringify(document),'');assert.equal(clean.complete,true);
 const partial=dieJson(JSON.stringify(document)+'\nSignature.sg: 271: TypeError\n','Unimplemented code.');assert.equal(partial.complete,false);assert.equal(partial.diagnostics.length,2);assert.deepEqual(partial.data,document);
 assert.equal(dieFindings(partial.data)[0]!.name,'.NET Core');
});
test('DiE malformed or absent structured data is not accepted as a complete classification',()=>{
 for(const input of ['', 'error only','{"detects": [','{broken}'])assert.throws(()=>dieJson(input,''));
 for(const data of [{},{detects:{}},{detects:[{}]},{detects:[{filetype:'PE',values:[{name:'missing fields'}]}]}])assert.throws(()=>dieFindings(data));
 assert.deepEqual(dieFindings({detects:[]}),[]);
});
