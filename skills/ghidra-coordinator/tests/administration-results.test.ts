import test from 'node:test';
import assert from 'node:assert/strict';
import {administrationResult} from '../src/administration-results.js';
test('administrative acknowledgments require selected repository/path and actual readback',()=>{
  assert.throws(()=>administrationResult('file',{repository:'owned',path:'/program'},{repository:'other',file:{name:'program',path:'/program',type:'Program',version:1}}),/another/);
  assert.throws(()=>administrationResult('set_permissions',{repository:'owned',user:'reader',access:0},{repository:'owned',state:'applied',users:{reader:2},anonymous:false}),/readback/);
  assert.throws(()=>administrationResult('repositories',{}, {repositories:['owned'],count:2}),/inconsistent/);
  administrationResult('checkouts',{repository:'owned',path:'/'},{repository:'owned',path:'/',checkouts:[{id:'9223372036854775807',path:'/program',user:'publisher',version:1}]});
});
