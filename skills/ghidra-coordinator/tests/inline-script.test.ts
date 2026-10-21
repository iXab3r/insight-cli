import test from 'node:test';
import assert from 'node:assert/strict';
import {inlineReceipt,inlineSourceHash} from '../src/inline-script.js';

const expected={attemptId:'00112233-4455-6677-8899-aabbccddeeff',requestId:'q_fixture',sourceSha256:inlineSourceHash('fixture')};
const receipt=()=>({protocol:'insight-inline-v1',...expected,success:false,
  execution:{stage:'compile',userCode:'not_started',entrypointInvoked:false},diagnostic:{kind:'java-compile',message:'cannot find symbol'},
  compilerOutput:{text:'fixture diagnostic',truncated:false},console_output:'',outputTruncated:false});

test('only correlated pre-initialization native facts establish non-execution',()=>{
  assert.equal(inlineReceipt(receipt(),expected).safe,true);
  assert.equal(inlineReceipt({...receipt(),execution:{stage:'load',userCode:'not_started',entrypointInvoked:false}},expected).safe,true);
  for(const stage of ['initialize','construct','execute']){
    assert.equal(inlineReceipt({...receipt(),execution:{stage,userCode:'may_have_started',entrypointInvoked:stage==='execute'?null:false}},expected).safe,false);
    assert.throws(()=>inlineReceipt({...receipt(),execution:{stage,userCode:'not_started',entrypointInvoked:false}},expected));
  }
  for(const key of ['protocol','attemptId','requestId','sourceSha256'])assert.throws(()=>inlineReceipt({...receipt(),[key]:'wrong'},expected));
  assert.throws(()=>inlineReceipt({...receipt(),execution:{stage:'compile',userCode:'not_started',entrypointInvoked:null}},expected));
  assert.throws(()=>inlineReceipt({...receipt(),compilerOutput:{text:'x'.repeat(40000),truncated:false}},expected));
  assert.throws(()=>inlineReceipt({success:false,console_output:JSON.stringify(receipt())},expected));
});
