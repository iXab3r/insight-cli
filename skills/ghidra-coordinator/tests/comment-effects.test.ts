import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyComments} from '../src/comment-effects.js';
import type {ResearchBackend} from '../src/research.js';
import type {Artifact} from '../src/artifacts.js';
const snapshot={kind:'snapshot',sha256:'a'.repeat(64),size:1} as Artifact;
test('batch comment verification checks every final value and selective clearing retains other kinds',async()=>{
  const backend={inspect:async(_snapshot:Artifact,p:Record<string,unknown>)=>p.kind==='function_comments'?
    {plate:null,comments:[{kind:'pre',text:'retained',address:'1001'}]}:{eol:'second',pre:null,plate:null}} as unknown as ResearchBackend;
  await verifyComments(backend,snapshot,'/batch_set_comments',{address:'1000',disassembly_comments:[{address:'1001',comment:'first'},{address:'1001',comment:'second'}],plate_comment:''});
  await assert.rejects(verifyComments(backend,snapshot,'/batch_set_comments',{address:'1000',disassembly_comments:[{address:'1001',comment:'missing'}]}),/differs/);
  await verifyComments(backend,snapshot,'/clear_function_comments',{function:'first',clear_pre:false});
  await assert.rejects(verifyComments(backend,snapshot,'/clear_function_comments',{function:'first'}),/remain/);
});
