import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

test('owned trace batches permit reply callbacks and unwind model transactions after failures',()=>{
 const source=readFileSync(new URL('../../skills/ghidra-coordinator/references/native/InsightPythonWheels.java',import.meta.url),'utf8').replaceAll('\r\n','\n');
 const blocks={};for(const name of ['batchEndBefore','batchEndAfter','traceTxAfter','batchBodyAfter','trackedTxAfter']){
  const value=source.match(new RegExp('    String '+name+'="""\\n([\\s\\S]*?)    """;'))?.[1];assert.ok(value,name);blocks[name]=value.split('\n').map(line=>line.replace(/^ {4}/,'')).join('\n');
 }
 const result=execFileSync('python3',['-I','-c',`
from typing import Optional,List,Any
from concurrent.futures import Future,TimeoutError
from contextlib import contextmanager
from types import SimpleNamespace
from threading import Lock,Event,Thread
blocks=${JSON.stringify(blocks)}
def callback_case(code):
 ns={'Optional':Optional,'List':List,'Any':Any}
 exec('class Client:\\n'+code,ns)
 client=ns['Client']();client._block=Lock();ready=Event();reply=Future()
 class Batch:
  def dec(self): return 0
  def results(self):
   ready.set()
   return [reply.result(timeout=2)]
 client.cur_batch=Batch()
 def receiver_callback():
  assert ready.wait(3)
  with client._block:
   reply.set_result('callback entered the batch state')
 worker=Thread(target=receiver_callback,daemon=True);worker.start()
 try:
  try: result=client.end_batch()
  except TimeoutError: return False
  return result==['callback entered the batch state'] and client.cur_batch is None
 finally:
  worker.join(3)
  assert not worker.is_alive()
# The pinned implementation reproduces the wait cycle; the adapter must break it.
assert not callback_case(blocks['batchEndBefore'])
assert callback_case(blocks['batchEndAfter'])
class Wanted(Exception): pass
actions=[]
class Tx:
 def commit(self): actions.append('commit')
 def abort(self): actions.append('abort')
ns={'contextmanager':contextmanager}
exec('@contextmanager\\ndef transaction(self,description,undoable=False):\\n'+blocks['traceTxAfter'],ns)
transaction=ns['transaction'];trace=SimpleNamespace(start_tx=lambda *args:Tx())
with transaction(trace,'normal'): pass
assert actions==['commit'];actions.clear()
try:
 with transaction(trace,'failed'): raise Wanted('model write failed')
except Wanted: pass
else: raise AssertionError('failure was swallowed')
assert actions==['abort'];actions.clear()
trace.open_tx=lambda description:transaction(trace,description)
state=SimpleNamespace(tx=None,require_trace=lambda:trace)
state.reset_tx=lambda:setattr(state,'tx',None)
ns={'STATE':state,'contextmanager':contextmanager}
exec('@contextmanager\\ndef tracked(description):\\n'+blocks['trackedTxAfter'],ns)
try:
 with ns['tracked']('failed'):
  assert isinstance(state.tx,Tx)
  raise Wanted('tracked write failed')
except Wanted: pass
assert state.tx is None and actions==['abort']
ended=[];client=SimpleNamespace(start_batch=lambda:'batch',end_batch=lambda:ended.append('end'))
ns={'contextmanager':contextmanager}
exec('@contextmanager\\ndef batch(self):\\n'+blocks['batchBodyAfter'],ns)
try:
 with ns['batch'](client) as value:
  assert value=='batch'
  raise Wanted('batch write failed')
except Wanted: pass
assert ended==['end']
print('TRACE_BATCH_CALLBACK_AND_FAILURE_CLEANUP_PASSED')
`],{encoding:'utf8',timeout:15000});
 assert.match(result,/TRACE_BATCH_CALLBACK_AND_FAILURE_CLEANUP_PASSED/);
});
