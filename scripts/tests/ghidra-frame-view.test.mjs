import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

test('owned LLDB frame view removes only a zero-span stale prefix matching the live CPU',()=>{
 const source=readFileSync(new URL('../../skills/ghidra-coordinator/references/native/InsightPythonWheels.java',import.meta.url),'utf8').replaceAll('\r\n','\n');
 const blocks=[...source.matchAll(/    utilSource\+="""\n([\s\S]*?)    """;/g)].map(m=>m[1].split('\n').map(line=>line.replace(/^ {4}/,'')).join('\n'));
 assert.equal(blocks.length,2);
 const aliases=source.match(/    String registerAliases="""\n([\s\S]*?)    """;/)?.[1].split('\n').map(line=>line.replace(/^ {4}/,'')).join('\n');
 assert.ok(aliases);
 const base='class DefaultRegisterMapper:\n def map_name(self,proc,name): return name\n def map_name_back(self,proc,name): return name\n';
 const result=execFileSync('python3',['-I','-c','INSIGHT_NORMALIZE_PHYSICAL_STACK=True\n'+base+aliases+'\n'+blocks.join('\n')+`
mapper=InsightAarch64RegisterMapper()
assert [mapper.map_name(None,n) for n in ['fp','lr','pc','x0']]==['x29','x30','pc','x0']
assert [mapper.map_name_back(None,n) for n in ['x29','x30','pc','x0']]==['fp','lr','pc','x0']
class Value:
 def __init__(self, number, valid=True): self.number,self.valid=number,valid
 def IsValid(self): return self.valid
 def GetError(self): return self
 def Fail(self): return not self.valid
 def GetValueAsUnsigned(self): return self.number
class Frame:
 def __init__(self, identity, pc, sp, cfa, inline=False, artificial=False):
  self.identity,self.pc,self.sp,self.cfa,self.inline,self.artificial=identity,pc,sp,cfa,inline,artificial
 def GetFrameID(self): return self.identity
 def GetPC(self): return self.pc
 def GetSP(self): return self.sp
 def GetCFA(self): return self.cfa
 def IsInlined(self): return self.inline
 def IsArtificial(self): return self.artificial
 def GetThread(self): return self.thread
 def FindRegister(self,name): return Value(self.thread.pc if name=='pc' else self.thread.sp,self.thread.valid)
class Thread:
 def __init__(self, frames, pc, sp=0x1000, valid=True):
  self.items,self.pc,self.sp,self.valid=frames,pc,sp,valid
  for frame in frames: frame.thread=self
 def GetNumFrames(self): return len(self.items)
 def GetFrameAtIndex(self,index): return self.items[index]
def identities(thread): return [f.GetFrameID() for f in insight_frames(thread)]
# Observed native shape: old leaf frame and current caller share SP, but only the
# caller matches the CPU PC; the old frame has no remaining stack span.
frames=[Frame(0,0x464,0x1000,0x1000),Frame(1,0x508,0x1000,0x1030),Frame(2,0x900,0x1030,0x1100)]
t=Thread(frames,0x508)
assert identities(t)==[1,2]
assert insight_frame_level(frames[0])==0
assert insight_frame_level(frames[1])==0
assert insight_frame_level(frames[2])==1
assert insight_frame_native_index(frames[1])==1
assert insight_frame_pc(frames[1])==0x508
# Unwound caller banks cannot supply volatile return registers. Logical top-frame
# register operations must continue to address the live native hardware frame.
frames[0].return_value,frames[1].return_value=109,0
assert insight_frame_for_level(t,0).return_value==109
assert insight_frame_for_level(t,1) is frames[2]
# Recursive duplicate return PCs remain distinct, including non-dense native IDs.
r=Thread([Frame(0,0x494,0x1000,0x1020),Frame(2,0x494,0x1020,0x1040),Frame(3,0x494,0x1040,0x1060)],0x494)
assert identities(r)==[0,2,3]
assert [insight_frame_level(f) for f in r.items]==[0,1,2]
# A stale recursive callee can share the return PC as well as the current SP.
ghost=Thread([Frame(0,0x494,0x1000,0x1000),Frame(2,0x494,0x1000,0x1020),Frame(3,0x494,0x1020,0x1040)],0x494)
assert identities(ghost)==[2,3]
for altered in [Frame(0,0x464,0x1000,0x1000,inline=True),Frame(0,0x464,0x1000,0x1000,artificial=True),Frame(0,0x464,0x1000,0x1020)]:
 candidate=Thread([altered,Frame(1,0x508,0x1000,0x1030)],0x508)
 assert identities(candidate)==[0,1]
 if altered.inline or altered.artificial: assert insight_frame_pc(altered)==0x464
assert identities(Thread([Frame(0,0x464,0x1000,0x1000),Frame(1,0x508,0x1020,0x1040)],0x508))==[0,1]
assert identities(Thread([Frame(0,0x464,0x1000,0x1000),Frame(1,0x508,0x1000,0x1030)],0x508,valid=False))==[0,1]
assert identities(Thread([],0x508))==[]
print('native frame view invariants passed')
`],{encoding:'utf8',timeout:15000});
 assert.match(result,/native frame view invariants passed/);
});
