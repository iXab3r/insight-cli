import test from 'node:test';import assert from 'node:assert/strict';import {dnspyToken,dnspyPlan} from '../src/dnspy.js';
test('managed locations retain full MethodDef RID and explicit expected copy edits',()=>{
 assert.equal(dnspyToken('0x06abcdef'),0x06abcdef);for(const token of ['0x06000000','0x02000001','0x140001000','7','0x06bad'])assert.throws(()=>dnspyToken(token));
 const plan=dnspyPlan({method:'0x06000003',ilOffset:4,expectInt32:-2147483648,setInt32:2147483647},'edit-constant');assert.ok('ExpectedConstant'in plan);assert.equal(plan.Offset,4);assert.equal(plan.ExpectedConstant,-2147483648);assert.equal(plan.ReplacementConstant,2147483647);
 for(const options of [{setInt32:1},{expectInt32:1},{expectInt32:2147483648,setInt32:0},{expectInt32:1.5,setInt32:0}])assert.throws(()=>dnspyPlan({method:'0x06000001',...options},'edit-constant'));
});
test('typed debugger inputs preserve literal arguments and require Core module identity',()=>{
 const plan=dnspyPlan({method:'0x06000002',runtime:'core',module:'app.dll',parameters:'0, 2',arg:['','space value','quote"value','Ω','trailing\\']},'debug');assert.ok('Arguments'in plan);assert.deepEqual(plan.Arguments,['','space value','quote"value','Ω','trailing\\']);assert.deepEqual(plan.Parameters,[0,2]);
 for(const options of [{runtime:'core'},{runtime:'framework',module:'x.dll'},{parameters:'0,0'},{parameters:'0,'},{arg:['a\0b']},{runtime:'shell'}])assert.throws(()=>dnspyPlan({method:'0x06000002',...options},'debug'));
});
