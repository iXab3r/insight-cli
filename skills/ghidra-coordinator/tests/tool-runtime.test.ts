import test from 'node:test';
import assert from 'node:assert/strict';
import {createCli} from '@eyeauras/cli-factory';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {defineTool,lifecycleCommands,type ToolDefinition} from '../src/tool-runtime/definition.js';

test('Ghidra and one-shot definitions share Factory lifecycle, permission gates and JSON',async t=>{
 const f=await createCliFixture(t,{applicationId:'tool-fixture'});let writes=0;
 const tool=(id:string,components:ToolDefinition['components'])=>defineTool({id,description:'Fixture',components,lifecycle:{
  async status(){return {tool:id,state:'not_ready'};},async download(){writes++;return {state:'downloaded'};},
  async install(){writes++;return {state:'installed'};},async uninstall(){writes++;return {state:'uninstalled'};},async doctor(){return {state:'verified'};},
 }});
 const ghidra=tool('ghidra',[{id:'jdk',version:'fixture',artifacts:[]},{id:'ghidra',version:'fixture',dependencies:['jdk'],artifacts:[]}]);
 const ilspy=tool('ilspy',[{id:'ilspy',version:'fixture',artifacts:[]}]);
 for(const item of [ghidra,ilspy]){
  const app=f.createApplication(runtime=>createCli({name:'tool-fixture',description:'Tool contract fixture',runtime,permissions:{categories:[{name:'Destructive',description:'Remove owned files',enabledByDefault:false}]},commands:lifecycleCommands(item)}));
  assert.equal((await f.json(app,['status']) as any).tool,item.id);
  const denied=await f.run(app,['install','--json']);assert.notEqual(denied.exitCode,0);assert.equal(writes,0);
 }
 assert.throws(()=>tool('bad',[{id:'a',version:'1',artifacts:[],dependencies:['a']}]),/Cyclic/);
 assert.throws(()=>tool('bad',[{id:'a',version:'1',artifacts:[],dependencies:['missing']}]),/Unknown/);
});
