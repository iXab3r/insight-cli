// Structural accounting only: command presence does not substitute for native acceptance.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createDefinition} from '../skills/ghidra-coordinator/dist/src/cli.js';
const definition=createDefinition(),leaves=new Map();
function collect(rows,prefix=''){
  for(const row of rows){const path=(prefix+' '+row.name.split(' ')[0]).trim();if(row.children)collect(row.children,path);
    else{assert.ok(!leaves.has(path),'Duplicate command '+path);leaves.set(path,row);}}
}
collect(definition.commands);assert.ok(definition.auth,'Factory authentication equivalent');
const ledger=await readFile(new URL('../docs/GHIDRA-COVERAGE.md',import.meta.url),'utf8'),operations=[],bridge=[];
let category='';
for(const line of ledger.split(/\r?\n/)){
  const title=/^### (\w+)/.exec(line);if(title)category=title[1];
  const row=/^\| `(\/[^`]+)` \| `([^`]+)` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$/.exec(line);
  if(row){
    const [,path,equivalent,mode,access,scope,effect]=row,command=equivalent.replace(/\s*\(.*/,'').trim(),leaf=leaves.get(command);
    assert.ok(leaf||['auth login','--help'].includes(command),'Missing command/equivalent '+path+': '+command);
    operations.push({path,category,command,mode:mode.trim(),upstreamAccess:access.trim(),scope:scope.trim(),effect:effect.trim(),
      factoryPermission:leaf?.permission??'Factory builtin',requestId:Boolean(leaf?.options?.some(option=>option.flags.startsWith('--request-id ')))});
  }
  const control=/^\| `(list_instances|connect_instance|list_tool_groups|load_tool_group|unload_tool_group|check_tools|search_tools|import_file)` \| (.+) \|$/.exec(line);
  if(control)bridge.push({control:control[1],equivalent:control[2]});
}
assert.equal(operations.length,210);assert.equal(new Set(operations.map(row=>row.path)).size,210);assert.equal(bridge.length,8);
for(const file of ['queries.json','mutations.json']){
  const schema=JSON.parse(await readFile(new URL('../skills/ghidra-coordinator/references/'+file,import.meta.url),'utf8'));
  for(const tool of schema.tools){const mapped=operations.find(row=>row.path===tool.path);assert.ok(mapped,'Unaccounted typed adapter '+tool.path);assert.equal(mapped.command,'ghidra '+tool.command);}
}
const report={schema:1,scope:'command/equivalence accounting; behavioral acceptance remains separate',
  catalogCommit:'57e37a8bf388b1279cff46378f85be1554548f61',catalogSha256:'ebdaa9195ec2ea55fb706107bba1ee3732abd2eda783ed67a6ccc7359fdc5c66',
  commandTreeSha256:createHash('sha256').update(JSON.stringify(operations)).digest('hex'),sourceOperations:operations.length,bridgeControls:bridge.length,publicLeaves:leaves.size,operations,bridge};
console.log(JSON.stringify(process.argv.includes('--summary')?{sourceOperations:operations.length,bridgeControls:bridge.length,publicLeaves:leaves.size,commandTreeSha256:report.commandTreeSha256}:report,null,2));
