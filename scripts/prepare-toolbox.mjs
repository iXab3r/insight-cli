import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,rm,lstat,cp} from 'node:fs/promises';
import {join,dirname,relative,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';

const ownedPath=path=>{assert.equal(typeof path,'string');assert.ok(path&&!isAbsolute(path)&&!path.includes('\\')&&!path.split('/').some(p=>p==='..'||p==='.'||!p),'Unsafe toolbox resource path');return path;};
export async function prepareToolbox(root){
 const inventory=JSON.parse(await readFile(join(root,'runtime/toolbox.json'),'utf8'));
 assert.equal(inventory.schema,1);assert.ok(inventory.skills.length>=2);
 const version=JSON.parse(await readFile(join(root,'package.json'),'utf8')).version;
 const skills=new Map(), paths=new Set(), resources=new Map();
 for(const skill of inventory.skills){
  assert.match(skill.name,/^insight-[a-z][a-z0-9-]*$/);assert.ok(!skills.has(skill.name),'Duplicate skill');
  const entry=ownedPath(skill.path);assert.ok(!paths.has(entry),'Duplicate skill path');paths.add(entry);skills.set(skill.name,skill);
  const body=(await readFile(join(root,entry),'utf8')).replaceAll('\r\n','\n');
  assert.ok(body.startsWith('---\nname: '+skill.name+'\n'),'Skill metadata name differs: '+entry);
  assert.ok(body.split('\n').includes('# '+skill.title+' '+version),'Skill version differs: '+entry);
  // Generated resources are copies from one canonical source, not separately edited manuals.
  const dir=dirname(join(root,entry));
  if(skill.name!=='insight-cli')await rm(join(dir,'references'),{recursive:true,force:true});
  for(const [destination,source] of Object.entries(skill.resources)){
   assert.ok(destination.startsWith('references/'),'Skill resources belong under references');
   const input=join(root,ownedPath(source)),output=join(dir,ownedPath(destination));
   assert.ok((await lstat(input)).isFile(),'Skill resource source must be a regular file');
   await mkdir(dirname(output),{recursive:true});await writeFile(output,await readFile(input));
  }
  const visited=new Set();
  const links=async file=>{
   if(visited.has(file))return;visited.add(file);
   const text=await readFile(file,'utf8');
   for(const match of text.matchAll(/\]\(([^)]+)\)/g)){
    const link=match[1];if(/^[a-z][a-z0-9+.-]*:|^#/.test(link))continue;
    const target=join(dirname(file),link.split('#')[0]);const local=relative(dir,target);
    assert.ok(local&&!local.startsWith('..')&&!isAbsolute(local),'Skill reference escapes its own directory: '+skill.name);
    assert.ok((await lstat(target)).isFile(),'Missing skill reference: '+skill.name);
    if(target.endsWith('.md'))await links(target);else visited.add(target);
   }
  };
  await links(join(root,entry));
  resources.set(skill.name,{directory:dir,files:[...visited]});
 }
 const {createDefinition}=await import(pathToFileURL(join(root,'dist/src/cli.js')).href);
 const definition=createDefinition();
 try{
  const commands=new Set();
  const walk=(items,parent='')=>{for(const item of items){const path=(parent+' '+item.name.split(' ')[0]).trim();assert.ok(!commands.has(path),'Duplicate command '+path);commands.add(path);walk(item.children??[],path);}};
  walk([...definition.commands,...(definition.builtins??[])]);
  for(const app of definition.commands){const rootName=app.name.split(' ')[0],leaves=new Set((app.children??[]).map(child=>child.name.split(' ')[0]));
   if(['download','install','uninstall','doctor','status'].every(name=>leaves.has(name)))assert.ok(inventory.tools.some(tool=>tool.namespace===rootName),'Managed tool has no packaged admission: '+rootName);
  }
  const ids=new Set();
  for(const tool of inventory.tools){
   assert.match(tool.id,/^[a-z][a-z0-9-]*$/);assert.ok(!ids.has(tool.id),'Duplicate tool');ids.add(tool.id);
   const evaluation=tool.evaluationCase;
   assert.ok(evaluation&&evaluation.id&&evaluation.inputFamily&&evaluation.task&&evaluation.requiredObservations?.length&&JSON.stringify(evaluation.modes)==='[\"cold\",\"prepared\"]','Missing agent evaluation case: '+tool.id);
   assert.ok(skills.has(tool.skill),'Tool has no packaged skill: '+tool.id);
   assert.ok(commands.has(tool.namespace),'Tool has no adapter namespace: '+tool.id);
   assert.ok(tool.tasks.length&&tool.inputs.length&&tool.platforms.length&&tool.workflowCommands.length,'Incomplete tool admission: '+tool.id);
   for(const command of tool.workflowCommands)assert.ok(command.startsWith(tool.namespace+' ')&&commands.has(command),'Missing advertised command '+command);
  }
 }finally{for(const resource of [...(definition.resources??[])].reverse())await resource.dispose();}
 const bundle=join(root,'skill-bundle');
 await rm(bundle,{recursive:true,force:true});
 for(const [name,resource] of resources){
  for(const source of resource.files){
   const destination=join(bundle,name,relative(resource.directory,source));
   await mkdir(dirname(destination),{recursive:true});await cp(source,destination);
  }
 }
 await writeFile(join(bundle,'manifest.json'),JSON.stringify({schema:1,package:'@eyeauras/insight-cli',version,skills:inventory.skills.map(s=>s.name)},null,2)+'\n');
 return inventory;
}
