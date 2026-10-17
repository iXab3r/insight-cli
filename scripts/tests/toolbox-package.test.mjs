import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,mkdir,readFile,rm,cp} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {prepareToolbox} from '../prepare-toolbox.mjs';

async function fixture(t,change=x=>x){
 const root=await mkdtemp(join(tmpdir(),'toolbox-admission-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const inventory=change({schema:1,skills:[{name:'insight-cli',title:'Entry',path:'SKILL.md',resources:{}},{name:'insight-probe',title:'Probe',path:'skills/insight-probe/SKILL.md',resources:{'references/probe.md':'references/probe.md'}}],tools:[{id:'probe',namespace:'probe',kind:'analytical',skill:'insight-probe',purpose:'Inspect fixture',tasks:['inspect'],inputs:['file'],platforms:['test'],dependencies:[],workflowCommands:['probe inspect'],evaluationCase:{id:'probe-case',inputFamily:'probe',task:'Inspect the supplied input',modes:['cold','prepared'],requiredObservations:['actual finding']}}]});
 const files={'package.json':JSON.stringify({type:'module',version:'1.0.0'}),'runtime/toolbox.json':JSON.stringify(inventory),'SKILL.md':'---\nname: insight-cli\n---\n# Entry 1.0.0\n','skills/insight-probe/SKILL.md':'---\nname: insight-probe\n---\n# Probe 1.0.0\n[Details](references/probe.md)\n','references/probe.md':'Canonical fixture guidance\n','dist/src/cli.js':"export const createDefinition=()=>({commands:[{name:'probe',children:[{name:'inspect'}]}]});"};
 for(const [path,text] of Object.entries(files)){await mkdir(dirname(join(root,path)),{recursive:true});await writeFile(join(root,path),text);}
 return root;
}

test('admission generates one-source resources that survive independent skill relocation',async t=>{
 const root=await fixture(t);await prepareToolbox(root);
 assert.equal(await readFile(join(root,'skills/insight-probe/references/probe.md'),'utf8'),'Canonical fixture guidance\n');
 const relocated=join(root,'independent');await cp(join(root,'skills/insight-probe'),relocated,{recursive:true});
 await rm(join(root,'references'),{recursive:true});
 assert.equal(await readFile(join(relocated,'references/probe.md'),'utf8'),'Canonical fixture guidance\n');
});

test('admission rejects unshipped skills and advertised commands without adapters',async t=>{
 for(const change of [x=>{x.tools[0].skill='insight-missing';return x;},x=>{x.tools[0].workflowCommands=['probe missing'];return x;},x=>{delete x.tools[0].evaluationCase;return x;}]){
  const root=await fixture(t,change);await assert.rejects(prepareToolbox(root),/no packaged skill|Missing advertised command|Missing agent evaluation case/);
 }
});

test('admission rejects stale versions and escaping standalone references',async t=>{
 let root=await fixture(t);await writeFile(join(root,'skills/insight-probe/SKILL.md'),'---\nname: insight-probe\n---\n# Probe 0.0.1\n');
 await assert.rejects(prepareToolbox(root),/version differs/);
 root=await fixture(t);await writeFile(join(root,'skills/insight-probe/SKILL.md'),'---\nname: insight-probe\n---\n# Probe 1.0.0\n[Outside](../../SKILL.md)\n');
 await assert.rejects(prepareToolbox(root),/escapes its own directory/);
});

test('a newly added managed tool cannot ship without discovery and skill admission',async t=>{
 const root=await fixture(t);await writeFile(join(root,'dist/src/cli.js'),`export const createDefinition=()=>({commands:[{name:'probe',children:[{name:'inspect'}]},{name:'forgotten',children:['download','install','uninstall','doctor','status'].map(name=>({name}))}]});`);
 await assert.rejects(prepareToolbox(root),/Managed tool has no packaged admission: forgotten/);
});

test('skill admission accepts CRLF checkouts without changing the packaged source',async t=>{
 const root=await fixture(t),path=join(root,'SKILL.md'),bytes=(await readFile(path,'utf8')).replaceAll('\n','\r\n');await writeFile(path,bytes);await prepareToolbox(root);assert.equal(await readFile(path,'utf8'),bytes);
});
