// Maintainer-only locked and independently reproducible ClrMD helper build.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,copyFile,mkdir,rm,readdir} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const [dotnet,output]=process.argv.slice(2);assert.ok(output);
assert.equal(execFileSync(dotnet,['--version'],{encoding:'utf8'}).trim(),'10.0.303');
const source=resolve('skills/ghidra-coordinator/runtime/managed/insight-heap');
const sha=b=>createHash('sha256').update(b).digest('hex');
const names=['Program.cs','Insight.Heap.csproj','NuGet.Config','packages.lock.json','dependencies.json'];
const dependencies=JSON.parse(await readFile(join(source,'dependencies.json'),'utf8'));
for(const dependency of Object.values(dependencies.dependencies))for(const notice of dependency.notices)names.push(notice.path);
const inputs={};for(const name of names)inputs[name]=sha(await readFile(join(source,name)));
async function tree(root,relative=''){const result={};for(const entry of await readdir(join(root,relative),{withFileTypes:true})){const name=join(relative,entry.name);if(entry.isDirectory())Object.assign(result,await tree(root,name));else{assert.ok(entry.isFile());result[name.replaceAll('\\','/')]=await readFile(join(root,name));}}return result;}
const results=[];
for(let n=0;n<2;n++){const root=await mkdtemp('/tmp/insight-heap-build-');try{
 for(const name of names){await mkdir(dirname(join(root,name)),{recursive:true});await copyFile(join(source,name),join(root,name));}
 execFileSync(dotnet,['build',join(root,'Insight.Heap.csproj'),'--configuration','Release','-p:RestoreLockedMode=true','-p:PathMap='+root+'=/_/insight-heap','--nologo'],{stdio:'pipe'});
 results.push(await tree(join(root,'bin/Release/net10.0')));
}finally{await rm(root,{recursive:true,force:true});}}
assert.deepEqual(Object.keys(results[0]).sort(),Object.keys(results[1]).sort());
await mkdir(output,{recursive:true});const files={};
for(const name of Object.keys(results[0]).sort()){assert.equal(sha(results[0][name]),sha(results[1][name]),'Independent helper builds differ: '+name);await mkdir(dirname(join(output,name)),{recursive:true});await writeFile(join(output,name),results[0][name]);files[name]={sha256:sha(results[0][name]),size:results[0][name].length};}
await writeFile(join(output,'provenance.json'),JSON.stringify({schema:1,sdk:'10.0.303',target:'net10.0',sourceLicense:'MIT',inputs,files,reproducible:true,liveAttachment:false,automaticSymbolLookup:false,dependencies:'dependencies.json'},null,2)+'\n');
