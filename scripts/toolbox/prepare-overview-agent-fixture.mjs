// Maintainer-only large static input; the consumer receives only the assembly, never source.
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile,readdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const [directory,dotnet]=process.argv.slice(2);assert.ok(directory&&dotnet,'Arguments: fresh-directory SDK-dotnet');
const root=resolve(directory),execute=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
await mkdir(root,{recursive:true});assert.deepEqual(await readdir(root),[]);
const source=join(root,'source');await mkdir(source);
await writeFile(join(source,'ReviewPolicy.csproj'),'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType><Deterministic>true</Deterministic><DebugType>none</DebugType><AssemblyName>ReviewPolicy</AssemblyName></PropertyGroup></Project>\n');
const methods=[];
for(let n=0;n<1000;n++){
 methods.push('public static int Helper'+String(n).padStart(4,'0')+'(int value) => value + '+n+';');
 if(n===576)methods.push('public static int ComputeInvoice(int count) => count <= 20 ? count * 9 + 37 : count * 6 + 91;');
}
const body='namespace InvoiceResearch; public static class ReviewPolicy { public const string Label = "révision 🧭";\n'+methods.join('\n')+'\n}\n';
await writeFile(join(source,'Policy.cs'),body);
await execute(resolve(dotnet),['build',join(source,'ReviewPolicy.csproj'),'-c','Release','-o',join(root,'out'),'--nologo'],{timeout:60000,maxBuffer:1024**2});
const assembly=join(root,'out/ReviewPolicy.dll');
await writeFile(join(root,'fixture.json'),JSON.stringify({schema:1,assembly,sha256:sha(await readFile(assembly)),sourceSha256:sha(Buffer.from(body)),sdk:(await execute(resolve(dotnet),['--version'])).stdout.trim(),methods:1001,authorSourceSupplied:false},null,2)+'\n');
console.log('Large static overview/drilldown fixture prepared.');
