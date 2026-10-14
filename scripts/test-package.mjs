// Locked offline pack/install proof. npm ci setup populates the ordinary artifact cache.
import assert from 'node:assert/strict';import{execFile}from'node:child_process';import{promisify}from'node:util';import{mkdtemp,mkdir,readFile,writeFile,cp,rm,realpath}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';import{createHash}from'node:crypto';import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),exec=promisify(execFile);
const proof=await realpath(await mkdtemp(join(process.platform==='win32'?tmpdir():'/tmp','ip-'))),install=join(proof,'installed spaces-Ω');await mkdir(install);
const provenance=JSON.parse(await readFile(join(root,'vendor/provenance.json'),'utf8'));
assert.equal(createHash('sha256').update(await readFile(join(root,'vendor',provenance.file))).digest('hex'),provenance.sha256);
try{
 const artifacts=join(install,'artifacts');await mkdir(artifacts);
 const pack=JSON.parse((await exec('npm',['pack','--ignore-scripts','--json','--workspace','@ixab3r/insight-ghidra','--pack-destination',artifacts],{cwd:root})).stdout)[0];
 const files=new Set(pack.files.map(f=>f.path));for(const path of ['SKILL.md','references/setup.md','references/findings.md','references/recovery.md','references/InsightRepositoryProbe.java','LICENSE','dist/src/bin.js','.cli-package-build.json'])assert.ok(files.has(path),path);
 assert.ok([...files].every(f=>!f.includes('/tests/')&&(!f.endsWith('.ts')||f.endsWith('.d.ts'))));
 const sourcePackage=JSON.parse(await readFile(join(root,'package.json'),'utf8'));const lock=JSON.parse(await readFile(join(root,'package-lock.json'),'utf8'));
 const packageFile='file:artifacts/'+pack.filename;
 const manifest={name:'isolated-insight-proof',version:'1.0.0',private:true,type:'module',dependencies:{...sourcePackage.dependencies,'@ixab3r/insight-ghidra':packageFile},devDependencies:sourcePackage.devDependencies};
 await cp(join(root,'vendor'),join(install,'vendor'),{recursive:true});
 lock.name=manifest.name;lock.version=manifest.version;lock.packages['']=manifest;
 for(const [name,item]of Object.entries(lock.packages)){if(item.link||name.startsWith('skills/'))delete lock.packages[name];}
 const cli=JSON.parse(await readFile(join(root,'skills/ghidra-coordinator/package.json'),'utf8'));
 lock.packages['node_modules/@ixab3r/insight-ghidra']={version:cli.version,resolved:packageFile,integrity:'sha512-'+createHash('sha512').update(await readFile(join(artifacts,pack.filename))).digest('base64'),dependencies:cli.dependencies,engines:cli.engines,bin:cli.bin,license:cli.license};
 await writeFile(join(install,'package.json'),JSON.stringify(manifest));await writeFile(join(install,'package-lock.json'),JSON.stringify(lock));
 await exec('npm',['ci','--offline','--ignore-scripts','--no-audit','--no-fund'],{cwd:install,timeout:60000,maxBuffer:262144});
 const fixture=join(install,'proof.mjs');await writeFile(fixture,`import test from'node:test';import assert from'node:assert/strict';import{createCliFixture}from'@eyeauras/cli-factory/testing';import{createInsightCli}from'@ixab3r/insight-ghidra';import{readFile}from'node:fs/promises';test('installed skill and commands without source checkout',async t=>{const f=await createCliFixture(t,{applicationId:'insight-ghidra',profiles:[{name:'default',values:{server:'ghidra://127.0.0.1:14100'}}]});const app=f.createApplication(runtime=>createInsightCli({runtime}));const skill=await f.json(app,['skill']);assert.ok(skill.path.includes('node_modules'));assert.match(await readFile(skill.path,'utf8'),/insight-ghidra 0.1.0/);const replies=await f.rpc(app,[['targets','list'],['findings','list'],['status']]);assert.equal(replies.length,3);assert.equal(replies[0].result.length,0);assert.equal(replies[1].result.length,0);const denied=await f.run(app,['targets','register','--file','missing.json','--json']);assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);});`);
 await exec(process.execPath,['--test',fixture],{cwd:install,timeout:30000,maxBuffer:262144});
 console.log('Packed isolated install: skill/resources, profile/JSON/RPC, permission denial and spaces/Unicode PASS');
}finally{await rm(proof,{recursive:true,force:true});}
