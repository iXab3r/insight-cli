import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile,readFile,mkdir,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../src/cli.js';
import {ilspyComponents} from '../src/ilspy.js';
test('ILSpy uses shared lifecycle, immutable targets, literal argv and plain files without Ghidra',async t=>{
 if(process.platform==='win32'){t.skip('Executable fixture uses a POSIX shebang; native Windows acceptance is separate.');return;}
 const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update','Destructive']}]}),app=f.createApplication(runtime=>createInsightCli({runtime,backend:()=>{throw Error('Ghidra must not start');}}));
 assert.equal((await f.json(app,['ilspy','status']) as any).state,'not_ready');const rpc=await f.rpc(app,[['ilspy','status'],['tools','processes']]);assert.equal((rpc[0] as any).result.state,'not_ready');assert.equal((rpc[1] as any).result.items.length,0);
 const input=join(f.root,'managed input ;.dll'),tool=join(f.root,'ilspy fixture'),output=join(f.root,'ordinary code.cs');await writeFile(input,'fixture PE bytes');
 await writeFile(tool,'#!'+process.execPath+'\n'+`if(process.argv.includes('--version'))console.log('ilspycmd: 11.1.0.9782');else console.log(JSON.stringify(process.argv.slice(2)));\n`,{mode:0o755});
 const installed=await f.json(app,['ilspy','install','--executable',tool]) as any;assert.equal(installed.mode,'external');
 const types=await f.json(app,['ilspy','types',input]) as any;assert.match(types.content,/--disable-updatecheck/);assert.ok(JSON.parse(types.content).includes('cisde'));assert.equal(types.truncated,false);
 const decompiled=await f.json(app,['ilspy','decompile','--target',types.target,'--member','M:Example;literal','--output',output]) as any;
 assert.equal(decompiled.target,types.target);assert.match(await readFile(output,'utf8'),/M:Example;literal/);
 const occupied=await f.run(app,['ilspy','decompile',input,'--output',output,'--json']);assert.notEqual(occupied.exitCode,0);assert.match(await readFile(output,'utf8'),/M:Example;literal/);
 const invalid=await f.run(app,['ilspy','decompile',input,'--target',types.target,'--json']);assert.notEqual(invalid.exitCode,0);
 const wrongSession=await f.run(app,['ilspy','types',input,'--session','s_missing','--json']);assert.notEqual(wrongSession.exitCode,0);
 assert.equal((await f.json(app,['ilspy','doctor']) as any).state,'verified');
 const runs=await f.json(app,['tools','processes','--tool','ilspy','--all']) as any;assert.ok(runs.items.length>=4);assert.ok(runs.items.every((r:any)=>r.tool==='ilspy'));
 assert.equal((await f.json(app,['targets','list']) as any).items.length,1);await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'workspace/ghidra-native')));
 assert.equal((await f.json(app,['ilspy','uninstall']) as any).externalInstallationPreserved,true);assert.match(await readFile(tool,'utf8'),/11.1.0.9782/);
 assert.equal((await f.json(app,['targets','list']) as any).items.length,1);assert.equal((await f.json(app,['ilspy','status']) as any).state,'not_ready');
});
test('ILSpy catalog supports only explicitly mirrored runtimes',()=>{
 for(const [platform,arch]of [['darwin','arm64'],['darwin','x64'],['linux','x64'],['win32','x64']] as const){const c=ilspyComponents(platform,arch);assert.equal(Object.keys(c).length,2);assert.match(c.dotnet!.url,/insight-cli\/releases\/download\/tool-dotnet-/);}
 assert.throws(()=>ilspyComponents('linux','arm64'),/No pinned/);
});
