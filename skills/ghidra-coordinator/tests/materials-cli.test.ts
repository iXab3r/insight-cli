import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {join} from 'node:path';
import {mkdir,writeFile,readFile,stat} from 'node:fs/promises';
import {createInsightCli} from '../src/cli.js';
import {packageVersion} from '../src/package-version.js';

test('packaged entry and RE skills are discoverable without profile, authentication or Ghidra state',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli'});
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:()=>{throw Error('Must not start Ghidra');}}));
  const original=await f.json(app,['skill']) as {name:string;path:string;version:string;skills:string[]};
  assert.equal(original.name,'insight-cli');assert.equal(original.version,packageVersion);
  assert.deepEqual(original.skills,['insight-cli','insight-re','insight-ghidra','insight-ilspy','insight-artifacts','insight-sevenzip','insight-llvm','insight-dotnet-dump','insight-dotnet-stack','insight-dotnet-trace','insight-die','insight-lldb','insight-frida','insight-windbg','insight-strace','insight-procmon','insight-dnspy','insight-tshark','insight-mitmproxy','insight-managed-metadata','insight-managed-heap']);
  const research=await f.json(app,['skill','insight-re']) as {name:string;path:string;version:string};
  assert.equal(research.name,'insight-re');assert.equal(research.version,original.version);
  assert.match(await readFile(research.path,'utf8'),/name: insight-re/);
  assert.notEqual(research.path,original.path);
  const unknown=await f.run(app,['skill','missing','--json']);assert.notEqual(unknown.exitCode,0);
  await assert.rejects(stat(f.appArguments.AppDataDirectory));
});

test('public artifact save is permission gated and works through CLI and RPC without native configuration',async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default'},{name:'other',permissions:['ReadOnly','Update']}]});
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:()=>{throw Error('Must not start Ghidra');}}));
  const denied=await f.run(app,['artifacts','save','missing-file','--json']);
  assert.notEqual(denied.exitCode,0);assert.match(denied.stderr,/permission/i);
  await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'materials')));
  await app.execute(['permissions','grant','Update']);
  const source=join(f.root,'report Ω.md');await writeFile(source,'Observed result\n');
  const saved=await f.json(app,['artifacts','save',source]) as {state:string;path:string;kind:string;files:number;bytes:number;sha256:string};
  assert.equal(saved.state,'saved');assert.equal(saved.kind,'file');assert.equal(saved.files,1);assert.equal(saved.bytes,16);
  assert.match(saved.sha256,/^[a-f0-9]{64}$/);assert.ok(saved.path.startsWith(join(f.appArguments.AppDataDirectory,'materials')));
  await writeFile(source,'Changed source');assert.equal(await readFile(saved.path,'utf8'),'Observed result\n');
  const folder=join(f.root,'research');await mkdir(folder);await writeFile(join(folder,'empty.txt'),'');await writeFile(join(folder,'notes.md'),'Notes');
  const response=await f.rpc(app,[['artifacts','save',folder,'--profile','other']]) as {result:{path:string;files:number;kind:string}}[];
  const other=response[0]!.result;assert.equal(other.kind,'directory');assert.equal(other.files,2);
  assert.ok(other.path.startsWith(join(f.appArguments.WithProfile('other').AppDataDirectory,'materials')));
  assert.equal(await readFile(join(other.path,'notes.md'),'utf8'),'Notes');
  await assert.rejects(stat(join(f.appArguments.AppDataDirectory,'workspace')));
  const deletion=await f.run(app,['profile','delete','default','--json']);assert.notEqual(deletion.exitCode,0);
  assert.equal(await readFile(saved.path,'utf8'),'Observed result\n');
});
