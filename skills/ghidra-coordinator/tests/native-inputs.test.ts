import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,cp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {nativeRuntimeFiles,nativeRuntimeFingerprint} from '../src/native-inputs.js';
async function fixture(root:string){
  const suffix=process.platform==='win32'?'.exe':'',java=join(root,'jdk/bin/java'+suffix),home=join(root,'sdk');
  const files:Record<string,string>={['jdk/bin/java'+suffix]:'launcher',['jdk/bin/javac'+suffix]:'compiler',['jdk/bin/keytool'+suffix]:'keytool',
    'jdk/lib/modules':'modules-v1','jdk/lib/server/vm.bin':'vm-v1','jdk/lib/src.zip':'source docs','jdk/conf/security/java.security':'policy','jdk/release':'jdk-build',
    'sdk/Ghidra/application.properties':'application.version=12.1.2','sdk/Ghidra/Processors/Fixture/Module.manifest':'module',
    'sdk/Ghidra/Processors/Fixture/data/languages/fixture.sla':'sleigh-v1','sdk/Ghidra/Processors/Fixture/data/languages/fixture.cspec':'compiler-spec',
    'sdk/Ghidra/Features/Fixture/os/host/decompile':'native-v1','sdk/Ghidra/Features/Fixture/lib/Fixture.jar':'jar-v1',
    'sdk/Ghidra/Features/Fixture/lib/Fixture-src.zip':'source docs','sdk/Ghidra/Features/Fixture/ghidra_scripts/Fixture.java':'vendor script',
    'sdk/Ghidra/Debug/Fixture/pypkg/src/agent.py':'agent-v1','sdk/Ghidra/Debug/Fixture/pypkg/src/__pycache__/agent.pyc':'generated',
    'sdk/Ghidra/Debug/Fixture/pypkg/dist/agent.whl':'wheel-v1'};
  for(const [name,value]of Object.entries(files)){const at=join(root,name);await mkdir(join(at,'..'),{recursive:true});await writeFile(at,value);}
  return {java,home};
}
test('native identity covers SLA/compiler/native/Python/JDK inputs and stays independent of relocation and generated caches',async t=>{
  const root=await mkdtemp(join(tmpdir(),'insight-native-inputs-'));t.after(()=>rm(root,{recursive:true,force:true}));const a=await fixture(join(root,'one'));
  const list=await nativeRuntimeFiles(a.home,a.java),names=list.map(file=>file.name);
  for(const end of ['fixture.sla','fixture.cspec','decompile','agent.py','agent.whl','Module.manifest','java.security','modules','vm.bin'])assert.ok(names.some(name=>name.endsWith('/'+end)),end);
  assert.ok(names.every(name=>!name.includes('__pycache__')&&!name.endsWith('src.zip')));
  const original=await nativeRuntimeFingerprint('12.1.2',list);await cp(join(root,'one'),join(root,'relocated'),{recursive:true});
  const b={home:join(root,'relocated/sdk'),java:join(root,'relocated/jdk/bin',process.platform==='win32'?'java.exe':'java')};
  assert.equal(await nativeRuntimeFingerprint('12.1.2',await nativeRuntimeFiles(b.home,b.java)),original);
  await writeFile(join(a.home,'Ghidra/Debug/Fixture/pypkg/src/__pycache__/agent.pyc'),'another generated cache');assert.equal(await nativeRuntimeFingerprint('12.1.2',await nativeRuntimeFiles(a.home,a.java)),original);
  await writeFile(join(a.home,'Ghidra/Processors/Fixture/data/languages/fixture.sla'),'sleigh-v2');assert.notEqual(await nativeRuntimeFingerprint('12.1.2',await nativeRuntimeFiles(a.home,a.java)),original);
  await writeFile(join(root,'relocated/jdk/lib/modules'),'modules-v2');assert.notEqual(await nativeRuntimeFingerprint('12.1.2',await nativeRuntimeFiles(b.home,b.java)),original);
});
