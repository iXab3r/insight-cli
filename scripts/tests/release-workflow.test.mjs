// Execute the actual workflow publication program with a fake public registry/npm.
// No registry writes, credentials, network or native runtime are needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
const workflow=(await readFile(new URL('../../.github/workflows/release-npm.yml',import.meta.url),'utf8')).replaceAll('\r\n','\n');
const section=workflow.split('- name: Publish once using OIDC and verify registry integrity\n')[1];
assert.ok(section,'Publication step is present');
const body=section.split("<<'NODE'\n")[1].split('\n          NODE')[0];
const program=body.split('\n').map(line=>line.slice(10)).join('\n');

for(const scenario of [
  {name:'identical accepted version is read back without another upload',existing:true,latest:'0.2.0',calls:0,success:true},
  {name:'different bytes at the same version prevent upload',existing:true,different:true,latest:'0.2.0',calls:0,success:false},
  {name:'older version cannot move latest backwards',existing:false,latest:'0.3.0',calls:0,success:false},
  {name:'new version is uploaded exactly once then read back',existing:false,latest:'0.1.0',calls:1,success:true},
  {name:'lost successful response is resolved by readback without retry',existing:false,latest:'0.1.0',exit:1,calls:1,success:true},
])test(scenario.name,{skip:process.platform==='win32'?'Publication runs on Linux; this fixture uses a POSIX executable':false},async()=>{
  const root=await mkdtemp(join(tmpdir(),'insight-release-test-'));
  try{
    await mkdir(join(root,'release'));await mkdir(join(root,'bin'));
    const bytes=Buffer.from('owned release test fixture');
    const manifest={schema:1,name:'@eyeauras/insight-cli',version:'0.2.0',sourceCommit:'a'.repeat(40),
      sha256:createHash('sha256').update(bytes).digest('hex'),
      integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64')};
    await writeFile(join(root,'release/package.tgz'),bytes);
    await writeFile(join(root,'release/release.json'),JSON.stringify(manifest));
    await writeFile(join(root,'fixture.json'),JSON.stringify({scenario,manifest}));
    await writeFile(join(root,'publish.mjs'),program);
    const npm=join(root,'bin','npm');
    const stub="const args=process.argv.slice(2);if(!args[1]?.startsWith('./'))throw Error('npm archive argument must be an explicit local path, not a GitHub shorthand');require('node:fs').writeFileSync('npm-called.json',JSON.stringify(args));process.exit(Number(process.env.FIXTURE_NPM_EXIT)||0);";
    await writeFile(npm,'#!/usr/bin/env node\n'+stub,{mode:0o755});
    await writeFile(join(root,'registry.mjs'),`
      import {readFileSync,existsSync} from 'node:fs';
      const {scenario,manifest}=JSON.parse(readFileSync('fixture.json'));
      globalThis.fetch=async url=>{
        const uploaded=existsSync('npm-called.json');
        if(url.endsWith('/dist-tags'))return new Response(JSON.stringify({latest:uploaded?'0.2.0':scenario.latest}));
        if(!scenario.existing&&!uploaded)return new Response('{}',{status:404});
        return new Response(JSON.stringify({dist:{integrity:scenario.different?'wrong':manifest.integrity,tarball:'https://registry.npmjs.org/fixture.tgz'}}));
      };
    `);
    let succeeded=true,output='';
    try{await exec(process.execPath,['--import',join(root,'registry.mjs'),join(root,'publish.mjs')],{
      cwd:root,timeout:15000,env:{...process.env,PATH:join(root,'bin')+':'+process.env.PATH,
        GITHUB_STEP_SUMMARY:join(root,'summary.md'),FIXTURE_NPM_EXIT:String(scenario.exit??0)},
    });}catch(error){succeeded=false;output=error.stderr??String(error);}
    assert.equal(succeeded,scenario.success,output);
    let args;try{args=JSON.parse(await readFile(join(root,'npm-called.json'),'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;}
    assert.equal(args?1:0,scenario.calls);
    if(args)assert.deepEqual(args,['publish','./release/package.tgz','--access','public','--tag','latest','--ignore-scripts','--provenance']);
    if(scenario.success){
      const receipt=JSON.parse(await readFile(join(root,'release/registry.json'),'utf8'));
      assert.equal(receipt.integrity,manifest.integrity);assert.equal(receipt.latest,'0.2.0');
    }
  }finally{await rm(root,{recursive:true,force:true});}
});
