import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,appendFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';

const workspace='skills/ghidra-coordinator';
export const versionFiles=[`${workspace}/package.json`,'package-lock.json',`${workspace}/SKILL.md`,`${workspace}/skills/insight-re/SKILL.md`];
export const increments=['patch','minor','major','none'];
const packageName='@eyeauras/insight-cli';
function parts(version){
  assert.equal(typeof version,'string');
  assert.match(version,/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/,'Expected a stable version');
  return version.split('.').map(BigInt);
}
export function nextVersion(source,latest,bump){
  assert.ok(increments.includes(bump),'Unknown version increment');
  const a=parts(source),b=parts(latest);
  if(bump==='none')return source;
  const different=a.findIndex((part,index)=>part!==b[index]);
  const chosen=different<0||a[different]>b[different]?a:b;
  const result=[...chosen],index={major:0,minor:1,patch:2}[bump];
  result[index]++;
  for(let i=index+1;i<3;i++)result[i]=0n;
  return result.join('.');
}
function validate(record,{sourceCommit,runId,bump,sourceVersion}){
  assert.equal(record.schema,1);assert.equal(record.package,packageName);
  assert.equal(record.sourceCommit,sourceCommit,'Reserved source commit differs');
  assert.equal(record.runId,runId,'Reserved workflow run differs');
  assert.equal(record.bump,bump,'Reserved increment differs');
  assert.equal(record.sourceVersion,sourceVersion,'Reserved source version differs');
  assert.equal(record.version,nextVersion(sourceVersion,record.registryLatest,bump),'Invalid reserved version');
  return record;
}
export async function reserveVersion(root,{sourceCommit,runId,bump,attempt,latest}){
  assert.match(sourceCommit,/^[a-f0-9]{40}$/);assert.match(runId,/^\d+$/);
  const pkg=JSON.parse(await readFile(join(root,versionFiles[0]),'utf8'));
  assert.equal(pkg.name,packageName);parts(pkg.version);
  const expected={sourceCommit,runId,bump,sourceVersion:pkg.version};
  const file=join(root,'version-record/version.json');
  try{return validate(JSON.parse(await readFile(file,'utf8')),expected);}
  catch(error){if(error.code!=='ENOENT')throw error;}
  assert.equal(String(attempt),'1','Re-run requires its original version artifact; start a new workflow if it is missing');
  const registryLatest=await latest();
  const record={schema:1,package:packageName,...expected,registryLatest,version:nextVersion(pkg.version,registryLatest,bump)};
  await mkdir(dirname(file),{recursive:true});
  await writeFile(file,JSON.stringify(record,null,2)+'\n',{flag:'wx'});
  return record;
}
function transformed(originals,record){
  const pkg=JSON.parse(originals[versionFiles[0]]),lock=JSON.parse(originals['package-lock.json']);
  validate(record,{sourceCommit:record.sourceCommit,runId:record.runId,bump:record.bump,sourceVersion:pkg.version});
  assert.equal(pkg.name,packageName);assert.equal(lock.packages[workspace].version,pkg.version);
  pkg.version=record.version;lock.packages[workspace].version=record.version;
  const result={[versionFiles[0]]:JSON.stringify(pkg,null,2)+'\n','package-lock.json':JSON.stringify(lock,null,2)+'\n'};
  for(const [path,title] of [[versionFiles[2],'insight-cli'],[versionFiles[3],'Insight RE']]){
    const heading=`# ${title} ${record.sourceVersion}`;
    assert.ok(originals[path].split('\n').includes(heading),`Missing original skill heading: ${path}`);
    result[path]=originals[path].replace(heading,`# ${title} ${record.version}`);
  }
  return result;
}
export async function applyVersion(root,record){
  const originals=Object.fromEntries(await Promise.all(versionFiles.map(async path=>[path,await readFile(join(root,path),'utf8')])));
  const updated=transformed(originals,record);
  for(const path of versionFiles)await writeFile(join(root,path),updated[path]);
}
export async function verifyVersionChanges(root,record){
  const git=args=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
  assert.equal(git(['rev-parse','HEAD']),record.sourceCommit,'Version was applied to a different source commit');
  const changed=git(['diff','--name-only','HEAD']).split('\n').filter(Boolean);
  assert.ok(changed.every(path=>versionFiles.includes(path)),'Build changed tracked files outside the version inputs');
  const originals=Object.fromEntries(versionFiles.map(path=>[path,execFileSync('git',['show',`HEAD:${path}`],{cwd:root,encoding:'utf8'})]));
  const expected=transformed(originals,record);
  for(const path of versionFiles)assert.equal(await readFile(join(root,path),'utf8'),expected[path],`Unexpected build change: ${path}`);
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const root=process.cwd(),mode=process.argv[2],file=join(root,'version-record/version.json');
  if(mode==='resolve'){
    const record=await reserveVersion(root,{sourceCommit:process.env.GITHUB_SHA,runId:process.env.GITHUB_RUN_ID,
      bump:process.env.RELEASE_BUMP,attempt:process.env.GITHUB_RUN_ATTEMPT,latest:async()=>{
        const response=await fetch('https://registry.npmjs.org/-/package/@eyeauras%2finsight-cli/dist-tags',{signal:AbortSignal.timeout(30000)});
        assert.equal(response.status,200,'Cannot resolve current npm latest');return (await response.json()).latest;
      }});
    if(process.env.GITHUB_STEP_SUMMARY)await appendFile(process.env.GITHUB_STEP_SUMMARY,
      `### Release version ${record.version}\n\nIncrement: ${record.bump}; source: ${record.sourceVersion}; observed npm latest: ${record.registryLatest}. Re-runs reuse this reservation.\n`);
    console.log(JSON.stringify(record));
  }else if(mode==='apply'||mode==='verify'){
    const record=JSON.parse(await readFile(file,'utf8'));
    assert.equal(record.sourceCommit,process.env.GITHUB_SHA);assert.equal(record.runId,process.env.GITHUB_RUN_ID);
    if(mode==='apply')await applyVersion(root,record);else await verifyVersionChanges(root,record);
  }else throw Error('Choose resolve, apply or verify');
}
