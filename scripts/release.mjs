// Verified package build and staged npm publication. Approval stays an owner action on npm.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,mkdtemp,rm,readdir,copyFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export const packageName='@eyeauras/insight-cli';
const registry='https://registry.npmjs.org/',root=process.cwd(),output=join(root,'output','release');
const uuid=/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
export const integrity=bytes=>'sha512-'+createHash('sha512').update(bytes).digest('base64');
export function requireNewer(version,latest){
  for(const v of [version,latest])assert.match(v,/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/,'Only stable versions are released');
  const a=version.split('.').map(BigInt),b=latest.split('.').map(BigInt),different=a.findIndex((part,i)=>part!==b[i]);
  assert.ok(different>=0&&a[different]>b[different],`Version ${version} is not newer than the published ${latest}`);
}
/** Upload once. The stage identity is durable before anything else can fail. */
export async function stage({manifest,archive,npm,receipt,download}){
  const listed=JSON.parse(await npm(['stage','list',manifest.name,'--json'])||'[]');
  assert.ok(Array.isArray(listed)&&!listed.some(item=>item.version===manifest.version),'This version already has a stage; inspect its receipt before retrying.');
  // A lost or malformed response leaves this receipt: the outcome is unknown, never retried here.
  await receipt('stage-upload-unknown');
  const response=await npm(['stage','publish',archive,'--json','--access','public','--tag','latest','--ignore-scripts']);
  console.log(response);
  const staged=JSON.parse(response)[manifest.name];
  assert.ok(uuid.test(staged?.stageId),'npm returned no stage ID; the upload outcome is unknown.');
  await receipt('staged-unverified',staged.stageId);
  assert.ok(staged.name===manifest.name&&staged.version===manifest.version&&staged.integrity===manifest.integrity,'Stage metadata differs from the tested archive; inspect the saved stage ID.');
  assert.equal(integrity(await download(staged.stageId)),manifest.integrity,'Downloaded stage differs from the tested archive; inspect the saved stage ID.');
  await receipt('awaiting-2fa-approval',staged.stageId);return staged.stageId;
}
export async function verifyRegistry({manifest,view}){
  const [published,tags]=[await view(manifest.version),await view('dist-tags')];
  assert.equal(published?.version,manifest.version,'The approved version is not in the registry');
  assert.equal(published.dist.integrity,manifest.integrity,'Registry bytes differ from this reproducible build');
  assert.equal(tags.latest,manifest.version,'latest points elsewhere; no tag is changed automatically');
}
async function main(mode){
  assert.ok(['verify','dry-run','stage','verify-registry'].includes(mode),'Choose verify, dry-run, stage or verify-registry');
  const token=process.env.NPM_TOKEN??'',revision=process.env.RELEASE_REVISION??'';
  const environment={...process.env,NPM_CONFIG_REGISTRY:registry};delete environment.NPM_TOKEN;
  const run=(command,args,extra={})=>execFileSync(command,args,{cwd:root,env:environment,stdio:'inherit',...extra});
  const git=(...args)=>execFileSync('git',args,{cwd:root,env:environment,encoding:'utf8',timeout:60000,killSignal:'SIGKILL'}).trim();
  await rm(output,{recursive:true,force:true});
  if(mode!=='verify'){
    assert.match(revision,/^[a-f0-9]{40}$/,'RELEASE_REVISION must be the full commit');
    assert.equal(git('rev-parse','HEAD'),revision,'RELEASE_REVISION differs from the checkout');
    assert.equal(git('status','--porcelain'),'','A release requires a clean tree');
  }
  run('npm',['ci','--ignore-scripts','--no-audit','--no-fund']);run('npm',['run','cache:factory']);run('npm',['test']);run('npm',['run','test:package']);
  assert.equal(git('status','--porcelain'),'','The build changed the source tree');
  if(mode==='verify')return;
  await mkdir(output,{recursive:true});run('npm',['run','pack:cli']);
  assert.equal(git('status','--porcelain'),'','Packing changed the source tree');
  const pkg=JSON.parse(await readFile('skills/ghidra-coordinator/package.json','utf8'));assert.equal(pkg.name,packageName);
  const file=`eyeauras-insight-cli-${pkg.version}.tgz`,archive=join(output,file);await copyFile(join(root,'artifacts',file),archive);
  const bytes=await readFile(archive),manifest={schema:1,name:pkg.name,version:pkg.version,commit:revision,file,bytes:bytes.length,
    sha256:createHash('sha256').update(bytes).digest('hex'),integrity:integrity(bytes)};
  await writeFile(join(output,'release-manifest.json'),JSON.stringify(manifest,null,2)+'\n');
  const receipt=(status,stageId)=>writeFile(join(output,'release.json'),JSON.stringify({status,stageId:stageId??null,revision,name:manifest.name,version:manifest.version,integrity:manifest.integrity},null,2)+'\n');
  const temporary=await mkdtemp(join(tmpdir(),'insight-release-'));
  try{
    const userconfig=join(temporary,'npmrc');await writeFile(userconfig,'',{mode:0o600});await writeFile(join(temporary,'global-npmrc'),'');
    const isolated={...environment,NPM_CONFIG_USERCONFIG:userconfig,NPM_CONFIG_GLOBALCONFIG:join(temporary,'global-npmrc')};
    const npm=(args,cwd=root,secret)=>{console.log('npm '+args.slice(0,2).join(' '));return execFileSync('npm',['--registry',registry,...args],{cwd,encoding:'utf8',stdio:['ignore','pipe','inherit'],timeout:300000,killSignal:'SIGKILL',env:secret?{...isolated,NPM_TOKEN:secret}:isolated});};
    const view=async field=>{
      const response=await fetch(field==='dist-tags'?registry+'-/package/@eyeauras%2finsight-cli/dist-tags':registry+'@eyeauras%2finsight-cli/'+field,{signal:AbortSignal.timeout(30000)});
      if(response.status===404)return;assert.equal(response.status,200);return response.json();
    };
    if(mode!=='verify-registry'){requireNewer(manifest.version,(await view('dist-tags')).latest);await smoke(archive,manifest,temporary,npm);}
    if(mode==='dry-run'){npm(['publish',archive,'--dry-run','--access','public','--tag','latest','--ignore-scripts']);await receipt('dry-run-verified');}
    else if(mode==='stage'){
      assert.equal(git('ls-remote','origin','refs/heads/main').split(/\s/)[0],revision,'Staging requires the current remote main');
      assert.ok(token,'Staging requires NPM_TOKEN');await writeFile(userconfig,'//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n',{mode:0o600});
      const id=await stage({manifest,archive,receipt,npm:args=>npm(args,root,token),download:async stageId=>{
        const at=join(temporary,'download');await mkdir(at);npm(['stage','download',stageId],at,token);
        const files=(await readdir(at)).filter(name=>name.endsWith('.tgz'));assert.equal(files.length,1);return readFile(join(at,files[0]));}});
      console.log(`Stage ${id} verified: ${manifest.name}@${manifest.version}. Owner 2FA approval is required on npm.`);
    }else{await verifyRegistry({manifest,view});await smoke(`${manifest.name}@${manifest.version}`,manifest,temporary,npm);await receipt('published-verified');}
  }finally{await rm(temporary,{recursive:true,force:true});}
}
/** Install exactly as a user would and exercise the executable without native Ghidra. */
async function smoke(spec,manifest,temporary,npm){
  const prefix=join(temporary,'global'),home=join(temporary,'home');await mkdir(home,{recursive:true});
  npm(['install','--global','--prefix',prefix,'--cache',join(temporary,'cache'),'--ignore-scripts',spec]);
  const env={PATH:process.env.PATH,HOME:home,XDG_CONFIG_HOME:join(home,'config'),XDG_DATA_HOME:join(home,'data'),XDG_CACHE_HOME:join(home,'cache')};
  const call=(...args)=>execFileSync(join(prefix,'bin/insight-cli'),args,{encoding:'utf8',timeout:60000,env});
  assert.equal(call('--version').trim(),manifest.version);assert.match(call('--help'),/ghidra/);
  const skill=JSON.parse(call('skill','insight-re','--json'));assert.ok((await readFile(skill.path,'utf8')).includes('Insight RE '+manifest.version));
  call('profile','create','release-check','--json');call('--profile','release-check','permissions','grant','Update','--json');
  const input=join(temporary,'smoke.txt');await writeFile(input,'Installed CLI checkpoint\n');
  const saved=JSON.parse(call('--profile','release-check','artifacts','save',input,'--json'));
  assert.equal(saved.state,'saved');assert.equal(await readFile(saved.path,'utf8'),'Installed CLI checkpoint\n');
  assert.equal(JSON.parse(call('--profile','release-check','ghidra','status','--json')).processes.length,0);
  call('--profile','release-check','ipc-server','stop');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main(process.argv[2]);
