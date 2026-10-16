// Consumer bootstrap only: all test/process orchestration belongs to EyeAuras.Automation.
import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url));
const dependency=join(root,'tests/vendor/EyeAuras.Automation/src/EyeAuras.Automation.Cli/EyeAuras.Automation.Cli.csproj');
try { await readFile(dependency); }
catch { throw Error('Initialize the pinned dependency: git submodule update --init tests/vendor/EyeAuras.Automation'); }
const base=join(root,'.automation/bootstrap');await mkdir(base,{recursive:true});
// Never rebuild a live sentinel host, including during concurrent invocations.
const build=await mkdtemp(join(base,'run-'));
const environment={...process.env,INSIGHT_REPOSITORY_ROOT:root,INSIGHT_NODE:process.execPath,DOTNET_CLI_TELEMETRY_OPTOUT:'1'};
async function run(args){
  const child=spawn('dotnet',args,{cwd:root,env:environment,stdio:'inherit'});
  const forward=()=>child.kill('SIGINT');process.once('SIGINT',forward);process.once('SIGTERM',forward);
  try { return await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve(code??(signal?130:1)));}); }
  finally { process.off('SIGINT',forward);process.off('SIGTERM',forward); }
}
const code=await run(['build','tests/automation/Host/Insight.Automation.Host.csproj','--configuration','Release',
  '--artifacts-path',build,'--disable-build-servers','-p:RestoreLockedMode=true','--nologo']);
if(code!==0)process.exitCode=code;
else process.exitCode=await run([join(build,'bin/Insight.Automation.Host/release/Insight.Automation.Host.dll'),...process.argv.slice(2)]);
