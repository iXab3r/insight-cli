// Test-side storage isolation only. Research still goes through the installed public executable.
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,writeFile,symlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {randomUUID,createHash} from 'node:crypto';
const execute=promisify(execFile);
export const digest=b=>createHash('sha256').update(b).digest('hex');
export async function createPublicFixture(packageRoot,directory){
 assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1','Explicitly select disposable native acceptance');
 packageRoot=resolve(packageRoot);directory=resolve(directory);await mkdir(directory,{recursive:true,mode:0o700});
 const project=join(directory,'project');await mkdir(join(project,'.agents/skills'),{recursive:true,mode:0o700});
 const cli=join(packageRoot,'dist/src/bin.js'),manifest=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));
 assert.equal(manifest.name,'@eyeauras/insight-cli');
 // Honor normal Node resolution: npm may hoist this dependency in an isolated local install.
 let factoryRoot,factory;
 for(const base of createRequire(join(packageRoot,'package.json')).resolve.paths('@eyeauras/cli-factory')??[]){try{const candidate=join(base,'@eyeauras/cli-factory'),manifest=JSON.parse(await readFile(join(candidate,'package.json'),'utf8'));assert.equal(manifest.name,'@eyeauras/cli-factory');factoryRoot=candidate;factory=manifest;break;}catch(error){if(error.code!=='ENOENT')throw error;}}
 assert.ok(factoryRoot&&factory,'Factory package root must resolve');
 // Keep the Unix endpoint below its native path-length limit, even under long runner paths.
 const preload=join(directory,'fixture-environment.mjs'),appdata=await mkdtemp(join(process.platform==='win32'?tmpdir():'/tmp','it-'));
 await writeFile(preload,`import{AppArguments}from ${JSON.stringify(pathToFileURL(join(factoryRoot,factory.main)).href)};const original=AppArguments.CurrentEnvironment;AppArguments.CurrentEnvironment=()=>({...original(),EnvironmentAppData:${JSON.stringify(appdata)},EnvironmentLocalAppData:${JSON.stringify(appdata)}});`,{flag:'wx',mode:0o600});
 const environment={...process.env,NODE_OPTIONS:'--import '+pathToFileURL(preload).href};
 const profile='toolbox-'+randomUUID();let sequence=0;const calls=[];
 const call=async(argv,{allowFailure=false,timeout=process.platform==='win32'?120000:600000}={})=>{
  const id=++sequence,start=performance.now();let result,code=0;
  if(process.env.INSIGHT_NATIVE_PROGRESS==='1')console.log('[public-cli]',id,argv.slice(0,2).join(' '));
  try{result=await execute(process.execPath,[cli,...argv,'--json'],{cwd:project,env:environment,timeout,maxBuffer:16*1024**2});}catch(error){result=error;code=error.code;}
  await writeFile(join(directory,id+'.stdout'),result.stdout??'',{mode:0o600});await writeFile(join(directory,id+'.stderr'),result.stderr??'',{mode:0o600});
  calls.push({id,argv,code,elapsedMs:Math.round(performance.now()-start)});await writeFile(join(directory,'commands.json'),JSON.stringify(calls,null,2)+'\n',{mode:0o600});
  if(code!==0&&process.env.INSIGHT_NATIVE_PROGRESS==='1')console.error('[public-cli failure]',id,(result.stderr??'').slice(0,4096),(result.stdout??'').slice(0,4096));
  if(!allowFailure)assert.equal(code,0,'Public CLI failed; inspect private transcript '+id);
  let value;try{value=JSON.parse(result.stdout);}catch{if(!allowFailure)throw Error('Public CLI did not return JSON; transcript '+id);}
  return allowFailure?{code,value}:value;
 };
 await call(['profile','create',profile]);await call(['profile','set-default',profile]);await call(['permissions','grant','Update']);
 await symlink(join(packageRoot,'skill-bundle'),join(project,'.agents/skills/insight-toolbox'),process.platform==='win32'?'junction':'dir');
 const holder=spawn(process.execPath,[cli,'--json-rpc'],{cwd:project,env:environment,stdio:['pipe','pipe','pipe']});holder.stdout.resume();holder.stderr.resume();holder.stdin.write('{"jsonrpc":"2.0","id":1,"method":"cli.execute","params":{"argv":["profile","show"]}}\n');
 const cleanup=async()=>{try{await call(['ipc-server','stop']);}finally{holder.stdin.end();holder.kill();}};
 return {packageRoot,project,profile,environment,cli,calls,call,cleanup,version:manifest.version,appdata};
}
