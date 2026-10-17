// Test-side storage isolation only. Research still goes through the installed public executable.
import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile,symlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomUUID,createHash} from 'node:crypto';
const execute=promisify(execFile);
export const digest=b=>createHash('sha256').update(b).digest('hex');
export async function createPublicFixture(packageRoot,directory){
 assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1','Explicitly select disposable native acceptance');
 packageRoot=resolve(packageRoot);directory=resolve(directory);await mkdir(directory,{recursive:true,mode:0o700});
 const project=join(directory,'project');await mkdir(join(project,'.agents/skills'),{recursive:true,mode:0o700});
 const cli=join(packageRoot,'dist/src/bin.js'),manifest=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));
 assert.equal(manifest.name,'@eyeauras/insight-cli');
 const factoryRoot=join(packageRoot,'node_modules/@eyeauras/cli-factory'),factory=JSON.parse(await readFile(join(factoryRoot,'package.json'),'utf8'));
 const preload=join(directory,'fixture-environment.mjs'),appdata=join(directory,'appdata');
 await writeFile(preload,`import{AppArguments}from ${JSON.stringify(pathToFileURL(join(factoryRoot,factory.main)).href)};const original=AppArguments.CurrentEnvironment;AppArguments.CurrentEnvironment=()=>({...original(),EnvironmentAppData:${JSON.stringify(appdata)},EnvironmentLocalAppData:${JSON.stringify(appdata)}});`,{flag:'wx',mode:0o600});
 const environment={...process.env,NODE_OPTIONS:'--import '+preload};
 const profile='toolbox-'+randomUUID();let sequence=0;const calls=[];
 const call=async(argv,{allowFailure=false,timeout=600000}={})=>{
  const id=++sequence,start=performance.now();let result,code=0;
  try{result=await execute(process.execPath,[cli,...argv,'--json'],{cwd:project,env:environment,timeout,maxBuffer:16*1024**2});}catch(error){result=error;code=error.code;}
  await writeFile(join(directory,id+'.stdout'),result.stdout??'',{mode:0o600});await writeFile(join(directory,id+'.stderr'),result.stderr??'',{mode:0o600});
  calls.push({id,argv,code,elapsedMs:Math.round(performance.now()-start)});await writeFile(join(directory,'commands.json'),JSON.stringify(calls,null,2)+'\n',{mode:0o600});
  if(!allowFailure)assert.equal(code,0,'Public CLI failed; inspect private transcript '+id);
  let value;try{value=JSON.parse(result.stdout);}catch{if(!allowFailure)throw Error('Public CLI did not return JSON; transcript '+id);}
  return allowFailure?{code,value}:value;
 };
 await call(['profile','create',profile]);await call(['profile','set-default',profile]);await call(['permissions','grant','Update']);
 await symlink(join(packageRoot,'skill-bundle'),join(project,'.agents/skills/insight-toolbox'),'dir');
 const holder=spawn(process.execPath,[cli,'--json-rpc'],{cwd:project,env:environment,stdio:['pipe','pipe','pipe']});holder.stdout.resume();holder.stderr.resume();holder.stdin.write('{"jsonrpc":"2.0","id":1,"method":"cli.execute","params":{"argv":["profile","show"]}}\n');
 const cleanup=async()=>{try{await call(['ipc-server','stop']);}finally{holder.stdin.end();holder.kill();}};
 return {packageRoot,project,profile,environment,cli,calls,call,cleanup,version:manifest.version,appdata};
}
