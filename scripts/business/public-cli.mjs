// Test-side public process adapter. No product imports, runtime patches or bridge requests.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,readFile,writeFile,appendFile} from 'node:fs/promises';
import {join} from 'node:path';
import {homedir} from 'node:os';
import {performance} from 'node:perf_hooks';
export const exec=promisify(execFile);
export const json=async path=>JSON.parse(await readFile(path,'utf8'));
export const save=async(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n',{mode:0o600});
export class PublicCli {
 constructor(manifest,directory,profile=manifest.profile){this.m=manifest;this.directory=directory;this.profile=profile;this.scopes=[];this.sequence=0;this.calls=[];}
 async call(args,{allowFailure=false,discardReply=false,timeout=600000,global=false}={}){
  await mkdir(this.directory,{recursive:true,mode:0o700});const n=++this.sequence,started=performance.now();let output,code=0;
  try{output=await exec(process.execPath,[this.m.cli,...(global?[]:['--profile',this.profile]),...args,'--json'],{timeout,maxBuffer:8*1024*1024});}
  catch(error){output=error;code=Number(error.code)||1;}
  await writeFile(join(this.directory,n+'.stdout'),output.stdout??'',{mode:0o600});await writeFile(join(this.directory,n+'.stderr'),output.stderr??'',{mode:0o600});
  const timing={n,args,code,started,ended:performance.now(),discardReply};this.calls.push(timing);await appendFile(join(this.directory,'commands.jsonl'),JSON.stringify(timing)+'\n',{mode:0o600});
  if(!allowFailure)assert.equal(code,0,`Public CLI command failed (${args.slice(0,3).join(' ')}); transcript ${n}: ${(output.stderr??'').slice(0,600)}`);
  if(discardReply)return {discarded:true};
  let value;if(output.stdout?.trim()){try{value=JSON.parse(output.stdout);}catch{assert.fail('Public CLI returned malformed JSON; transcript '+n);}}
  return allowFailure?{code,value,stderr:output.stderr}:value;
 }
 async setup(){await this.call(['profile','create',this.profile,'--java',this.m.java,'--ghidra-home',this.m.ghidra],{global:true});await appendFile(join(this.m.directory,'profiles.jsonl'),JSON.stringify(this.profile)+'\n',{mode:0o600});await this.call(['permissions','grant','Update']);}
 async open(input=this.m.inputs[0].path,session='new',extra=[]){const value=await this.call(['ghidra','open',input,'--session',session,...extra]);assert.equal(value.state,'ready');assert.ok(value.session&&value.target);this.scopes.push(value);return value;}
 async fresh(target){const value=await this.call(['ghidra','open','--target',target,'--session','new']);assert.equal(value.state,'ready');this.scopes.push(value);return value;}
 selectors(scope){return ['--session',scope.session,'--target',scope.target];}
 scoped(scope,words,args=[],options){return this.call(['ghidra',...words.split(' '),...this.selectors(scope),...args],options);}
 async comment(scope,address,text,extra=[]){return this.scoped(scope,'comments set',['--address',address,'--kind','plate','--text',text,...extra]);}
 async readComment(scope,address){return (await this.scoped(scope,'comments get',['--address',address,'--kind','plate'])).text;}
 async status(scope){return this.call(['sessions','status',scope.session,'--target',scope.target]);}
 async close(scope){await this.scoped(scope,'close');this.scopes=this.scopes.filter(s=>s.session!==scope.session||s.target!==scope.target);}
 async cleanup(){const failures=[];for(const scope of [...this.scopes].reverse()){try{await this.close(scope);}catch(e){failures.push(e);}}if(failures.length)throw new AggregateError(failures,'Owned public CLI context cleanup failed');}
 workspace(){return join(homedir(),'Library','Application Support','insight-cli',this.profile,'workspace');}
 async history(target){const server=await this.call(['ghidra','server','status']);const files=await this.call(['ghidra','server','repositories','files','--repository',server.repository]);const file=files.files.find(f=>f.name===target+'.bin');assert.ok(file);return this.call(['ghidra','server','history','--repository',server.repository,'--path',file.path]);}
}
