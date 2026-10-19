import assert from 'node:assert/strict';
import {resultHash} from './equivalence.mjs';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {performance} from 'node:perf_hooks';
import {appendFile,writeFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {loadavg} from 'node:os';
import {createInterface} from 'node:readline';
const exec=promisify(execFile);
export const hash=x=>createHash('sha256').update(typeof x==='string'||Buffer.isBuffer(x)?x:JSON.stringify(x)).digest('hex');
export class Recorder {
 constructor(directory,base){this.directory=directory;this.base=base;this.sequence=0;this.rows=[];}
 async measure(stage,action,extra={}){const start=process.hrtime.bigint(),n=++this.sequence;let result,error,ended;const done=()=>{ended??=process.hrtime.bigint();};
  try{result=await action(done,n);return result;}catch(e){error=e;throw e;}
  finally{const row={...this.base,n,stage,...extra,startNs:start.toString(),ms:Number((ended??process.hrtime.bigint())-start)/1e6,observerMs:ended?Number(process.hrtime.bigint()-ended)/1e6:0,loadAtEnd:loadavg(),ok:!error,...(error?{failure:String(error.code??error.name??'failure'),censored:Boolean(extra.censored||error.killed||/deadline|timeout/i.test(error.message??''))}:{})};
   this.rows.push(row);await appendFile(join(this.directory,'requests.jsonl'),JSON.stringify(row)+'\n',{mode:0o600});
   if(error)await writeFile(join(this.directory,n+'.failure.txt'),String(error.stack??error)+'\n'+String(error.stderr??''),{mode:0o600});
  }
 }
}
export class PublicCli {
 constructor(cli,profile,recorder,environment={}){this.cli=cli;this.profile=profile;this.r=recorder;this.environment=environment;this.scope=undefined;}
 async call(argv,{global=false,expectedFailure=false,stage=argv.slice(0,3).join('.'),validate,...extra}={}){
  const metadata={route:'cli',...extra};return this.r.measure(stage,async (done,n)=>{let output,code=0;
   try{const invocation=exec(process.execPath,[this.cli,...global?[]:['--profile',this.profile],...argv,'--json'],{cwd:process.cwd(),env:{...process.env,...this.environment},timeout:1200000,maxBuffer:8*1024**2});metadata.pid=invocation.child?.pid;output=await invocation;}
   catch(e){output=e;code=e.code;}done();metadata.exitStatus=code;metadata.censored=Boolean(output.killed||output.signal);
   await writeFile(join(this.r.directory,n+'.stdout'),output.stdout??'',{mode:0o600});await writeFile(join(this.r.directory,n+'.stderr'),output.stderr??'',{mode:0o600});
   assert.equal(code===0,!expectedFailure,`Public CLI failed: ${stage}; transcript ${this.r.sequence}`);
   let value;try{value=JSON.parse(output.stdout);}catch{if(!expectedFailure)throw Error('Malformed public JSON');value={};}
   if(expectedFailure){value.failure=JSON.parse(output.stderr.trim().split('\n').at(-1)).error;}
   validate?.(value);metadata.resultHash=resultHash(stage,value);return value;
  },metadata);
 }
 selectors(){return ['--session',this.scope.session,'--target',this.scope.target];}
 scoped(argv,extra){return this.call(['ghidra',...argv,...this.selectors()],extra);}
 async setup(java,ghidra){await this.call(['profile','create',this.profile,'--java',java,'--ghidra-home',ghidra],{global:true,stage:'setup.profile'});await this.call(['permissions','grant','Update'],{stage:'setup.permission'});}
 async rpc(){
  const child=spawn(process.execPath,[this.cli,'--json-rpc'],{env:{...process.env,...this.environment},cwd:process.cwd(),stdio:['pipe','pipe','pipe']});let n=0;const pending=new Map();let errors='';child.stderr.on('data',b=>{errors=(errors+b).slice(-65536);});
  createInterface({input:child.stdout}).on('line',line=>{const value=JSON.parse(line),entry=pending.get(value.id);if(entry){pending.delete(value.id);entry(value);}});
  child.once('exit',()=>{for(const entry of pending.values())entry({error:{message:'RPC process exited: '+errors}});pending.clear();});
  const execute=(argv,extra={})=>{const metadata={route:'rpc',...extra};return this.r.measure(extra.stage??'rpc',async done=>{const id=++n;const reply=await Promise.race([new Promise(resolve=>{pending.set(id,resolve);child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method:'cli.execute',params:{argv:['--profile',this.profile,...argv]}})+'\n');}),new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('RPC deadline')),1200000);timer.unref();})]);
   done();if(extra.expectedFailure){assert.ok(reply.error);const value={...reply.error.data?.result,failure:reply.error.data};extra.validate?.(value);metadata.resultHash=resultHash(extra.stage??'rpc',value);return value;}assert.ok(!reply.error,'Persistent RPC command failed: '+JSON.stringify(reply.error));extra.validate?.(reply.result);metadata.resultHash=resultHash(extra.stage??'rpc',reply.result);return reply.result;},metadata);};
  return {execute,call:(argv,extra)=>execute(['ghidra',...argv,...this.selectors()],extra),close:async()=>{child.stdin.end();await new Promise(resolve=>child.once('close',resolve));assert.equal(child.exitCode,0);}};
 }
 async cleanup(){if(this.scope){await this.scoped(['close'],{stage:'cleanup.close'});this.scope=undefined;}await this.call(['ghidra','server','stop'],{stage:'cleanup.server'});}
}
