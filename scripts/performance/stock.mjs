import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdir,open,readFile,readdir,writeFile} from 'node:fs/promises';
import {join,delimiter} from 'node:path';
import {createServer} from 'node:net';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {resultHash} from './equivalence.mjs';
import {Recorder,hash} from './public.mjs';
import {archivePayloads} from './storage.mjs';
async function port(){const s=createServer();await new Promise((ok,bad)=>{s.once('error',bad);s.listen(0,'127.0.0.1',ok);});const p=s.address().port;await new Promise(ok=>s.close(ok));return p;}
async function jars(path){const out=[];for(const e of await readdir(path,{withFileTypes:true})){if(e.isDirectory()&&e.name!=='data')out.push(...await jars(join(path,e.name)));else if(e.isFile()&&e.name.endsWith('.jar'))out.push(join(path,e.name));}return out;}
export class Stock {
 constructor(o,root,r){this.o=o;this.root=root;this.r=r;this.program='/program';}
 async start(){
  await mkdir(this.root,{recursive:true});const p=await port(),token=randomBytes(32).toString('hex');this.endpoint=`http://127.0.0.1:${p}`;this.headers={Authorization:'Bearer '+token};
  const classpath=[this.o.jar,...(await jars(join(this.o.ghidra,'Ghidra'))).filter(x=>!x.includes('GhidraMCP'))].join(delimiter),log=await open(join(this.root,'jvm.log'),'a',0o600);
  this.child=spawn(this.o.java,['-Djava.awt.headless=true','-Dghidra.home='+this.o.ghidra,'-Duser.home='+this.root,'-Djava.io.tmpdir='+this.root,'-Dapplication.cachedir='+join(this.root,'cache'),'-Dapplication.settingsdir='+join(this.root,'settings'),'-Dapplication.tempdir='+this.root,'-cp',classpath,'com.xebyte.headless.GhidraMCPHeadlessServer','--bind','127.0.0.1','--port',String(p)],{cwd:process.cwd(),env:{...process.env,GHIDRA_MCP_FILE_ROOT:this.o.fixtureRoot,GHIDRA_MCP_SHARED_PROJECT_DIR:this.root,GHIDRA_MCP_ALLOW_SCRIPTS:'1',GHIDRA_MCP_AUTH_TOKEN:token},stdio:['ignore',log.fd,log.fd]});await log.close();
  for(let i=0;;i++){assert.ok(i<1800,'Stock readiness timeout');assert.equal(this.child.exitCode,null);try{const info=await(await fetch(this.endpoint+'/mcp/instance_info',{headers:this.headers})).json();assert.equal(info.pid,this.child.pid);break;}catch{await delay(100);}}
  this.transport=new StdioClientTransport({command:this.o.python,args:['-m','bridge_mcp_ghidra','--no-lazy'],cwd:process.cwd(),env:{...process.env,PYTHONPATH:join(this.o.bridge,'python'),GHIDRA_MCP_URL:this.endpoint,GHIDRA_MCP_AUTH_TOKEN:token,GHIDRA_MCP_DISABLE_DISCOVERY:'1'},stderr:'pipe'});
  this.client=new Client({name:'insight-native-performance',version:'1.0.0'},{capabilities:{}});await this.client.connect(this.transport);
  this.transport.stderr?.on('data',()=>{});
  let all=await this.client.listTools();
  const selected=await this.client.callTool({name:'connect_instance',arguments:{project:'perf66-owned-'+this.child.pid}},undefined,{timeout:30000});
  const connection=JSON.parse(selected.content.find(x=>x.type==='text').text);assert.equal(connection.connected,true);assert.equal(connection.url,this.endpoint,'Stock MCP must bind only the explicitly owned TCP endpoint');
  all=await this.client.listTools();this.tools=new Map(all.tools.map(x=>[x.name,x]));await writeFile(join(this.root,'tools.json'),JSON.stringify(all.tools.map(x=>x.name)));
 }
 async call(name,args={},extra={}){const metadata={route:'stock',...extra};return this.r.measure(extra.stage??name,async (done,n)=>{
  assert.ok(this.tools.has(name),'Stock tool absent: '+name);const response=await this.client.callTool({name,arguments:args},undefined,{timeout:1200000});
  const text=response.content.filter(x=>x.type==='text').map(x=>x.text).join('\n');let value;try{value=JSON.parse(text);}catch{value={text};}
  if(extra.withComments){const comments=await this.client.callTool({name:'get_comment',arguments:{program:this.program,address:args.functions}},undefined,{timeout:1200000});assert.ok(!comments.isError);value.comments=JSON.parse(comments.content.find(c=>c.type==='text').text);metadata.componentCalls=2;}done();
  const failed=response.isError||value.error||value.success===false;
  if(extra.expectedFailure)assert.ok(failed||/not found|no function/i.test(text));else assert.ok(!failed,`Stock tool failed ${name}: ${text.slice(0,300)}`);
  await writeFile(join(this.r.directory,n+'.stock.json'),JSON.stringify(value,null,2),{mode:0o600});extra.validate?.(value);metadata.resultHash=resultHash(extra.stage??name,name==='get_xrefs_to'?{...value,requestedAddress:args.address}:value);return value;
 },metadata);}
 scoped(name,p,extra){return this.call(name,{program:this.program,...p},extra);}
 async close(){await this.client?.close();await this.transport?.close();if(this.child&&this.child.exitCode===null){const exited=new Promise(ok=>this.child.once('exit',ok));this.child.kill('SIGTERM');await Promise.race([exited,delay(10000)]);if(this.child.exitCode===null){this.child.kill('SIGKILL');await exited;}}}
}
export async function runStock(o,manifest){
 for(const fixture of manifest.fixtures){
  assert.equal(hash(await readFile(fixture.prepared)),fixture.snapshotSha256);
  for(let cold=0;cold<o.cold;cold++){
   const directory=join(o.root,`${fixture.name}-${fixture.analyzed?'analysis':'no-analysis'}-${cold}`);await mkdir(directory,{recursive:true});
   const r=new Recorder(directory,{label:o.label,fixture:fixture.name,analysis:fixture.analyzed,coldTrial:cold,jarSha256:hash(await readFile(o.jar))}),s=new Stock(o,join(directory,'jvm'),r);
   try{
    await r.measure('cold.server',()=>s.start(),{route:'stock'});
    await s.call('create_project',{name:'owned',parentDir:s.root},{stage:'setup.project'});
    await s.call('import_file',{file_path:fixture.path,auto_analyze:fixture.analyzed},{stage:'cold.import'});
    const file=await s.call('list_open_programs',{}, {stage:'setup.open-programs'});const programs=file.programs;assert.equal(programs.length,1);const imported=programs[0].path??programs[0].name??'owned.exe';
    await s.call('close_program',{name:imported,save:false},{stage:'setup.close-import'});
    await s.call('import_program',{gzf_path:fixture.prepared,target_folder:'/',target_name:'program',overwrite:false},{stage:'prepared.import'});
    await s.call('open_program',{path:s.program},{stage:'prepared.open'});
    const information=await s.scoped('get_program_options',{group:'Program Information'},{stage:'prepared.identity'});assert.equal(information.options.find(p=>p.name==='Executable SHA256').value,fixture.sha256);
    const operations=[
     {name:'metadata',tool:'get_metadata',args:{},check:v=>{assert.equal(v.language,'x86:LE:64:default');assert.equal(v.compiler,'windows');assert.ok(v.function_count>=3);}},
     {name:'decompile',withComments:true,tool:'get_functions',args:{functions:fixture.exports.owned_add,fields:'entry_point,signature,decompiled_code',include_call_context:false},check:v=>assert.match(JSON.stringify(v),/return/)},
     {name:'hash-decompile',withComments:true,tool:'get_functions',args:{functions:fixture.exports.owned_hash,fields:'entry_point,signature,decompiled_code',include_call_context:false},check:v=>assert.match(JSON.stringify(v),/return/)},
     {name:'bulk',tool:'get_functions',args:{functions:fixture.exports.owned_add+','+fixture.exports.owned_hash,fields:'entry_point,signature,decompiled_code',include_call_context:false},check:v=>assert.equal(Object.keys(v.functions).length,2)},
     {name:'memory',tool:'read_memory',args:{address:fixture.exports.owned_data,length:16},check:v=>assert.match(JSON.stringify(v).toLowerCase(),/01.{0,6}02.{0,6}03.{0,6}04/)},
     {name:'large-output',tool:'read_memory',args:{address:fixture.exports.owned_data,length:fixture.name==='large'?65536:256},check:v=>assert.ok(JSON.stringify(v).length>256)},
     {name:'paging',tool:'list_program_items',args:{kind:'methods',limit:2,offset:1},check:v=>{assert.equal(v.offset,1);assert.equal(v.items.length,2);}},
     {name:'strings',tool:'list_strings',args:{filter:'owned',limit:5,offset:0},check:v=>assert.ok(Array.isArray(v.strings))},
     {name:'xrefs',tool:'get_xrefs_to',args:{address:fixture.exports.owned_string,limit:5,offset:0},check:v=>assert.ok(Array.isArray(v.references))},
     {name:'missing',tool:'get_functions',args:{functions:'0',fields:'entry_point,signature,decompiled_code',include_call_context:false},check:v=>assert.match(JSON.stringify(v),/not found|no function/i)}
    ];
    for(const c of operations)await s.scoped(c.tool,c.args,{stage:'first.'+c.name,validate:c.check,withComments:c.withComments});
    for(let i=-(cold===0?o.warmups:0);i<(cold===0?o.warm:0);i++)for(let j=0;j<operations.length;j++){const c=operations[(j+Math.max(i,0))%operations.length],value=await s.scoped(c.tool,c.args,{stage:'read.'+c.name,sample:i,warmup:i<0,validate:c.check,withComments:c.withComments});c.check(value);}
    for(let sample=-(cold===0?o.warmups:0);sample<(cold===0?o.warm:1);sample++){
     const meta={sample,warmup:sample<0},text='Owned performance annotation '+sample;
     await s.scoped('run_script_inline',{code:'import ghidra.app.script.GhidraScript; public class OwnedReadScript extends GhidraScript {public void run(){println("owned-read");}}'},{stage:'persistence.read-script',...meta});
     await s.scoped('set_comment',{address:fixture.exports.owned_add,type:'plate',comment:text},{stage:'persistence.edit',...meta});
     await s.scoped('save_program',{}, {stage:'persistence.save',...meta});
     await s.call('close_program',{name:s.program,save:false},{stage:'persistence.close',...meta});
     await s.call('open_program',{path:s.program},{stage:'persistence.reopen',...meta});
     assert.equal((await s.scoped('get_comment',{address:fixture.exports.owned_add},{stage:'persistence.readback',...meta})).plate,text);
    }
   }finally{await s.close();assert.equal(hash(await readFile(fixture.prepared)),fixture.snapshotSha256);assert.equal(hash(await readFile(fixture.path)),fixture.sha256);await writeFile(join(directory,'cleanup.json'),JSON.stringify({nativeExited:!s.child||s.child.exitCode!==null||s.child.signalCode!==null,bridgeClosed:true}));}
   await archivePayloads(s.root,join(directory,'closed-fixtures'),{roots:['owned.rep']});
  }
 }
}
