import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile,copyFile} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {homedir,loadavg,cpus,totalmem,release} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {PublicCli,Recorder,hash} from './public.mjs';
export const setupScript=`import ghidra.app.script.GhidraScript; public class OwnedPerformanceSetup extends GhidraScript {public void run() throws Exception {for(String p:new String[]{"140001000","140001010","140001050"}){var a=toAddr(p);if(getFunctionAt(a)==null){disassemble(a);createFunction(a,null);}}}}`;
export function cases(f){return [
 {name:'metadata',argv:['program','metadata'],check:v=>{assert.equal(v.value.language,'x86:LE:64:default');assert.equal(v.value.compiler,'windows');assert.ok(v.value.function_count>=3);}},
 {name:'decompile',argv:['functions','decompile','--address',f.exports.owned_add],check:v=>{assert.match(v.code,/return/);assert.match(v.code,/17|0x11/);assert.equal(v.truncated,false);}},
 {name:'hash-decompile',argv:['functions','decompile','--address',f.exports.owned_hash],check:v=>{assert.match(v.code,/return/);assert.equal(v.truncated,false);}},
 {name:'bulk',argv:['functions','inspect','--functions',f.exports.owned_add+','+f.exports.owned_hash,'--fields','entry_point,signature,decompiled_code','--include-call-context','false'],check:v=>{assert.equal(Object.keys(v.value.functions).length,2);for(const fn of Object.values(v.value.functions)){assert.ok(fn.decompiled_code);assert.equal(fn.status,'success');assert.equal(fn.text.truncated,false)};}},
 {name:'memory',argv:['memory','read','--address',f.exports.owned_data,'--length','16'],check:v=>{assert.match(JSON.stringify(v).toLowerCase(),/01.{0,6}02.{0,6}03.{0,6}04/);}},
 {name:'large-output',argv:['memory','read','--address',f.exports.owned_data,'--length',f.name==='large'?'65536':'256'],check:v=>{assert.ok(JSON.stringify(v).length>256);}},
 {name:'paging',argv:['listing','list-program-items','--kind','methods','--limit','2','--offset','1'],check:v=>{assert.equal(v.value.offset,1);assert.equal(v.value.items.length,2);}},
 {name:'strings',argv:['strings','search','--contains','owned','--limit','5'],check:v=>{assert.ok(Array.isArray(v.items));if(f.analyzed)assert.ok(v.items.length>0);}},
 {name:'xrefs',argv:['xrefs','to','--address',f.exports.owned_string,'--limit','5'],check:v=>{assert.ok(Array.isArray(v.items));if(f.analyzed)assert.ok(v.items.length>0);}},
 {name:'missing',argv:['functions','decompile','--address','0'],expectedFailure:true,check:v=>assert.equal(v.reason,'function_not_found')},
 {name:'undefined',argv:['functions','decode','--address','140001100','--max-bytes','16','--max-instructions','4'],check:v=>assert.equal(v.value.read_only.modification_unchanged,true)}
 ];}
export async function runInsight(o,fixtures){
 const report={schema:1,label:o.label,source:o.source,cli:o.cli,warm:o.warm,cold:o.cold,warmups:o.warmups,seed:66067,cache:'OS caches are not flushed; each cold native trial uses a fresh profile/server/JVM/DB',host:{node:process.version,cpu:cpus()[0].model,memory:totalmem(),os:release()},fixtures:[]};
 for(const f of fixtures)for(const analyzed of (o.analysis==='both'?[false,true]:[o.analysis==='full'])){
  for(let cold=0;cold<o.cold;cold++){
   const directory=join(o.root,`${f.name}-${analyzed?'analysis':'no-analysis'}-${cold}`);await mkdir(directory,{recursive:true});
   const profile=`perf66-${o.label}-${f.name}-${analyzed?'a':'n'}-${o.runId}-${cold}`;
   const rec=new Recorder(directory,{label:o.label,fixture:f.name,analysis:analyzed,coldTrial:cold,load:loadavg()}),client=new PublicCli(o.cli,profile,rec),retained=[];let rpc;
   try{
    await client.setup(o.java,o.ghidra);
    client.scope=await client.call(['ghidra','open',f.path,'--session','new','--language','x86:LE:64:default','--compiler-spec','windows',...analyzed?[]:['--no-analysis']],{stage:'cold.open'});assert.equal(client.scope.state,'ready');
    await client.scoped(['scripts','run-inline','--code',setupScript,'--request-id','prepare-functions'],{stage:'prepare.functions'});
    await client.scoped(['merge','--request-id','prepare-merge'],{stage:'prepare.merge'});
    const dbPath=join(homedir(),'Library/Application Support/insight-cli',profile,'workspace/workspace.sqlite');
    const db=new DatabaseSync(dbPath,{readOnly:true});let context;try{context=JSON.parse(db.prepare('SELECT data FROM contexts WHERE session=? AND target=?').get(client.scope.session,client.scope.target).data);}finally{db.close();}
    assert.equal(context.scalars.length+context.complexChanges.length,0);
    const snapshot=join(dirname(dbPath),'artifacts',context.workingSnapshot.sha256+'.gzf'),bytes=await readFile(snapshot);assert.equal(hash(bytes),context.workingSnapshot.sha256);
    if(cold===0){const prepared=join(o.root,`${f.name}-${analyzed?'analysis':'no-analysis'}.gzf`);await copyFile(snapshot,prepared);report.fixtures.push({...f,analyzed,prepared,snapshotSha256:hash(bytes),profile});}
    const cliScope=client.scope,rpcScope=await client.call(['ghidra','open','--target',cliScope.target,'--session','new'],{stage:'prepared.rpc-context'});retained.push(rpcScope);
    const routes={cli:cliScope,rpc:rpcScope};client.scope=rpcScope;
    const information=await client.scoped(['program','get-program-options','--group','Program Information'],{stage:'prepared.identity'});assert.equal(information.value.options.find(p=>p.name==='Executable SHA256').value,f.sha256);
    rpc=await rec.measure('cold.rpc-process',async()=>{const transport=await client.rpc();await transport.call(['program','metadata'],{stage:'first.metadata',validate:v=>assert.match(JSON.stringify(v),new RegExp(f.sha256))});return transport;},{route:'rpc'});const operations=cases({...f,analyzed});
    for(const c of operations)for(const route of ['cli','rpc']){if(c.name==='metadata'&&route==='rpc')continue;client.scope=routes[route];const meta={stage:'first.'+c.name,validate:c.check,expectedFailure:c.expectedFailure};await (route==='cli'?client.scoped(c.argv,meta):rpc.call(c.argv,meta));}
    // Fixed rotation alternates route order each round. No retries/replacement samples.
    const samples=cold===0?o.warm:0;
    for(let i=-(cold===0?o.warmups:0);i<samples;i++)for(let j=0;j<operations.length;j++){
     const c=operations[(j+Math.max(0,i))%operations.length];for(const route of i%2?['rpc','cli']:['cli','rpc']){
      client.scope=routes[route];const value=await (route==='cli'?client.scoped(c.argv,{stage:'read.'+c.name,sample:i,warmup:i<0,validate:c.check,expectedFailure:c.expectedFailure}):rpc.call(c.argv,{stage:'read.'+c.name,sample:i,warmup:i<0,validate:c.check,expectedFailure:c.expectedFailure}));c.check(value);
     }
    }
    await rpc.close();rpc=undefined;client.scope=rpcScope;await client.scoped(['close'],{stage:'prepared.rpc-close'});retained.pop();client.scope=cliScope;
    await client.scoped(['comments','set','--address',f.exports.owned_add,'--kind','plate','--text','Owned performance annotation','--request-id','small-edit'],{stage:'persistence.edit'});
    const merged=await client.scoped(['merge','--request-id','publish-edit'],{stage:'persistence.merge'});assert.equal(merged.state,'merged');
    const original=client.scope;retained.push(original);
    client.scope=await client.call(['ghidra','open','--target',original.target,'--session','new'],{stage:'persistence.independent-open'});
    const readback=await client.scoped(['comments','get','--address',f.exports.owned_add,'--kind','plate'],{stage:'persistence.readback'});assert.equal(readback.text,'Owned performance annotation');
    await client.scoped(['close'],{stage:'persistence.independent-close'});client.scope=original;retained.pop();
    await client.scoped(['refresh','--request-id','refresh-check'],{stage:'persistence.refresh'});
    const before=await client.call(['sessions','status',original.session,'--target',original.target],{stage:'state.before-read-script'});
    await client.scoped(['scripts','run-inline','--code','import ghidra.app.script.GhidraScript; public class OwnedReadScript extends GhidraScript {public void run(){println("owned-read");}}','--request-id','program-read-script'],{stage:'persistence.read-script'});
    const after=await client.call(['sessions','status',original.session,'--target',original.target],{stage:'state.after-read-script'});
    report.readOnlyScriptPending={before:before.ghidra.pendingChanges,after:after.ghidra.pendingChanges};
   }finally{await rpc?.close();const primary=client.scope;for(const scope of retained){client.scope=scope;await client.scoped(['close'],{stage:'cleanup.retained'});}client.scope=primary;await client.cleanup();assert.equal(hash(await readFile(f.path)),f.sha256,'Fixture bytes changed');await writeFile(join(o.root,'manifest.json'),JSON.stringify(report,null,2)+'\n');}
  }
 }
 return report;
}
