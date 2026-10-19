import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {PublicCli,Recorder} from './public.mjs';
import {archiveClosedProfile} from './storage.mjs';
export async function runConcurrency(o,manifest){
 const f=manifest.fixtures[0],directory=join(o.root,'concurrency');await mkdir(directory,{recursive:true});const r=new Recorder(directory,{label:o.label,fixture:f.name,analysis:f.analyzed}),cli=new PublicCli(o.cli,f.profile,r);let other;
 try{
  cli.scope=await cli.call(['ghidra','open',f.path,'--session','new'],{stage:'setup.context'});other=await cli.call(['ghidra','open','--target',cli.scope.target,'--session','new'],{stage:'setup.independent-context'});
  const original=cli.scope;
  for(let sample=-o.warmups;sample<o.warm;sample++){
  const meta={sample,warmup:sample<0},suffix=o.runId+'-'+(sample<0?'warmup-'+(-sample):'sample-'+sample);
  const slow=cli.scoped(['scripts','run-inline','--code','import ghidra.app.script.GhidraScript; public class OwnedQueueProbe extends GhidraScript {public void run() throws Exception {Thread.sleep(8000);println("owned-queue-probe");}}','--request-id',suffix+'-slow'],{stage:'concurrency.long-operation',...meta});
  await delay(1000);
  const configuration=cli.call(['profile','create','perf66-queue-'+suffix],{global:true,stage:'concurrency.queued-configuration',...meta});
  await delay(500);
  const independent=cli.call(['ghidra','program','metadata','--session',other.session,'--target',other.target],{stage:'concurrency.independent-read',...meta});
  const diagnostic=cli.call(['sessions','status',other.session,'--target',other.target],{stage:'concurrency.diagnostic',...meta});
  const [long,configured,read,status]=await Promise.all([slow,configuration,independent,diagnostic]);assert.ok(long);assert.ok(configured);assert.match(JSON.stringify(read),new RegExp(f.sha256));assert.equal(status.ghidra.state,'ready');
  // Concurrent independent workers without an exclusive profile change must both return useful results.
  await Promise.all([cli.scoped(['program','metadata'],{stage:'concurrency.first-read',...meta}),cli.call(['ghidra','program','metadata','--session',other.session,'--target',other.target],{stage:'concurrency.second-read',...meta})]);
  }
 }finally{if(other){const original=cli.scope;cli.scope=other;await cli.scoped(['close'],{stage:'cleanup.peer'});cli.scope=original;}await cli.cleanup();await writeFile(join(directory,'cleanup.json'),JSON.stringify({ownedContextsClosed:true,ownedServerStopped:true}));}
 await archiveClosedProfile(o,f.profile);
}
