import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {PublicCli,Recorder} from './public.mjs';
import {archiveClosedProfile} from './storage.mjs';
export async function runColdRpc(o,manifest){
 for(const f of manifest.fixtures)for(let cold=0;cold<o.cold;cold++){
  const directory=join(o.root,`${f.name}-${f.analyzed?'analysis':'no-analysis'}-${cold}`);await mkdir(directory,{recursive:true});
  const profile=`perf66-${o.label}-rpc-${f.name}-${f.analyzed?'a':'n'}-${o.runId}-${cold}`,r=new Recorder(directory,{label:o.label,fixture:f.name,analysis:f.analyzed,coldTrial:cold}),cli=new PublicCli(o.cli,profile,r);let rpc;
  try{
   await cli.setup(o.java,o.ghidra);
   cli.scope=await r.measure('cold.rpc-process-and-open',async()=>{rpc=await cli.rpc();return rpc.execute(['ghidra','open',f.path,'--session','new','--language','x86:LE:64:default','--compiler-spec','windows',...f.analyzed?[]:['--no-analysis']],{stage:'cold.open'});},{route:'rpc'});
   assert.equal(cli.scope.state,'ready');await rpc.call(['program','metadata'],{stage:'first.metadata',validate:v=>assert.match(JSON.stringify(v),new RegExp(f.sha256))});
  }finally{await rpc?.close();await cli.cleanup();await writeFile(join(directory,'cleanup.json'),JSON.stringify({ownedContextsClosed:true,ownedServerStopped:true}));}
  await archiveClosedProfile(o,profile);
 }
}
