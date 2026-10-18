import assert from 'node:assert/strict';
import {join} from 'node:path';
import {mkdir,writeFile} from 'node:fs/promises';
import {PublicCli,Recorder} from './public.mjs';
import {archiveClosedProfile} from './storage.mjs';
// Reopen the same public prepared model with fresh private contexts, preserving the original input/state recipe.
export async function runPersistence(o,manifest){
 for(const f of manifest.fixtures){const directory=join(o.root,`${f.name}-${f.analyzed?'analysis':'no-analysis'}`);await mkdir(directory,{recursive:true});
  const r=new Recorder(directory,{label:o.label,fixture:f.name,analysis:f.analyzed,cache:'warm-server-new-context'}),cli=new PublicCli(o.cli,f.profile,r);
  let peer;
  try{
   for(let sample=-o.warmups;sample<o.warm;sample++){
    const meta={sample,warmup:sample<0};
    cli.scope=await cli.call(['ghidra','open',f.path,'--session','new'],{stage:'persistence.new-context',...meta});
    peer=await cli.call(['ghidra','open','--target',cli.scope.target,'--session','new'],{stage:'persistence.peer-context',...meta});
    const text='Owned benchmark annotation '+sample,id=o.runId+'-'+(sample<0?'warmup-'+(-sample):'sample-'+sample);
    const write=await cli.scoped(['comments','set','--address',f.exports.owned_add,'--kind','plate','--text',text,'--request-id',id+'-edit'],{stage:'persistence.edit',...meta});assert.equal(write.state,'applied');
    const repeated=await cli.scoped(['comments','set','--address',f.exports.owned_add,'--kind','plate','--text',text,'--request-id',id+'-edit'],{stage:'persistence.durable-replay',...meta});assert.deepEqual(repeated,write);
    await cli.scoped(['scripts','run-inline','--code','import ghidra.app.script.GhidraScript; public class OwnedProgramRead extends GhidraScript {public void run(){println("owned-read");}}','--request-id',id+'-script'],{stage:'persistence.read-script',...meta});
    const result=await cli.scoped(['merge','--request-id',id+'-merge'],{stage:'persistence.merge',...meta});assert.equal(result.state,'merged');
    const original=cli.scope;cli.scope=peer;await cli.scoped(['refresh','--request-id',id+'-refresh'],{stage:'persistence.refresh',...meta});
    assert.equal((await cli.scoped(['comments','get','--address',f.exports.owned_add,'--kind','plate'],{stage:'persistence.refresh-readback',...meta})).text,text);
    await cli.scoped(['close'],{stage:'persistence.peer-close',...meta});peer=undefined;cli.scope=original;
    await cli.scoped(['close'],{stage:'persistence.close',...meta});cli.scope=await cli.call(['ghidra','open','--session',original.session,'--target',original.target],{stage:'persistence.reopen',...meta});
    assert.equal((await cli.scoped(['comments','get','--address',f.exports.owned_add,'--kind','plate'],{stage:'persistence.reopen-readback',...meta})).text,text);
    await cli.scoped(['close'],{stage:'persistence.final-close',...meta});cli.scope=undefined;
   }
  }finally{if(peer){const original=cli.scope;cli.scope=peer;await cli.scoped(['close'],{stage:'cleanup.peer'});cli.scope=original;}await cli.cleanup();await writeFile(join(directory,'cleanup.json'),JSON.stringify({ownedContextsClosed:true,ownedServerStopped:true}));}
  if(f.profile!==manifest.fixtures[0].profile)await archiveClosedProfile(o,f.profile);
 }
}
