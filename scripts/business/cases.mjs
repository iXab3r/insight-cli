import assert from 'node:assert/strict';
import {mkdir,readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {PublicCli,exec,json,save} from './public-cli.mjs';
export async function bindings(client,target){
 const parent=join(client.workspace(),'ghidra-native/context');let dirs;try{dirs=await readdir(parent);}catch(e){if(e.code==='ENOENT')return [];throw e;}
 const out=[];for(const dir of dirs){let b;try{b=await json(join(parent,dir,'current.json'));}catch(e){if(e.code==='ENOENT')continue;throw e;}
  if(target&&b.target!==target)continue;try{const command=(await exec('ps',['-p',String(b.pid),'-o','command='])).stdout;if(command.includes(b.root)&&command.includes('InsightHeadlessMain'))out.push(b);}catch(e){if(e.code!==1)throw e;}
 }return out;
}
async function killOwned(binding,main='InsightHeadlessMain'){
 const command=(await exec('ps',['-p',String(binding.pid),'-o','command='])).stdout;assert.ok(command.includes(binding.root)&&command.includes(main));process.kill(binding.pid,'SIGKILL');
}
async function until(action,ms=180000){const end=Date.now()+ms;while(Date.now()<end){const value=await action();if(value)return value;await delay(5);}throw Error('Owned fault boundary not reached');}
export async function runCase(id,m,directory){
 const cli=new PublicCli(m,directory),checks={},facts={};let other,failed;
 const check=(name,condition)=>{assert.ok(condition,name);checks[name]=true;};
 const index=Number(id.slice(3)),address=m.inputs[0].exports['case'+index],set=(s,t,extra=[])=>cli.comment(s,address,t,extra),get=s=>cli.readComment(s,address),merge=s=>cli.scoped(s,'merge');
 const observe=async(target,expected,at=address)=>{const reader=await cli.fresh(target);assert.equal(await cli.readComment(reader,at),expected);await cli.close(reader);};
 const pair=async()=>{const a=await cli.open(),b=await cli.open();check('sameTargetIndependentSessions',a.target===b.target&&a.session!==b.session);return [a,b];};
 try{
  if(index===17){
   other=new PublicCli(m,join(directory,'interrupted'),m.profile+'-first');await other.setup();const request='first-import-'+randomUUID(),args=['ghidra','open',m.inputs[0].path,'--session','new','--request-id',request];
   const pending=other.call(args,{allowFailure:true});
   const binding=await until(async()=>{const parent=join(other.workspace(),'ghidra-native/initial');let targets;try{targets=await readdir(parent);}catch(e){if(e.code==='ENOENT')return;throw e;}
    for(const target of targets){let progress;try{progress=await json(join(parent,target,'import.json'));}catch(e){if(e.code==='ENOENT')continue;throw e;}if(progress.phase==='importing')return {pid:progress.pid,root:join(parent,target)};}
   });await killOwned(binding,'InsightInitialImport');check('firstOpenInterrupted',(await pending).code!==0);
   const sessions=await other.call(['sessions','list']),targets=await other.call(['targets','list']);assert.equal(sessions.items.length,1);assert.equal(targets.items.length,1);
   const ready=await other.call(args);other.scopes.push(ready);check('originalScopeRetained',ready.session===sessions.items[0].id&&ready.target===targets.items[0].target&&ready.baseRevision==='R1');
   check('oneInitialPublication',(await other.history(ready.target)).versions.length===1);await other.comment(ready,address,'BS-17 recovered import');assert.equal((await other.scoped(ready,'merge')).state,'merged');
   const reader=await other.fresh(ready.target);check('recoveredInvestigationDelivered',await other.readComment(reader,address)==='BS-17 recovered import');
  }else if(index===1){
   const a=await cli.open();const target=await cli.call(['targets','show',a.target]);check('inputIdentity',target.binarySha256===m.inputs[0].sha256);
   const health=await cli.scoped(a,'status');check('contextUsable',health.health.connected===true);facts.scope={session:a.session,target:a.target};
  }else if(index===2||index===3){
   const a=await cli.open(),strings=await cli.scoped(a,'strings search',['--contains','insight-config-v1.json']);
   check('knownClueAddress',strings.items.some(x=>x.address===m.inputs[0].exports.evidence_config));
   if(index===3){const refs=await cli.scoped(a,'xrefs to',['--address',m.inputs[0].exports.evidence_config]);check('clueReferencesExpectedFunction',refs.items.some(x=>x.function?.address===m.inputs[0].exports.config_read));
    const code=await cli.scoped(a,'functions decompile',['--address',m.inputs[0].exports.config_read]);check('decompilationExplainsClue',(code.code.includes('evidence_config')||code.code.includes('insight-config-v1.json'))&&code.code.includes('case1'));facts.clueFunction=m.inputs[0].exports.config_read;
   }
  }else if(index===4||index===5){
   const [a,b]=await pair(),name='Finding_'+index;await cli.scoped(a,'functions rename',['--address',address,'--name',name]);await set(a,'Private finding '+index);
   check('privateNameAndComment',(await cli.scoped(a,'functions get',['--address',address])).name===name&&await get(a)==='Private finding '+index);
   check('otherAgentDoesNotSeeUnpublished',await get(b)===null&&(await cli.scoped(b,'functions get',['--address',address])).name!=='Finding_'+index);
   if(index===5){await merge(a);await observe(a.target,'Private finding '+index);const reader=await cli.fresh(a.target);check('publishedName',(await cli.scoped(reader,'functions get',['--address',address])).name===name);check('independentPublishedReadback',true);}
  }else if([6,7,8,9].includes(index)){
   const a=await cli.open(),b=await cli.open(m.inputs[1].path,a.session);check('twoDistinctInputs',a.target!==b.target);
   await set(a,'First build '+index);const secondAt=m.inputs[1].exports['case'+index];await cli.comment(b,secondAt,'Second build '+index);
   assert.equal(await get(a),'First build '+index);assert.equal(await cli.readComment(b,secondAt),'Second build '+index);check('privateTargetIsolation',true);
   if(index===7){check('equalBasenamesAndAddresses',m.inputs.every(i=>i.path.endsWith('/client.exe'))&&address===secondAt);await merge(a);await observe(a.target,'First build '+index);const read=await cli.fresh(b.target);check('otherSharedTargetUnaffected',await cli.readComment(read,secondAt)===null);}
   if(index===8){const first=await cli.scoped(a,'strings search',['--contains','business-build-one']),second=await cli.scoped(b,'strings search',['--contains','business-build-two']);check('versionDifferencesBoundToTargets',first.items.some(x=>x.address===m.inputs[0].exports.evidence_version)&&second.items.some(x=>x.address===m.inputs[1].exports.evidence_version));}
   if(index===9){await cli.close(a);const resumed=await cli.call(['ghidra','open',...cli.selectors(a)]);cli.scopes.push(resumed);check('originalContextResumed',resumed.session===a.session&&resumed.target===a.target&&await get(resumed)==='First build '+index);}
  }else if(index>=10&&index<=16){
   const [a,b]=await pair(),otherAt=m.inputs[0].exports.config_read,one='Agent A '+index,two='Agent B '+index;
   if(index===10){const start=cli.calls.length;await Promise.all([set(a,one),set(b,two)]);const calls=cli.calls.slice(start);check('overlappingCliCalls',calls.length===2&&Math.min(...calls.map(c=>c.ended))>Math.max(...calls.map(c=>c.started)));check('twoNativeWorkers',(await bindings(cli,a.target)).length===2);check('independentPrivateResults',await get(a)===one&&await get(b)===two);}
   if(index===11){await set(a,one);await cli.comment(b,otherAt,two);await merge(a);await merge(b);await observe(a.target,one);await observe(a.target,two,otherAt);check('bothContributionsAccepted',true);}
   if(index===12){await cli.comment(b,otherAt,two);await set(a,one);await merge(a);check('stableUntilExplicitRefresh',await get(b)===null);await cli.scoped(b,'refresh');check('refreshPreservesLocalWork',await get(b)===one&&await cli.readComment(b,otherAt)===two);await merge(b);await observe(a.target,two,otherAt);check('combinedResultDelivered',true);}
   if(index===13){await set(a,one);await set(b,one);await merge(a);const result=await merge(b);check('agreementWithoutConflict',result.state==='merged'&&result.pendingChanges===0);await observe(a.target,one);}
   if(index===14||index===15){await set(a,one);await set(b,two);if(index===15)await cli.comment(b,otherAt,'Safe but unpublished '+index);await merge(a);
    const conflict=await cli.scoped(b,'merge',[],{allowFailure:true});check('conflictReported',conflict.code!==0);const status=await cli.status(b);check('bothConflictVersionsRetained',status.ghidra.conflicts.some(c=>c.local===two&&c.shared===one));
    if(index===15){check('entireLocalSetRetained',await get(b)===two&&await cli.readComment(b,otherAt)==='Safe but unpublished '+index);const shared=await cli.fresh(a.target);check('noPartialPublication',await get(shared)===one&&await cli.readComment(shared,otherAt)!=='Safe but unpublished '+index);}
    await set(b,two,['--resolve-conflict','--expect-shared',one]);await merge(b);await observe(a.target,two);check('deliberateResolutionDelivered',true);
   }
   if(index===16){const name='BusinessRecord_'+randomUUID().replaceAll('-',''),fields=JSON.stringify([{name:'kind',type:'int'},{name:'length',type:'int'}]);
    const correct=v=>v.name===name&&Array.isArray(v.fields)&&v.fields.length===2&&v.fields[0].name==='kind'&&v.fields[1].name==='length';
    await cli.scoped(b,'types create-struct',['--name',name,'--fields',fields]);await set(a,one);await merge(a);const conflict=await cli.scoped(b,'merge',[],{allowFailure:true});check('complexDivergenceRetained',conflict.code!==0&&correct((await cli.scoped(b,'types struct-layout',['--name',name])).value));
    const current=await cli.fresh(a.target);await cli.scoped(current,'types create-struct',['--name',name,'--fields',fields]);await merge(current);const reader=await cli.fresh(a.target);check('transferredStructureAndSharedFinding',correct((await cli.scoped(reader,'types struct-layout',['--name',name])).value)&&await get(reader)===one);
   }
  }else if(index===18){
   const a=await cli.open();await set(a,'Published before crash');await merge(a);await cli.comment(a,m.inputs[0].exports.config_read,'Acknowledged private work');
   const owned=await bindings(cli,a.target);assert.equal(owned.length,1);await killOwned(owned[0]);await cli.call(['ghidra','open',...cli.selectors(a)]);
   check('savedWorkRecovered',await get(a)==='Published before crash'&&await cli.readComment(a,m.inputs[0].exports.config_read)==='Acknowledged private work');await merge(a);await observe(a.target,'Acknowledged private work',m.inputs[0].exports.config_read);check('recoveredWorkDelivered',true);
  }else if(index===19||index===20){
   const a=await cli.open(),request=id+'-lost-'+randomUUID(),text='Lost reply finding '+index;
   if(index===19){await cli.scoped(a,'comments set',['--address',address,'--kind','plate','--text',text,'--request-id',request],{discardReply:true});check('replyDiscardedAtClientBoundary',true);const status=await cli.status(a);check('outcomeEstablished',status.ghidra.unresolvedRequests.length===0&&await get(a)===text);
    const first=(await cli.status(a)).ghidra.pendingChanges;await set(a,text,['--request-id',request]);check('sameIntentNotDuplicated',(await cli.status(a)).ghidra.pendingChanges===first);
    const changed=await cli.scoped(a,'comments set',['--address',address,'--kind','plate','--text','Different intent','--request-id',request],{allowFailure:true});check('retryIdentityRejectsDifferentIntent',changed.code!==0&&await get(a)===text);await merge(a);await observe(a.target,text);
   }else{await set(a,text);const before=(await cli.history(a.target)).versions.length;await cli.scoped(a,'merge',['--request-id',request],{discardReply:true});check('replyDiscardedAtClientBoundary',true);const status=await cli.status(a);check('outcomeEstablished',status.ghidra.mergeState==='idle'&&status.ghidra.pendingChanges===0);await observe(a.target,text);await cli.scoped(a,'merge',['--request-id',request]);check('onePublicationAfterRetry',(await cli.history(a.target)).versions.length===before+1);}
  }else throw Error('Unknown functional scenario '+id);
 }catch(e){failed=e;throw e;}finally{
  try{await cli.cleanup();if(other){await other.cleanup();await other.call(['ghidra','server','disconnect']);}}
  catch(cleanup){if(failed)throw new AggregateError([failed,cleanup],'Scenario and cleanup failed');throw cleanup;}
 }
 assert.ok(Object.keys(checks).length);const report={schema:1,id,state:'passed',checks,facts,artifactSha256:m.artifactSha256,inputSha256:m.inputs.map(i=>i.sha256),publicCliOnly:true,cleanupComplete:true};await save(join(directory,'result.json'),report);return report;
}
