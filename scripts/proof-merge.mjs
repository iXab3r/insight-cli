// Owned native merge fixture; refresh/recovery/full catalog remain distinct acceptance gates.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {createInsightCli} from '../skills/ghidra-coordinator/dist/src/cli.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const options={},argv=process.argv.slice(2);
for(let i=0;i<argv.length;i++){if(argv[i]==='--ack-disposable')options.ack=true;else if(argv[i].startsWith('--')&&argv[i+1])options[argv[i].slice(2)]=argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]),'Native proof is local only');
for(const key of ['ghidra-home','java','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
test('native saved-state and scalar three-way merge',async()=>{
 const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar']};
 const f=await createCliFixture({after(){}},{applicationId:'insight-cli',profiles:[{name:'default',values,permissions:['ReadOnly','Update']}]});
 let context,losePublishedAnswer=false;
 const actual=f.createApplication(runtime=>createInsightCli({runtime,backend:async(workspace,c)=>{
  context=c;const native=new GhidraContexts(workspace,await nativeInputs(values),c);
  return {open:native.open.bind(native),call:native.call.bind(native),saved:native.saved.bind(native),mode:native.mode.bind(native),
   close:native.close.bind(native),dispose:native.dispose.bind(native),latest:native.latest.bind(native),fields:native.fields.bind(native),
   candidate:native.candidate.bind(native),recover:native.recover.bind(native),recoverModel:native.recoverModel.bind(native),
   async publish(publication){const result=await native.publish(publication);if(losePublishedAnswer){losePublishedAnswer=false;throw Error('Synthetic native committed response loss');}return result;}};
 }}));
 const exec=promisify(execFile),dir=join(f.root,'input');await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
 await writeFile(c,'__declspec(noinline) int first(int x){return x+17;}\n__declspec(noinline) int second(int x){return x+23;}\nint main(void){return first(second(2));}\n');
 await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
 await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:second','/export:main','/out:'+exe,obj]);
 try {
  const a=await f.json(actual,['ghidra','open',exe,'--session','new']);
  const b=await f.json(actual,['ghidra','open',exe,'--session','new']);
  const select=who=>['--session',who.session,'--target',who.target];
  const at='0x140001000',other='0x140001010';
  await f.json(actual,['ghidra','comments','set',...select(a),'--address',at,'--kind','eol','--text','A shared comment']);
  await f.json(actual,['ghidra','comments','set',...select(b),'--address',other,'--kind','eol','--text','B disjoint comment']);
  const mergedA=await f.json(actual,['ghidra','merge',...select(a),'--request-id','merge-A']);assert.equal(mergedA.sharedRevision,'R2');assert.equal(mergedA.applied,1);
  assert.deepEqual(await f.json(actual,['ghidra','merge',...select(a),'--request-id','merge-A']),mergedA);
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(b),'--address',at,'--kind','eol'])).text,null);
  const refreshed=await f.json(actual,['ghidra','refresh',...select(b),'--request-id','refresh-B']);
  assert.equal(refreshed.state,'updated');assert.equal(refreshed.receivedChanges,1);assert.equal(refreshed.preservedLocalChanges,1);
  assert.deepEqual(await f.json(actual,['ghidra','refresh',...select(b),'--request-id','refresh-B']),refreshed);
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(b),'--address',at,'--kind','eol'])).text,'A shared comment');
  const mergedB=await f.json(actual,['ghidra','merge',...select(b)]);assert.equal(mergedB.sharedRevision,'R3');
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(b),'--address',at,'--kind','eol'])).text,'A shared comment');
  const reader=await f.json(actual,['ghidra','open','--session','new','--target',a.target]);
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(reader),'--address',other,'--kind','eol'])).text,'B disjoint comment');
  await f.json(actual,['ghidra','comments','set',...select(a),'--address',at,'--kind','eol','--text','A overlap']);
  await f.json(actual,['ghidra','comments','set',...select(b),'--address',at,'--kind','eol','--text','B overlap']);
  const secondA=await f.json(actual,['ghidra','merge',...select(a)]);assert.equal(secondA.sharedRevision,'R4');
  const conflict=await f.run(actual,['ghidra','merge',...select(b),'--request-id','conflict-B','--json']);assert.notEqual(conflict.exitCode,0);
  const conflictedRefresh=await f.json(actual,['ghidra','refresh',...select(b)]);assert.equal(conflictedRefresh.state,'conflict');
  assert.notEqual((await f.run(actual,['ghidra','merge',...select(b),'--json'])).exitCode,0,'Refresh cannot implicitly resolve an overlapping field');
  const status=await f.json(actual,['sessions','status',b.session,'--target',b.target]);assert.equal(status.ghidra.conflicts.length,1);assert.equal(status.ghidra.pendingChanges,1);
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(b),'--address',at,'--kind','eol'])).text,'B overlap');
  const stale=await f.run(actual,['ghidra','comments','set',...select(b),'--address',at,'--kind','eol','--text','Resolved B',
    '--resolve-conflict','--expect-shared','obsolete','--json']);assert.notEqual(stale.exitCode,0);
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(b),'--address',at,'--kind','eol'])).text,'B overlap');
  const resolved=await f.json(actual,['ghidra','comments','set',...select(b),'--address',at,'--kind','eol','--text','Resolved B',
    '--resolve-conflict','--expect-shared','A overlap']);assert.equal(resolved.conflict,'resolved');
  const mergedResolution=await f.json(actual,['ghidra','merge',...select(b)]);assert.equal(mergedResolution.sharedRevision,'R5');
  await f.json(actual,['ghidra','comments','set',...select(a),'--address',other,'--kind','eol','--text','A after response loss']);
  losePublishedAnswer=true;
  const lostArgs=['ghidra','merge',...select(a),'--request-id','lost-native'];
  assert.notEqual((await f.run(actual,[...lostArgs,'--json'])).exitCode,0);
  assert.equal((await f.json(actual,['sessions','status',b.session,'--target',b.target])).ghidra.mergeState,'unknown');
  await f.json(actual,['ghidra','comments','set',...select(b),'--address',at,'--kind','eol','--text','B remains private']);
  assert.notEqual((await f.run(actual,['ghidra','merge',...select(b),'--json'])).exitCode,0);
  const resumed=await f.json(actual,['ghidra','open',...select(a)]);assert.equal(resumed.pendingChanges,0);
  const reconciled=await f.json(actual,lostArgs);assert.equal(reconciled.sharedRevision,'R6');
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(a),'--address',other,'--kind','eol'])).text,'A after response loss');
  const complex=await f.json(actual,['ghidra','open','--session','new','--target',a.target]);
  await f.json(actual,['ghidra','types','create-struct',...select(complex),'--name','PublishedRecord','--fields','[{"name":"count","type":"uint"}]']);
  await f.json(actual,['ghidra','functions','set-function-prototype',...select(complex),'--address',at,'--prototype','unsigned int first(unsigned int count)']);
  await f.json(actual,['ghidra','memory','create-block',...select(complex),'--address','0x150000000','--name','PublishedMemory','--size','64']);
  await f.json(actual,['ghidra','comments','set',...select(complex),'--address',at,'--kind','plate','--text','Comment after local signature change']);
  const complexMerged=await f.json(actual,['ghidra','merge',...select(complex)]);assert.equal(complexMerged.sharedRevision,'R7');assert.equal(complexMerged.applied,4);
  const missing=await f.run(actual,['ghidra','types','struct-layout',...select(a),'--name','PublishedRecord','--json']);assert.notEqual(missing.exitCode,0);
  await f.json(actual,['ghidra','refresh',...select(a)]);
  const layout=await f.json(actual,['ghidra','types','struct-layout',...select(a),'--name','PublishedRecord']);assert.equal(layout.value.fields[0].name,'count');
  assert.ok(JSON.stringify(await f.json(actual,['ghidra','memory','list',...select(a)])).includes('PublishedMemory'));
  assert.ok((await f.json(actual,['ghidra','functions','get',...select(a),'--address',at])).signature.includes('uint'));
  assert.equal((await f.json(actual,['ghidra','comments','get',...select(a),'--address',at,'--kind','plate'])).text,'Comment after local signature change');
  await f.json(actual,['ghidra','types','create-struct',...select(b),'--name','PrivateRecord','--fields','[{"name":"id","type":"uint"}]']);
  const complexConflict=await f.run(actual,['ghidra','merge',...select(b),'--json']);assert.notEqual(complexConflict.exitCode,0);
  const complexRefresh=await f.json(actual,['ghidra','refresh',...select(b)]);assert.equal(complexRefresh.state,'conflict');
  assert.equal((await f.json(actual,['ghidra','types','struct-layout',...select(b),'--name','PrivateRecord'])).value.fields[0].name,'id');
  const receipt={schema:1,scope:'owned native public merge commands',unchangedBaseFullSnapshot:true,divergedScalarMerge:true,
    callerRetryDoesNotCheckInAgain:true,otherAgentViewStable:true,independentPublishedRead:true,overlapRetainsPrivate:true,
    anyConflictPublishesZero:true,refreshPreservesLocal:true,refreshRetainsConflict:true,staleResolutionRejected:true,
    explicitResolutionPublishes:true,committedResponseLossReconciled:true,unknownBlocksAllPublishers:true,
    independentFullBuffersVerified:true,recoveryDoesNotCheckInAgain:true,complexSavedStatePublished:true,
    complexDivergenceRetainsBoth:true,publishedRevisions:7,ghidra:'12.1.2',java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,
    limitations:['complete crash matrix and full complex catalog remain separate gates','source Factory fixture transport and credential adapter']};
  await writeFile(join(f.root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
 }catch(error){console.error('Owned merge fixture diagnostics:',f.root);throw error;}
 finally{await actual.dispose();if(context)await new GhidraServer(join(f.appArguments.AppDataDirectory,'workspace'),await nativeInputs(values),context).stop();}
});
