import test from 'node:test';
import assert from 'node:assert/strict';
import {stage,verifyRegistry,requireNewer,integrity,packageName} from '../release.mjs';
const bytes=Buffer.from('owned archive'),id='11111111-2222-3333-4444-555555555555';
const manifest={name:packageName,version:'0.6.0',integrity:integrity(bytes)};
function fixture(changes={}){
  const calls=[],receipts=[];
  return {calls,receipts,input:{manifest,archive:'/owned/package.tgz',receipt:async(...r)=>{receipts.push(r);},download:async()=>changes.downloaded??bytes,
    npm:async args=>{calls.push(args);if(args[1]==='list')return JSON.stringify(changes.listed??[]);
      return JSON.stringify({[packageName]:{stageId:id,name:packageName,version:'0.6.0',integrity:manifest.integrity,...changes.staged}});}}};
}
test('a stage is uploaded once, downloaded back and left for owner approval',async()=>{
  const f=fixture();assert.equal(await stage(f.input),id);
  assert.deepEqual(f.calls.map(c=>c[1]),['list','publish']);assert.deepEqual(f.receipts,[['stage-upload-unknown'],['staged-unverified',id],['awaiting-2fa-approval',id]]);
  assert.ok(!f.calls.flat().some(v=>v==='approve'));
});
test('an existing stage of this version prevents another upload',async()=>{
  const f=fixture({listed:[{version:'0.6.0'}]});await assert.rejects(stage(f.input),/already has a stage/);assert.equal(f.calls.length,1);assert.equal(f.receipts.length,0);
});
for(const [name,changes] of Object.entries({integrity:{staged:{integrity:'sha512-other'}},version:{staged:{version:'0.6.1'}},bytes:{downloaded:Buffer.from('other')}}))
  test('a stage with different '+name+' keeps only its unverified identity',async()=>{
    const f=fixture(changes);await assert.rejects(stage(f.input),/inspect the saved stage ID/);assert.deepEqual(f.receipts,[['stage-upload-unknown'],['staged-unverified',id]]);
  });
for(const [name,publish] of Object.entries({failure:()=>{throw Error('timed out');},malformed:()=>'{',missing:()=>'{}',empty:()=>JSON.stringify({[packageName]:{name:packageName}})}))
  test('a '+name+' upload response leaves an unknown receipt without another upload',async()=>{
    const f=fixture();let uploads=0;
    await assert.rejects(stage({...f.input,npm:async args=>{if(args[1]==='list')return '[]';uploads++;return publish();}}));
    assert.equal(uploads,1);assert.deepEqual(f.receipts,[['stage-upload-unknown']]);
  });
test('registry verification needs the exact version, bytes and latest tag',async()=>{
  const values={'0.6.0':{version:'0.6.0',dist:{integrity:manifest.integrity}},'dist-tags':{latest:'0.6.0'}},view=async key=>values[key];
  await verifyRegistry({manifest,view});
  for(const changed of [{'0.6.0':undefined},{'0.6.0':{version:'0.6.0',dist:{integrity:'sha512-x'}}},{'dist-tags':{latest:'0.5.8'}}])
    await assert.rejects(verifyRegistry({manifest,view:async key=>({...values,...changed})[key]}));
});
test('only a newer stable version is released',()=>{
  requireNewer('0.6.0','0.5.8');requireNewer('0.10.0','0.9.9');
  for(const [a,b] of [['0.5.8','0.5.8'],['0.5.7','0.5.8'],['0.6.0-beta.1','0.5.8'],['0.6.0','latest']])assert.throws(()=>requireNewer(a,b));
});
