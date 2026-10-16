// Test-side orchestration for actual AI-agent research. All program operations use public CLI.
import assert from 'node:assert/strict';
import {readFile,mkdir,appendFile,copyFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {PublicCli,json,save,exec} from '../business/public-cli.mjs';
import {bindings} from '../business/cases.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url));
const protocol=await json(new URL('./protocol.json',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const stamp=()=>({monotonicNs:process.hrtime.bigint().toString(),utc:new Date().toISOString()});
const elapsed=(start,end)=>Number(BigInt(end.monotonicNs)-BigInt(start.monotonicNs))/1e9;
const [action,location,...args]=process.argv.slice(2);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
assert.equal(process.platform,'darwin');
assert.ok(!process.env.CI);
function uncomment(code) {
 let result='',state='code';
 for(let i=0;i<code.length;i++) {
  const c=code[i],next=code[i+1];
  if(state==='line'){if(c==='\n'){state='code';result+=' ';}continue;}
  if(state==='block'){if(c==='*'&&next==='/'){state='code';result+=' ';i++;}continue;}
  if(state==='string'||state==='char'){result+=c;if(c==='\\'){result+=next??'';i++;}else if(c===(state==='string'?'"':"'"))state='code';continue;}
  if(c==='/'&&next==='/'){state='line';i++;continue;}
  if(c==='/'&&next==='*'){state='block';i++;continue;}
  if(c==='"')state='string';else if(c==="'")state='char';result+=c;
 }
 return result.replace(/\s+/g,' ').trim();
}
const partOf=id=>{const p=protocol.parts.find(p=>p.id===id);assert.ok(p,'Unknown task part');return p;};
async function nativeProof(t) {
 const events=(await readFile(join(t.directory,'events.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
 const samples=(await readFile(join(t.directory,'native-observations.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);assert.ok(samples.length>=2);
 const before=samples[0].cpu,after=samples.at(-1).cpu;assert.ok(t.native.every(n=>after[n.pid]>before[n.pid]),'Every native worker must do CPU work');
 const actors=Array.from({length:t.workers},(_,actor)=>{
  const reads=events.filter(e=>Number(e.actor)===actor&&e.state==='read'),done=events.filter(e=>Number(e.actor)===actor&&e.state==='finding-saved');assert.ok(reads.length&&done.length);
  return {actor,reads:reads.length,parts:done.map(d=>d.part),firstRead:reads[0].started,lastSaved:done.at(-1).at};
 });
 const first=actors.reduce((a,b)=>BigInt(a.firstRead.monotonicNs)>BigInt(b.firstRead.monotonicNs)?a:b).firstRead;
 const last=actors.reduce((a,b)=>BigInt(a.lastSaved.monotonicNs)<BigInt(b.lastSaved.monotonicNs)?a:b).lastSaved;
 const overlapSeconds=elapsed(first,last);if(t.workers===3)assert.ok(overlapSeconds>0,'Agent research windows must overlap');
 const common=samples.filter(s=>BigInt(s.monotonicNs)>=BigInt(first.monotonicNs)&&BigInt(s.monotonicNs)<=BigInt(last.monotonicNs));
 return {distinctWorkers:t.native.length,actors,overlapSeconds,cpuBefore:before,cpuAfter:after,samples:samples.length,
  ...(common.length>=2?{commonWindow:{first:common[0],last:common.at(-1),allWorkersCpuGrew:t.native.every(n=>common.at(-1).cpu[n.pid]>common[0].cpu[n.pid])}}:{})};
}
async function client(t,actor,label) {
 const m=await json(t.manifest),dir=join(t.directory,'actors',String(actor),label+'-'+randomUUID());
 return new PublicCli(m,dir,t.profile);
}
if(action==='init') {
 const [packageManifest,input]=args,m=await json(packageManifest),bytes=await readFile(input);
 assert.equal(sha(bytes),protocol.inputSha256);assert.equal(sha(await readFile(m.artifact)),m.artifactSha256);
 await mkdir(location,{recursive:true,mode:0o700});await mkdir(join(location,'input'),{recursive:true});
 const inputPath=join(location,'input/7zr.exe');await copyFile(input,inputPath);
 const manifest={...m,directory:resolve(location),root,inputs:[{path:inputPath,sha256:sha(bytes),bytes:bytes.length}],profile:undefined};
 await save(join(location,'manifest.json'),manifest);await save(join(location,'protocol.json'),protocol);
 console.log(JSON.stringify({directory:resolve(location),artifactSha256:m.artifactSha256,inputSha256:sha(bytes)}));
} else if(action==='trial') {
 const [name,count,coldFlag]=args,m=await json(join(location,'manifest.json')),workers=Number(count);assert.ok([1,3].includes(workers));
 const directory=resolve(location,name);await mkdir(directory,{recursive:true,mode:0o700});
 const t={schema:1,name,directory,manifest:resolve(location,'manifest.json'),profile:'research7zr-'+randomUUID(),workers,cold:coldFlag==='cold',scopes:[],setupStarted:stamp(),state:'preparing'};
 const cli=await client(t,'setup','prepare');await save(join(directory,'trial.json'),t);await cli.setup();
 if(t.cold)t.started=stamp();
 for(let i=0;i<workers;i++){t.scopes.push(await cli.open());await save(join(directory,'trial.json'),t);}
 const identity=await cli.call(['targets','show',t.scopes[0].target]);assert.equal(identity.binarySha256,protocol.inputSha256);
 const native=await bindings(cli,t.scopes[0].target);assert.equal(native.length,workers);assert.equal(new Set(native.map(n=>n.root)).size,workers);t.native=native.map(({pid,session,target,root})=>({pid,session,target,ownedRootSha256:sha(root)}));
 t.ready=stamp();t.setupSeconds=elapsed(t.setupStarted,t.ready);t.state='ready';await save(join(directory,'trial.json'),t);
 console.log(JSON.stringify({trial:join(directory,'trial.json'),workers,cold:t.cold,setupSeconds:t.setupSeconds,scopes:t.scopes.map(({session,target})=>({session,target})),native:t.native}));
} else if(action==='start') {
 const t=await json(location);assert.equal(t.state,'ready');if(!t.started)t.started=stamp();t.dispatched=stamp();t.state='researching';await save(location,t);
 const observer=spawn(process.execPath,[fileURLToPath(new URL('./observer.mjs',import.meta.url)),resolve(location)],{detached:true,stdio:'ignore'});observer.unref();t.observerPid=observer.pid;await save(location,t);console.log(JSON.stringify(t.started));
} else if(action==='call') {
 const [actor,...command]=args,t=await json(location);assert.equal(t.state,'researching');const scope=t.scopes[Number(actor)];assert.ok(scope);
 const words=command.slice(0,2).join(' ');assert.ok(['strings search','xrefs to','functions get','functions decompile','functions search'].includes(words),'Research read is outside the declared public interface');
 const cli=await client(t,actor,'read'),started=stamp();const result=await cli.scoped(scope,words,command.slice(2));
 await appendFile(join(t.directory,'events.jsonl'),JSON.stringify({actor,command,started,ended:stamp(),state:'read'})+'\n');console.log(JSON.stringify(result));
} else if(action==='submit') {
 const [actor,id,path]=args,t=await json(location),part=partOf(id),scope=t.scopes[Number(actor)];assert.ok(scope);assert.equal(t.state,'researching');
 const permitted=resolve(t.directory,'actors',String(actor));assert.ok(resolve(path).startsWith(permitted+'/'),'Finding must be in the assigned actor folder');
 const finding=await json(path);assert.equal(finding.part,id);assert.match(finding.functionAddress,/^0x[0-9a-f]+$/i);assert.ok(finding.conclusion.length>=80);assert.ok(finding.facts.length>=3);assert.ok(finding.anchors.length>=1);assert.ok(Array.isArray(finding.limitations)&&finding.limitations.length>0);
 for(const fact of finding.facts){assert.match(fact.functionAddress,/^0x[0-9a-f]+$/i);assert.ok(fact.claim.length>=20);assert.ok(fact.codeQuote.length>=12);}
 for(const a of finding.anchors){assert.ok(a.text.length>=5);for(const p of ['stringAddress','referenceFrom','functionAddress'])assert.match(a[p],/^0x[0-9a-f]+$/i);for(const at of a.via??[])assert.match(at,/^0x[0-9a-f]+$/i);}
 finding.kind=part.kind;const text=JSON.stringify(finding);assert.ok(text.length<=16000);const cli=await client(t,actor,'save');await cli.scoped(scope,'comments set',['--address',finding.functionAddress,'--kind',part.kind,'--text',text]);
 await save(join(permitted,id+'-submitted.json'),finding);await appendFile(join(t.directory,'events.jsonl'),JSON.stringify({actor,part:id,state:'finding-saved',at:stamp()})+'\n');
 console.log(JSON.stringify({part:id,state:'saved-private',functionAddress:finding.functionAddress,kind:part.kind}));
} else if(action==='collect') {
 const t=await json(location);assert.equal(t.state,'researching');const m=await json(t.manifest),cli=await client(t,'lead','collect'),lead=t.scopes[0],collected=[],proof=[];t.researchFinished=stamp();
 for(let i=0;i<protocol.parts.length;i++) {
  const part=protocol.parts[i],actor=t.workers===1?0:i,finding=await json(join(t.directory,'actors',String(actor),part.id+'-submitted.json')),producer=t.scopes[actor];
  const text=(await cli.scoped(producer,'comments get',['--address',finding.functionAddress,'--kind',part.kind])).text;assert.deepEqual(JSON.parse(text),finding);
  if(actor!==0)await cli.scoped(lead,'comments set',['--address',finding.functionAddress,'--kind',part.kind,'--text',text]);
  collected.push(finding);
 }
 t.collected=stamp();const merge=await cli.scoped(lead,'merge');assert.equal(merge.state,'merged');t.merged=stamp();t.merge=merge;t.findings=collected;t.state='verifying';await save(location,t);
 const reader=await cli.fresh(lead.target),codes=new Map();t.reader=reader;await save(location,t);
 for(const finding of collected) {
  const part=partOf(finding.part),read=(await cli.scoped(reader,'comments get',['--address',finding.functionAddress,'--kind',part.kind])).text;assert.deepEqual(JSON.parse(read),finding);
  for(const a of finding.anchors) {
   const strings=await cli.scoped(reader,'strings search',['--contains',a.text,'--limit','100']);assert.ok(strings.items.some(s=>s.address.toLowerCase()===a.stringAddress.toLowerCase()&&s.text.includes(a.text)),'Clue string is absent');
   let destination=a.stringAddress,last;
   for(const from of [a.referenceFrom,...(a.via??[])]) {
    const refs=await cli.scoped(reader,'xrefs to',['--address',destination,'--limit','100']);last=refs.items.find(r=>r.from?.toLowerCase()===from.toLowerCase());assert.ok(last,'Clue xref hop is absent');destination=from;
   }
   assert.equal(last.function?.address.toLowerCase(),a.functionAddress.toLowerCase(),'Clue chain does not reach its declared function');
  }
  for(const fact of finding.facts) {
   if(!codes.has(fact.functionAddress)){const v=await cli.scoped(reader,'functions decompile',['--address',fact.functionAddress]);assert.equal(v.truncated,false);codes.set(fact.functionAddress,v.code);}
   assert.ok(uncomment(codes.get(fact.functionAddress)).includes(uncomment(fact.codeQuote)),'Code quotation is absent outside comments: '+fact.claim);
  }
  proof.push({part:finding.part,anchorsVerified:finding.anchors.length,factsVerified:finding.facts.length});
 }
 t.verified=stamp();t.state='awaiting-semantic-review';t.findings=collected;t.proof=proof;t.merge=merge;t.reader=reader;t.codeHashes=Object.fromEntries([...codes].map(([address,code])=>[address,sha(code)]));
 await save(join(t.directory,'independent-code.json'),Object.fromEntries(codes));await save(location,t);console.log(JSON.stringify({state:t.state,secondsBeforeSemanticReview:elapsed(t.started,t.verified),findings:collected,proof}));
} else if(action==='finish') {
 const [reviewPath]=args,t=await json(location),review=await json(reviewPath);assert.equal(t.state,'awaiting-semantic-review');
 assert.deepEqual(Object.keys(review.criteria).sort(),protocol.parts.map(p=>p.id).sort());assert.ok(Object.values(review.criteria).every(v=>v===true));assert.ok(review.explanation.length>=80);
 t.nativeProof=await nativeProof(t);t.finished=stamp();t.state='passed';t.elapsedSeconds=elapsed(t.started,t.finished);t.review=review;t.phases={setupSeconds:t.setupSeconds,researchSeconds:elapsed(t.dispatched,t.researchFinished),collectionSeconds:elapsed(t.researchFinished,t.collected),mergeSeconds:elapsed(t.collected,t.merged),independentVerificationSeconds:elapsed(t.merged,t.verified),semanticReviewSeconds:elapsed(t.verified,t.finished)};await save(location,t);
 const cli=await client(t,'cleanup','close'),sessions=await cli.call(['sessions','list']);
 for(const session of sessions.items)await cli.close({session:session.id,target:t.scopes[0].target});
 await cli.call(['ghidra','server','disconnect']);t.cleanupComplete=true;await save(location,t);
 console.log(JSON.stringify({state:t.state,elapsedSeconds:t.elapsedSeconds,phases:t.phases,cleanupComplete:true}));
} else if(action==='show') {
 const t=await json(location);console.log(JSON.stringify(t));
} else throw Error('Expected init/trial/start/call/submit/collect/finish/show');
