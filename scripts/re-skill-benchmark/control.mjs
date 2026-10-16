// Test-only live-agent benchmark. Program operations exclusively spawn the installed public CLI.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,appendFile,copyFile,readdir,statfs} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {PublicCli,json,save} from '../business/public-cli.mjs';
import {bindings} from '../business/cases.mjs';
const home=fileURLToPath(new URL('./',import.meta.url)),protocol=await json(join(home,'protocol.json'));
const [action,location,...args]=process.argv.slice(2),sha=b=>createHash('sha256').update(b).digest('hex');
const stamp=()=>({monotonicNs:process.hrtime.bigint().toString(),utc:new Date().toISOString()});
const elapsed=(a,b)=>Number(BigInt(b.monotonicNs)-BigInt(a.monotonicNs))/1e9;
const address=a=>BigInt(/^0x/i.test(a)?a:'0x'+a);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');assert.ok(!process.env.CI);
const part=id=>{const p=protocol.parts.find(p=>p.id===id);assert.ok(p);return p;};
const event=(t,value)=>appendFile(join(t.directory,'events.jsonl'),JSON.stringify(value)+'\n',{mode:0o600});
async function span(t,actor,category,operation,fn){
 const id=randomUUID(),at=stamp();await event(t,{id,actor:String(actor),category,operation,phase:'start',at});
 try{const result=await fn();await event(t,{id,actor:String(actor),category,operation,phase:'end',at:stamp(),ok:true});return result;}
 catch(error){await event(t,{id,actor:String(actor),category,operation,phase:'end',at:stamp(),ok:false,code:'public-cli-or-assertion.failed'});throw error;}
}
async function client(t,actor,category){
 const m=await json(t.manifest),cli=new PublicCli(m,join(t.directory,'calls',String(actor),randomUUID()),t.profile),call=cli.call.bind(cli);
 cli.category=category;cli.call=(argv,options)=>span(t,actor,cli.category,argv[0]==='ghidra'&&argv[1]==='open'&&argv.includes('--target')?'fresh-open':argv.slice(argv[0]==='ghidra'?1:0,argv[0]==='ghidra'?3:2).join(' '),()=>call(argv,options));return cli;
}
function assigned(t,actor,id){part(id);assert.ok(Number.isInteger(Number(actor))&&Number(actor)>=0&&Number(actor)<t.workers);assert.ok(t.workers===1||protocol.parts[Number(actor)].id===id);assert.equal(t.state,'researching');}
async function tree(path){const entries=[];async function walk(folder,prefix=''){for(const e of (await readdir(folder,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){const name=prefix+e.name;assert.ok(e.isDirectory()||e.isFile());entries.push(e.isDirectory()?{path:name,kind:'directory'}:{path:name,sha256:sha(await readFile(join(folder,e.name)))});if(e.isDirectory())await walk(join(folder,e.name),name+'/');}}await walk(path);return entries;}
function uncomment(code){let out='',state='code';for(let i=0;i<code.length;i++){const c=code[i],n=code[i+1];if(state==='line'){if(c==='\n'){state='code';out+=' ';}continue;}if(state==='block'){if(c==='*'&&n==='/'){state='code';i++;out+=' ';}continue;}if(state==='string'||state==='char'){out+=c;if(c==='\\'){out+=n??'';i++;}else if(c===(state==='string'?'"':"'"))state='code';continue;}if(c==='/'&&n==='/'){state='line';i++;continue;}if(c==='/'&&n==='*'){state='block';i++;continue;}if(c==='"')state='string';else if(c==="'")state='char';out+=c;}return out.replace(/\s+/g,' ').trim();}
async function identities(m){const result={};for(const name of ['protocol.json','AGENT-TASK.md','oracle.json','control.mjs','analyze.py','observer.mjs'])result[name]=sha(await readFile(join(home,name)));for(const name of ['../business/public-cli.mjs','../business/cases.mjs'])result[name]=sha(await readFile(join(home,name)));result.installedArtifact=sha(await readFile(m.artifact));result.installedSkill=sha(await readFile(m.skill));return result;}
async function nativeProof(t){
 const events=(await readFile(join(t.directory,'events.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),samples=(await readFile(join(t.directory,'native-observations.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
 assert.ok(samples.length>1);const firstReads=[],done=[];for(let actor=0;actor<t.workers;actor++){const rows=events.filter(e=>e.actor===String(actor));firstReads.push(rows.find(e=>e.category==='read'&&e.phase==='start').at);done.push(rows.find(e=>e.category==='marker'&&e.operation==='done').at);}
 const begin=firstReads.reduce((a,b)=>BigInt(a.monotonicNs)>BigInt(b.monotonicNs)?a:b),end=done.reduce((a,b)=>BigInt(a.monotonicNs)<BigInt(b.monotonicNs)?a:b),common=samples.filter(s=>BigInt(s.monotonicNs)>=BigInt(begin.monotonicNs)&&BigInt(s.monotonicNs)<=BigInt(end.monotonicNs));
 const cpuBefore=samples[0].cpu,cpuAfter=samples.at(-1).cpu;assert.ok(t.native.every(n=>cpuAfter[n.pid]>cpuBefore[n.pid]));
 const proof={distinctWorkers:t.native.length,overlapSeconds:elapsed(begin,end),cpuBefore,cpuAfter,samples:samples.length};if(t.workers===3){assert.ok(proof.overlapSeconds>0);assert.ok(common.length>1);proof.commonWindow={first:common[0],last:common.at(-1),allWorkersCpuGrew:t.native.every(n=>common.at(-1).cpu[n.pid]>common[0].cpu[n.pid])};assert.equal(proof.commonWindow.allWorkersCpuGrew,true);}return proof;
}
if(action==='init'){
 const [installed,input]=args,artifact=join(installed,'artifacts/ixab3r-insight-cli-0.1.0.tgz'),cli=join(installed,'node_modules/@ixab3r/insight-cli/dist/src/bin.js'),skill=join(installed,'node_modules/@ixab3r/insight-cli/skills/insight-re/SKILL.md');
 await mkdir(location,{mode:0o700});await mkdir(join(location,'input'));assert.equal(sha(await readFile(input)),protocol.inputSha256);await copyFile(input,join(location,'input/7zr.exe'));
 const m={directory:resolve(location),cli,artifact,skill,artifactSha256:sha(await readFile(artifact)),skillSha256:sha(await readFile(skill)),java:'/opt/homebrew/opt/openjdk@21/bin/java',ghidra:'/opt/homebrew/opt/ghidra/libexec',inputs:[{path:resolve(location,'input/7zr.exe'),sha256:protocol.inputSha256}]};m.frozen=await identities(m);
 await save(join(location,'manifest.json'),m);await save(join(location,'protocol.json'),protocol);console.log(JSON.stringify({artifactSha256:m.artifactSha256,frozen:m.frozen}));
}else if(action==='trial'){
 const [name,count]=args,m=await json(join(location,'manifest.json')),workers=Number(count);assert.ok([1,3].includes(workers));assert.deepEqual(await identities(m),m.frozen);const disk=await statfs(location);assert.ok(Number(disk.bavail)*Number(disk.bsize)>40*1024**3,'At least 40GiB free required before a trial');
 const t={name,workers,directory:resolve(location,name),manifest:resolve(location,'manifest.json'),profile:'reskill-bench-'+randomUUID(),scopes:[],native:[],setupStarted:stamp(),state:'preparing',freeBytesBefore:Number(disk.bavail)*Number(disk.bsize)};await mkdir(t.directory,{mode:0o700});await mkdir(join(t.directory,'checkpoints'));await mkdir(join(t.directory,'receipts'));
 for(const p of protocol.parts)await mkdir(join(t.directory,'research',p.id,'raw'),{recursive:true});await save(join(t.directory,'trial.json'),t);const cli=await client(t,'setup','setup');await cli.setup();t.firstOpenStarted=stamp();
 for(let i=0;i<workers;i++){t.scopes.push(await cli.open());await save(join(t.directory,'trial.json'),t);}
 const native=await bindings(cli,t.scopes[0].target);assert.equal(native.length,workers);assert.equal(new Set(native.map(n=>n.root)).size,workers);t.native=native.map(({pid,session,target,root})=>({pid,session,target,ownedRootSha256:sha(root)}));
 t.ready=stamp();t.setupSeconds=elapsed(t.setupStarted,t.ready);t.preparedOpenSeconds=elapsed(t.firstOpenStarted,t.ready);t.state='ready';await save(join(t.directory,'trial.json'),t);console.log(JSON.stringify({trial:join(t.directory,'trial.json'),workers,setupSeconds:t.setupSeconds,preparedOpenSeconds:t.preparedOpenSeconds,skill:m.skill,scopes:t.scopes}));
}else if(action==='start'){
 const t=await json(location);assert.equal(t.state,'ready');t.dispatched=stamp();t.state='researching';await save(location,t);const observer=spawn(process.execPath,[join(home,'observer.mjs'),resolve(location)],{detached:true,stdio:'ignore'});observer.unref();console.log(JSON.stringify({dispatched:t.dispatched}));
}else if(action==='mark'){
 const [actor,operation]=args,t=await json(location);assert.equal(t.state,'researching');assert.ok(/^(ready|done|writing:(switches|password|extraction)|written:(switches|password|extraction))$/.test(operation));
 if(operation==='done')for(const p of (t.workers===1?protocol.parts:[protocol.parts[Number(actor)]]))assert.ok(await json(join(t.directory,'checkpoints',p.id+'.json')));
 await event(t,{actor:String(actor),category:'marker',operation,phase:'point',at:stamp()});console.log(JSON.stringify({marked:operation}));
}else if(action==='call'){
 const [actor,id,...argv]=args,t=await json(location);assigned(t,actor,id);const operation=argv.slice(0,2).join(' ');assert.ok(['strings search','xrefs to','xrefs from','functions get','functions search','functions decompile','functions disassemble','functions inspect','memory read','analysis get-function-pcode'].includes(operation));assert.ok(!argv.some(a=>['--session','--target','--profile','--program'].includes(a)));
 const cli=await client(t,actor,'read'),value=await cli.scoped(t.scopes[Number(actor)],operation,argv.slice(2)),raw=join(t.directory,'research',id,'raw',randomUUID()+'.json');await save(raw,value);console.log(JSON.stringify({raw,result:value}));
}else if(action==='checkpoint'){
 const [actor,id,entry]=args,t=await json(location);assigned(t,actor,id);assert.match(entry,/^0x[0-9a-f]+$/i);const folder=join(t.directory,'research',id),note=await readFile(join(folder,'finding.md'),'utf8');assert.ok(note.length>=200&&note.length<=6000);const text=`research/${id}/finding.md\n${note}`,cli=await client(t,actor,'annotation');
 const comment=await cli.comment(t.scopes[Number(actor)],entry,text);assert.equal(comment.state,'applied');await save(join(folder,'annotation.json'),comment);cli.category='artifacts';const receipt=await cli.call(['artifacts','save',folder]);assert.equal(receipt.state,'saved');assert.deepEqual(await tree(folder),await tree(receipt.path));await save(join(t.directory,'receipts',id+'.json'),receipt);
 await save(join(t.directory,'checkpoints',id+'.json'),{actor:Number(actor),entry,text,noteSha256:sha(note),at:stamp()});console.log(JSON.stringify({part:id,state:'saved-private',receipt}));
}else if(action==='collect'){
 const t=await json(location);assert.equal(t.state,'researching');const m=await json(t.manifest);assert.deepEqual(await identities(m),m.frozen);t.researchFinished=stamp();t.state='collecting';await save(location,t);t.nativeProof=await nativeProof(t);const cli=await client(t,'lead','collection'),lead=t.scopes[0],checkpoints={};
 for(const p of protocol.parts){const c=await json(join(t.directory,'checkpoints',p.id+'.json'));const actual=await cli.readComment(t.scopes[c.actor],c.entry);assert.equal(actual,c.text);if(c.actor!==0)await cli.comment(lead,c.entry,c.text);checkpoints[p.id]=c;}
 t.collected=stamp();cli.category='merge';t.merge=await cli.scoped(lead,'merge');assert.equal(t.merge.state,'merged');assert.equal(t.merge.sharedRevision,'R2');t.merged=stamp();t.state='verifying';await save(location,t);cli.category='verification';const reader=await cli.fresh(lead.target);t.reader=reader;await save(location,t);
 const oracle=await json(join(home,'oracle.json')),codes={},proof={};for(const p of protocol.parts){const c=checkpoints[p.id],o=oracle[p.id];assert.equal(address(c.entry),address(o.entry));assert.equal(await cli.readComment(reader,c.entry),c.text);
  const strings=await cli.scoped(reader,'strings search',['--contains',o.clue,'--limit','100']);assert.ok(strings.items.some(s=>address(s.address)===address(o.string)&&s.text.includes(o.clue)));
  let destination=o.string,last;for(const from of o.hops){const refs=await cli.scoped(reader,'xrefs to',['--address',destination,'--limit','100']);last=refs.items.find(r=>r.from&&address(r.from)===address(from));assert.ok(last);destination=from;}assert.equal(address(last.function.address),address(o.entry));
  for(const [entry,fragments] of [[o.entry,o.code],...Object.entries(o.helpers)]){const v=await cli.scoped(reader,'functions decompile',['--address',entry]);assert.equal(v.truncated,false);codes[entry]=v.code;for(const fragment of fragments)assert.ok(uncomment(v.code).includes(fragment),'Independent code fragment absent at '+entry+': '+fragment);}
  proof[p.id]={entry:c.entry,noteSha256:c.noteSha256,clueAndReferenceChain:true,nativeCode:true};
 }
 const history=await cli.history(lead.target);assert.deepEqual(history.versions.map(v=>v.version).sort(),[1,2]);t.historyVersions=[1,2];t.proof=proof;t.checkpoints=checkpoints;await save(join(t.directory,'independent-code.json'),codes);t.verified=stamp();t.state='awaiting-semantic-review';await save(location,t);console.log(JSON.stringify({state:t.state,secondsBeforeReview:elapsed(t.dispatched,t.verified),proof}));
}else if(action==='finish'){
 const t=await json(location),review=await json(args[0]);assert.equal(t.state,'awaiting-semantic-review');assert.deepEqual(Object.keys(review.criteria).sort(),protocol.parts.map(p=>p.id).sort());assert.ok(Object.values(review.criteria).every(v=>v===true));assert.ok(review.explanation.length>80);
 const m=await json(t.manifest);assert.deepEqual(await identities(m),m.frozen);assert.equal(sha(await readFile(m.inputs[0].path)),protocol.inputSha256);const cli=await client(t,'lead','summary');
 const notes='# 7zr.exe accepted research\n\n'+protocol.question+'\n\nInput SHA256 '+protocol.inputSha256+'. Static analysis; target never executed.\n\n'+protocol.parts.map(p=>'- ['+p.id+']('+p.id+'/finding.md)').join('\n')+'\n\nAll three private findings were collected and published once as R2. A fresh session independently read the annotations, clue/reference chains and actual native code. Repository history: R1/R2.\n\nLead review: '+review.explanation+'\n';
 await writeFile(join(t.directory,'research/notes.md'),notes);t.materials=await cli.call(['artifacts','save',join(t.directory,'research')]);assert.deepEqual(await tree(join(t.directory,'research')),await tree(t.materials.path));t.review=review;t.finished=stamp();t.elapsedSeconds=elapsed(t.dispatched,t.finished);t.state='passed';await save(location,t);
 cli.category='cleanup';const sessions=await cli.call(['sessions','list']);for(const s of sessions.items)await cli.close({session:s.id,target:t.scopes[0].target});await cli.call(['ghidra','server','disconnect']);t.cleanupComplete=true;const disk=await statfs(t.directory);t.freeBytesAfter=Number(disk.bavail)*Number(disk.bsize);await save(location,t);console.log(JSON.stringify({state:t.state,elapsedSeconds:t.elapsedSeconds,cleanupComplete:true}));
}else throw Error('Expected init/trial/start/call/mark/checkpoint/collect/finish. Never blindly retry a publication after failure.');
