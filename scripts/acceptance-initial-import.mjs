// Real-EXE recovery through the installed public entry point. No SDK/Factory fixture imports.
// Receipt/log observation and OS signals are exclusively the owned crash-injection controller.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,readdir,mkdtemp} from 'node:fs/promises';
import {join} from 'node:path';
import {homedir,tmpdir} from 'node:os';
import {createHash,randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';

const exec=promisify(execFile),o={};
for(let i=2;i<process.argv.length;i++){const key=process.argv[i];if(key==='--ack-disposable')o.ack=true;else if(key.startsWith('--')&&process.argv[i+1])o[key.slice(2)]=process.argv[++i];else throw Error('Invalid argument');}
assert.equal(o.ack,true);assert.equal(process.platform,'darwin','Normal macOS AppData/keyring acceptance');
for(const key of ['cli','input','java','ghidra-home','artifact'])assert.ok(o[key],'Missing --'+key);
assert.ok(!process.env.CI,'Local interactive keyring acceptance only');
const sha=b=>createHash('sha256').update(b).digest('hex'),inputSha=sha(await readFile(o.input));
assert.equal(inputSha,'256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282','Use the recorded production 7zr.exe');
const scenarios=o.scenario?[o.scenario]:['analysis','prepared','created','committed'];
assert.ok(scenarios.every(s=>['analysis','prepared','created','committed','legacy'].includes(s)));
if(scenarios.includes('legacy'))assert.ok(o['legacy-cli'],'Legacy migration requires --legacy-cli');
const scratch=await mkdtemp(join(tmpdir(),'insight-initial-cli-'));console.log('Owned CLI diagnostics:',scratch);
let index=0,entry=o.cli;
async function raw(args,allowFailure=false){
 const n=++index;let r,code=0;
 try{r=await exec(process.execPath,[entry,...args,'--json'],{timeout:300000,maxBuffer:2*1024*1024});}
 catch(error){r=error;code=Number(error.code)||1;}
 await writeFile(join(scratch,String(n)+'.stdout'),r.stdout??'',{mode:0o600});await writeFile(join(scratch,String(n)+'.stderr'),r.stderr??'',{mode:0o600});
 if(!allowFailure)assert.equal(code,0,'Public CLI failed; see invocation '+n+' in owned diagnostics');
 return {code,value:r.stdout?.trim()?JSON.parse(r.stdout):undefined};
}
async function wait(action,ms=240000){const end=Date.now()+ms;while(Date.now()<end){const r=await action();if(r)return r;await delay(5);}throw Error('Owned crash boundary was not reached');}
async function json(path){try{return JSON.parse(await readFile(path,'utf8'));}catch(e){if(e.code==='ENOENT')return;throw e;}}
async function killNative(pid,main,root){const command=(await exec('ps',['-p',String(pid),'-o','command='])).stdout;
 assert.ok(command.includes(main)&&command.includes(root),'Crash PID does not identify the owned helper');process.kill(pid,'SIGKILL');}
const groups=[];
for(const scenario of scenarios){
 entry=scenario==='legacy'?o['legacy-cli']:o.cli;
 const profile='initial-cli-'+randomUUID(),workspace=join(homedir(),'Library','Application Support','insight-cli',profile,'workspace');
 const call=async args=>(await raw(['--profile',profile,...args])).value;
 const owner=async()=>(await raw(['ipc-server','status'])).value;
 assert.equal((await owner()).running,false,'Finish other work sharing the normal insight-cli owner first');
 await raw(['profile','create',profile,'--java',o.java,'--ghidra-home',o['ghidra-home']]);
 await call(['permissions','grant','Update']);
 let selected,root,legacyRoot,legacyReceipt;
 try{
  const request='interrupted-'+scenario,args=['ghidra','open',o.input,'--session','new','--request-id',request];
  const owned=await owner();assert.equal(owned.running,true);
  const pending=raw(['--profile',profile,...args],true);
  const kind=scenario==='legacy'?'bootstrap':'initial';
  root=await wait(async()=>{let names;const parent=join(workspace,'ghidra-native',kind);try{names=await readdir(parent);}catch(e){if(e.code==='ENOENT')return;throw e;}
   assert.ok(names.length<=1);if(!names[0])return;
   const targetRoot=join(parent,names[0]);if(scenario!=='legacy')return targetRoot;
   for(const attempt of await readdir(targetRoot)){const path=join(targetRoot,attempt);if(await json(join(path,'process.json')))return path;}
  });
  if(scenario==='legacy'){
   const processReceipt=await json(join(root,'process.json'));assert.equal(processReceipt.kind,'bootstrap');
   await wait(async()=>{try{return (await readFile(join(root,'runtime.log'),'utf8')).includes('Applied data type archive:');}catch{}});
   await killNative(processReceipt.pid,'InsightHeadlessMain',root);legacyRoot=root;
  }else if(scenario==='analysis'){
   const progress=await wait(async()=>{const p=await json(join(root,'import.json'));return p?.phase==='importing'&&p;});
   // Wait until this real PE has entered analysis, rather than only JVM startup.
   await wait(async()=>{let dirs;try{dirs=await readdir(join(workspace,'server','calls'));}catch{return;}
    for(const d of dirs.filter(d=>d.startsWith('initial-import-'))){try{if((await readFile(join(workspace,'server','calls',d,'diagnostic.log'),'utf8')).includes('Applied data type archive:'))return true;}catch{}}
   });
   await killNative(progress.pid,'InsightInitialImport',root);
  }else if(scenario==='prepared'){
   await wait(async()=>(await json(join(root,'import.json')))?.phase==='prepared');
   process.kill(owned.pid,'SIGKILL');
  }else{
   const progress=await wait(async()=>{const p=await json(join(root,'publication.json'));return p?.phase===scenario&&p;});
   if(scenario==='created')await killNative(progress.pid,'db.InsightInitialPublication',root);
   process.kill(owned.pid,'SIGKILL');
  }
  const interrupted=await pending;assert.notEqual(interrupted.code,0,'Fault must interrupt the caller');
  const sessions=await call(['sessions','list']),targets=await call(['targets','list']);
  assert.equal(sessions.items.length,1);assert.equal(targets.items.length,1);selected={session:sessions.items[0].id,target:targets.items[0].target};
  if(scenario==='legacy'){
   legacyReceipt=sha(await readFile(join(legacyRoot,'process.json')));
   await raw(['ipc-server','stop']);entry=o.cli;
   root=join(workspace,'ghidra-native','initial',selected.target);
   assert.equal(await json(join(root,'intent.json')),undefined,'Old build must not have the new initializer receipt');
  }
  const intent=await json(join(root,'intent.json')),before=await json(join(root,'import.json'));
  if(scenario==='analysis')assert.equal(await json(join(root,'publication.json')),undefined);
  if(scenario==='prepared')assert.equal(await json(join(root,'publication.json')),undefined,'Owner was killed before first publication');
  let ready;
  await wait(async()=>{
   const r=await raw(['--profile',profile,...args],true);
   if(r.code===0){ready=r.value;return true;}
   await delay(500);return false;
  },180000);
  assert.equal(ready.state,'ready');assert.equal(ready.session,selected.session);assert.equal(ready.target,selected.target);assert.equal(ready.baseRevision,'R1');
  assert.deepEqual(Object.keys(ready).sort(),['session','target','state','baseRevision','sharedRevision','pendingChanges'].sort());
  if(scenario==='legacy')assert.equal(sha(await readFile(join(legacyRoot,'process.json'))),legacyReceipt,'Legacy stage receipt retained');
  else assert.deepEqual(await json(join(root,'intent.json')),intent,'Intent/input/authority never reset');
  const prepared=await json(join(root,'import.json')),publication=await json(join(root,'publication.json'));
  if(!['analysis','legacy'].includes(scenario))assert.equal(prepared.snapshotSha256,before.snapshotSha256,'Completed analysis must be reused');
  const server=await call(['ghidra','server','status']),files=await call(['ghidra','server','repositories','files','--repository',server.repository]);
  const canonical=files.files.filter(f=>f.name===selected.target+'.bin');assert.equal(canonical.length,1);const path=canonical[0].path;
  const history=await call(['ghidra','server','history','--repository',server.repository,'--path',path]);
  assert.equal(history.versions.length,1);assert.equal(history.versions[0].version,1);
  const selectors=['--session',selected.session,'--target',selected.target];
  const strings=await call(['ghidra','strings','search',...selectors,'--contains','Unknown switch:']);assert.ok(strings.items.some(x=>x.address==='0x47c2ac'));
  assert.deepEqual(await call(args),ready,'Repeat returns the same successful open');
  assert.equal((await json(join(root,'publication.json'))).createCalls,publication.createCalls,'Replay never issues another create');
  await call(['ghidra','comments','set',...selectors,'--address','0x40125a','--kind','plate','--text','Recovered first import: '+scenario,'--request-id','annotate']);
  const merge=await call(['ghidra','merge',...selectors,'--request-id','merge']);assert.equal(merge.sharedRevision,'R2');
  const reader=await call(['ghidra','open',o.input,'--session','new','--request-id','reader']);
  assert.equal(reader.baseRevision,'R2');const read=await call(['ghidra','comments','get','--session',reader.session,'--target',reader.target,'--address','0x40125a','--kind','plate']);
  assert.equal(read.text,'Recovered first import: '+scenario);
  await call(['ghidra','close','--session',reader.session,'--target',reader.target]);
  await call(['ghidra','close',...selectors]);
  groups.push({scenario,state:'passed',sameSessionTargetAndIntent:true,preparedSnapshotReused:!['analysis','legacy'].includes(scenario),...(scenario==='legacy'?{legacyBootstrapRetained:true}:{}),firstVersions:1,stagingCreateCalls:publication.createCalls,
   privateAttempts:(await readdir(root)).filter(n=>/^attempt-.*\.gzf\.json$/.test(n)).length,readStringAddress:'0x47c2ac',mergeRevision:'R2',independentReaderVerified:true,publicReadyEnvelope:true});
  console.log('Public CLI initial recovery passed:',scenario);
 }finally{
  await raw(['--profile',profile,'ghidra','server','disconnect'],true);await raw(['ipc-server','stop'],true);
 }
}
assert.equal(sha(await readFile(o.input)),inputSha);
const report={schema:1,state:'passed',completedAt:new Date().toISOString(),scope:'Installed public CLI; real production 7zr.exe; normal Factory owner, AppData and keyring; OS-only owned crash injection',
 artifactSha256:sha(await readFile(o.artifact)),inputSha256:inputSha,ghidra:'12.1.2',node:process.versions.node,groups,
 limitations:['macOS headless static PE only','private receipts/logs observed solely to inject exact owned crashes','no hidden runtime hooks, SDK or bridge calls in research/recovery workflow']};
await writeFile(join(scratch,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
