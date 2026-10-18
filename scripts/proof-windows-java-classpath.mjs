// Installed public CLI only. Raw output stays in a separate, caller-owned transcript directory.
import assert from 'node:assert/strict';
import {parseArgs,promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {exportsOf} from './business/prepare.mjs';
const {values:o}=parseArgs({options:{cli:{type:'string'},input:{type:'string'},output:{type:'string'},transcripts:{type:'string'},profile:{type:'string'},session:{type:'string'},'skip-install':{type:'boolean'},'ack-disposable':{type:'boolean'}}});
assert.equal(process.platform,'win32');assert.equal(o['ack-disposable'],true);assert.ok(!process.env.CI);
for(const key of ['cli','input','output','transcripts'])assert.ok(o[key],key+' required');
assert.ok(!o['skip-install']||o.profile,'Existing owned profile required to skip installation');
assert.ok(!o.session||o['skip-install'],'Resume only an existing disposable managed installation');
const cli=resolve(o.cli),input=resolve(o.input),output=resolve(o.output),raw=resolve(o.transcripts),profile=o.profile??'i56-'+randomUUID().slice(0,8);
assert.match(profile,/^(?:issue56|i56)-[a-z0-9-]+$/);assert.ok(!cli.includes('dist/src/bin.ts'));
await mkdir(dirname(raw),{recursive:true});await mkdir(raw,{mode:0o700});await mkdir(dirname(output),{recursive:true});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex'),bytes=await readFile(input),inputSha256=sha(bytes),exports=exportsOf(bytes);
assert.ok(exports.config_read&&exports.evidence_config,'Use the public tests/acceptance/fixtures/research.c VERSION=1 PE');
const exec=promisify(execFile),scopes=[],calls=[],checks={};let sequence=0,installed,ownsProfile=o['skip-install']===true;
const report={schema:1,state:'running',scope:'Windows managed Ghidra long-classpath install and bounded synthetic PE research; no wider toolbox acceptance',installation:o['skip-install']?'existing-disposable-managed-selection':'fresh-managed-install',resumedScope:Boolean(o.session),node:process.version,platform:process.platform,architecture:process.arch,inputSha256,checks,calls};
async function call(args,{global=false,json=true}={}){
 const n=++sequence,started=Date.now();let result,code=0;
 try{result=await exec(process.execPath,[cli,...(global?[]:['--profile',profile]),...args,...(json?['--json']:[])],{timeout:1200000,maxBuffer:8*1024*1024});}
 catch(error){result=error;code=typeof error.code==='number'?error.code:1;}
 await writeFile(join(raw,n+'.stdout'),result.stdout??'');await writeFile(join(raw,n+'.stderr'),result.stderr??'');
 calls.push({operation:args.slice(0,2).join(' '),code,milliseconds:Date.now()-started});
 assert.equal(code,0,'CLI failed; inspect transcript '+n+' before any retry');return json?JSON.parse(result.stdout):result.stdout.trim();
}
const scoped=(s,args)=>call(['ghidra',...args,'--session',s.session,'--target',s.target]);
async function open(args,session='new'){const s=await call(['ghidra','open',...args,'--session',session]);assert.equal(s.state,'ready');scopes.push(s);return s;}
try{
 report.version=await call(['--version'],{global:true,json:false});
 report.installedPackageSha256=sha(await readFile(join(dirname(cli),'../../package.json')));
 if(!o['skip-install']){await call(['profile','create',profile],{global:true});ownsProfile=true;await call(['permissions','grant','Update']);installed=await call(['ghidra','install']);}
 else installed=await call(['ghidra','status']);
 assert.equal(installed.mode,'managed');checks.managedRuntime=true;
 const a=await open([input],o.session??'new');assert.equal(a.sharedRevision,'R1');
 const strings=await scoped(a,['strings','search','--contains','insight-config-v1.json']);assert.ok(strings.items.some(s=>s.address===exports.evidence_config));
 const refs=await scoped(a,['xrefs','to','--address',exports.evidence_config]);assert.ok(refs.items.some(r=>r.function?.address===exports.config_read));
 const code=await scoped(a,['functions','decompile','--address',exports.config_read]);assert.equal(code.truncated,false);assert.match(code.code,/case1/);checks.nativeResearch=true;
 const b=await open(['--target',a.target]),at=exports.config_read,text='Windows long-classpath synthetic acceptance';
 await scoped(a,['comments','set','--address',at,'--kind','plate','--text',text]);
 const read=s=>scoped(s,['comments','get','--address',at,'--kind','plate']);
 assert.equal((await read(b)).text,null);checks.privateIsolation=true;
 assert.equal((await scoped(a,['merge'])).sharedRevision,'R2');
 const reader=await open(['--target',a.target]);assert.equal((await read(reader)).text,text);checks.independentReadback=true;
 assert.equal((await read(b)).text,null);await scoped(b,['refresh']);assert.equal((await read(b)).text,text);checks.refresh=true;
 const records=await call(['tools','processes','--tool','ghidra','--all','--limit','1000']);
 assert.equal(records.truncated,false);const files=[];
 for(const r of records.items){try{const content=await readFile(join(r.root,'java-classpath.args'),'utf8');files.push({role:r.role,state:r.state,outcome:r.outcome,bytes:Buffer.byteLength(content),classpathCharacters:JSON.parse(content.trim().split('\n')[1]).length});}catch(error){if(error.code!=='ENOENT')throw error;}}
 assert.ok(files.some(r=>r.role==='compile-helpers'&&r.outcome==='completed'&&r.classpathCharacters>28000));
 assert.ok(files.some(r=>r.role!=='compile-helpers'&&r.state!=='failed'));report.argumentFiles=files;checks.supervisedLongClasspath=true;
 assert.equal(sha(await readFile(input)),inputSha256);checks.unchangedSyntheticInput=true;
 report.state='passed';
}catch(error){report.state='failed';throw error;}
finally{
 const errors=[];for(const s of scopes.reverse())try{await scoped(s,['close']);}catch{errors.push('context close');}
 if(ownsProfile)try{await call(['ghidra','server','stop']);}catch{errors.push('server stop');}
 // Factory's IPC owner serves multiple profiles; its idle policy owns that lifecycle.
 checks.ownedCleanup=errors.length===0;if(errors.length){report.state='failed';report.cleanupErrors=errors;}
 await writeFile(output,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({state:report.state,checks}));
 if(report.state!=='passed')process.exitCode=1;
}
