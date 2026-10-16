// Opt-in installed executable proof. Ordinary public CLI, owned disposable profile only.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,mkdir,writeFile,readFile,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
const exec=promisify(execFile),[executable,input,output]=process.argv.slice(2);
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.equal(process.platform,'darwin');
assert.ok(executable&&input&&output,'Executable, exact 7zr.exe and output JSON required');
const inputBytes=await readFile(input),inputSha256=createHash('sha256').update(inputBytes).digest('hex');
assert.equal(inputSha256,'256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282');
const directory=await realpath(await mkdtemp('/tmp/insight-global-proof-')),profile='npm-proof-'+randomUUID(),calls=[],scopes=[];
let sequence=0;
async function call(argv,{global=false,json=true}={}){
 const n=++sequence,started=process.hrtime.bigint();let result,code=0;
 try{result=await exec(executable,[...(global?[]:['--profile',profile]),...argv,...(json?['--json']:[])],{cwd:directory,timeout:600000,maxBuffer:8*1024*1024});}
 catch(e){result=e;code=Number(e.code)||1;}
 await writeFile(join(directory,n+'.stdout'),result.stdout??'',{mode:0o600});await writeFile(join(directory,n+'.stderr'),result.stderr??'',{mode:0o600});
 calls.push({operation:argv.slice(0,3).join(' '),code,seconds:Number(process.hrtime.bigint()-started)/1e9});
 assert.equal(code,0,'Global CLI failed; inspect owned transcript '+directory+'/'+n);return json?JSON.parse(result.stdout):result.stdout;
}
const scopeArgs=s=>['--session',s.session,'--target',s.target],scoped=(s,words,args=[])=>call(['ghidra',...words.split(' '),...scopeArgs(s),...args]);
const report={schema:1,package:'@eyeauras/insight-cli',version:'0.1.0',node:process.version,platform:process.platform,architecture:process.arch,inputSha256,checks:{},calls};
try{
 assert.match(await call(['--help'],{global:true,json:false}),/insight-cli/);assert.match(await call(['--version'],{global:true,json:false}),/0\.1\.0/);report.checks.executableHelpAndVersion=true;
 const skill=await call(['skill','insight-re'],{global:true});assert.equal(skill.name,'insight-re');assert.match(skill.path,/node_modules\/@eyeauras\/insight-cli\//);assert.match(await readFile(skill.path,'utf8'),/Follow the project contract/);report.checks.installedSkill=true;
 await call(['profile','create',profile,'--java','/opt/homebrew/opt/openjdk@21/bin/java','--ghidra-home','/opt/homebrew/opt/ghidra/libexec'],{global:true});await call(['permissions','grant','Update']);
 const materials=join(directory,'analysis spaces-Ω');await mkdir(materials);await writeFile(join(materials,'existing.evidence.md'),'Project format and canonical path retained.\n');await writeFile(join(materials,'empty.txt'),'');
 const folder=await call(['artifacts','save',materials]),file=await call(['artifacts','save',join(materials,'existing.evidence.md')]);assert.equal(folder.files,2);assert.equal(file.kind,'file');await writeFile(join(materials,'existing.evidence.md'),'Later source edit');assert.equal(await readFile(join(folder.path,'existing.evidence.md'),'utf8'),'Project format and canonical path retained.\n');assert.equal(await readFile(file.path,'utf8'),'Project format and canonical path retained.\n');report.checks.fileAndFolderSaves=true;
 const first=await call(['ghidra','open',input,'--session','new']);assert.equal(first.state,'ready');assert.equal(first.sharedRevision,'R1');scopes.push(first);
 const strings=await scoped(first,'strings search',['--contains','CRC Failed','--limit','30']);let at=strings.items.find(s=>s.text==='CRC Failed')?.address;assert.ok(at);let functionAddress;
 for(let depth=0;depth<3&&!functionAddress;depth++){const refs=await scoped(first,'xrefs to',['--address',at,'--limit','30']);const inside=refs.items.find(r=>r.function?.address);if(inside)functionAddress=inside.function.address;else at=refs.items.find(r=>r.from)?.from;assert.ok(functionAddress||at);}
 assert.ok(functionAddress);const code=await scoped(first,'functions decompile',['--address',functionAddress]);assert.equal(code.truncated,false);assert.match(code.code,/CRC Failed|DAT_0047f6b0/);assert.match(code.code,/case 3/);report.checks.realGhidraResearch=true;
 const text='Global npm installation verified through public insight-cli: CRC diagnostic selector code inspected; static analysis only.';
 const edit=await scoped(first,'comments set',['--address',functionAddress,'--kind','plate','--text',text]);assert.equal(edit.state,'applied');const merge=await scoped(first,'merge');assert.equal(merge.state,'merged');assert.equal(merge.sharedRevision,'R2');
 const fresh=await call(['ghidra','open','--target',first.target,'--session','new']);scopes.push(fresh);assert.equal(fresh.state,'ready');assert.equal((await scoped(fresh,'comments get',['--address',functionAddress,'--kind','plate'])).text,text);
 const freshCode=await scoped(fresh,'functions decompile',['--address',functionAddress]);assert.equal(freshCode.truncated,false);assert.match(freshCode.code,/case 3/);report.checks.mergeAndFreshReadback=true;report.sharedRevision=merge.sharedRevision;report.entry=functionAddress;
 assert.equal(createHash('sha256').update(await readFile(input)).digest('hex'),inputSha256);report.checks.unchangedInput=true;
 for(const scope of [...scopes].reverse())await scoped(scope,'close');await call(['ghidra','server','disconnect']);report.checks.ownedNativeCleanup=true;report.state='passed';
}catch(e){report.state='failed';report.failure='Inspect retained local transcripts; do not blindly repeat a possibly published mutation.';throw e;}
finally{await writeFile(join(directory,'calls.json'),JSON.stringify(calls,null,2)+'\n',{mode:0o600});await writeFile(output,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({state:report.state,checks:report.checks,transcripts:directory}));}
