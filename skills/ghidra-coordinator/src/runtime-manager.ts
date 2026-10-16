import {command,Permission,CliError,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {readFile,mkdir,rename,rm,open,realpath,readdir,stat,cp} from 'node:fs/promises';
import {existsSync,constants} from 'node:fs';
import {join,dirname,resolve,delimiter,basename} from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {runtimeRoot,runtimeSelection,runtimeValues,type RuntimeSelection} from './runtime-selection.js';
import {runtimeCatalog,type RuntimeArtifact} from './runtime-catalog.js';
import {cacheArtifact,extractArchive,fileSha256} from './tool-runtime/archives.js';
import {nativeInputs,nativeHelpers,nativeJvmDirectories,pinnedMcpJar,type NativeInputs} from './native-inputs.js';
import {GhidraServer,stopLocalServer} from './server.js';
import {fail,text,digest,object} from './model.js';
const exec=promisify(execFile),suffix=process.platform==='win32'?'.exe':'';
export async function runtimeWrite(path:string,value:unknown){
 await mkdir(dirname(path),{recursive:true,mode:0o700});const temporary=path+'.new-'+randomUUID(),handle=await open(temporary,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(value,null,2)+'\n');await handle.sync();}finally{await handle.close();}
 await rename(temporary,path);
 if(process.platform!=='win32'){const parent=await open(dirname(path),'r');try{await parent.sync();}finally{await parent.close();}}
}
const live=(pid:unknown)=>{if(!Number.isSafeInteger(pid)||Number(pid)<1)return false;try{process.kill(Number(pid),0);return true;}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH')return false;throw error;}};
/** Passive, conservative inventory: a reused PID blocks deletion; it never grants kill authority. */
export async function runtimeProcesses(directory:string){
 const items:Record<string,unknown>[]=[];
 async function walk(path:string,depth=0):Promise<void>{if(depth>6)return;let entries;try{entries=await readdir(path,{withFileTypes:true});}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
  for(const entry of entries){const at=join(path,entry.name);if(entry.isDirectory())await walk(at,depth+1);else if(entry.name==='process.json'){
   const p=object(JSON.parse(await readFile(at,'utf8')));let stopped=false;try{const s=object(JSON.parse(await readFile(join(path,'stopped.json'),'utf8')));stopped=s.pid===p.pid&&s.tokenSecret===p.tokenSecret;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
   if(!stopped&&live(p.pid))items.push({kind:p.kind,pid:p.pid,sessionContext:p.context,target:p.target,mode:p.mode});
  }}
 }
 await walk(join(directory,'workspace','ghidra-native'));
 try{const s=object(JSON.parse(await readFile(join(directory,'workspace/server/local.json'),'utf8')));if(live(s.pid))items.push({kind:'server',pid:s.pid});}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 return items;
}
export async function externalGhidra(path:string){
 const resolved=await realpath(path),kind=await stat(resolved);
 const parent=kind.isDirectory()?resolved:dirname(dirname(resolved));
 const candidates=kind.isDirectory()?[resolved,join(resolved,'libexec')]:[dirname(resolved),parent,join(parent,'libexec')];
 for(const home of candidates)if(existsSync(join(home,'Ghidra/application.properties'))){
  if(!kind.isDirectory()&&!['ghidraRun','ghidraRun.bat','analyzeHeadless','analyzeHeadless.bat'].includes(basename(resolved)))fail('configuration','Use the Ghidra launcher or installation directory, not a target EXE.');
  return home;
 }
 fail('configuration','The external path does not identify a complete Ghidra installation. Use its ghidraRun launcher or installation directory.');
}
async function findRoot(root:string,marker:string,depth=0):Promise<string|undefined>{
 if(existsSync(join(root,marker)))return root;if(depth>=4)return;
 for(const entry of await readdir(root,{withFileTypes:true}))if(entry.isDirectory()){const found=await findRoot(join(root,entry.name),marker,depth+1);if(found)return found;}
}
export class RuntimeManager {
 readonly directory:string;readonly root:string;
 constructor(private readonly c:CommandContext){this.directory=c.appArguments.AppDataDirectory;this.root=runtimeRoot(this.directory);}
 async status(){
  const selected=runtimeSelection(this.directory),values=selected?runtimeValuesForStatus(selected,this.c.profile.values):this.c.profile.values;
  const java=typeof values.java==='string'?values.java:undefined,home=typeof values.ghidraHome==='string'?values.ghidraHome:undefined;
  const missing=[];if(!java||!existsSync(java))missing.push('jdk');if(!home||!existsSync(join(home,'Ghidra/application.properties')))missing.push('ghidra');
  if(selected?.uninstalledAt)missing.push('uninstalled');
  if(selected?.mode==='managed'&&!existsSync(join(this.root,'installations',selected.id!,'ready.json')))missing.push('installation_receipt');
  let version:string|undefined;if(home)try{version=/^application.version=(.+)$/m.exec(await readFile(join(home,'Ghidra/application.properties'),'utf8'))?.[1]?.trim();}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  const host=process.platform==='darwin'?(process.arch==='arm64'?'mac_arm_64':'mac_x86_64'):process.platform==='win32'?'win_x86_64':'linux_x86_64';
  const native=home?join(home,'Ghidra/Features/Decompiler/os',host,'decompile'+suffix):undefined;
  if(home&&(!native||!existsSync(native)))missing.push('decompiler');if(version&&version!=='12.1.2')missing.push('compatible_ghidra');
  let lastCheck;try{lastCheck=JSON.parse(await readFile(join(this.root,'last-check.json'),'utf8'));}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  const installations=[];let stages:string[]=[];
  try{for(const name of (await readdir(join(this.root,'installations'))).slice(0,100)){if(!/^[a-f0-9]{64}$/.test(name))continue;const path=join(this.root,'installations',name);
   if(existsSync(join(path,'ready.json'))){const ready=object(JSON.parse(await readFile(join(path,'ready.json'),'utf8')));installations.push({id:name,selected:name===selected?.id,ghidraVersion:ready.ghidraVersion,verifiedAt:ready.verifiedAt});}}}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  try{stages=(await readdir(join(this.root,'stages'))).slice(0,100);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  const processes=await runtimeProcesses(this.directory),server=processes.find(p=>p.kind==='server');
  return {state:missing.length?'not_ready':'installed',mode:selected?.mode??(home||java?'external':'unconfigured'),recommended:'managed',ghidraVersion:version,java,ghidraHome:home,
   ...(selected?{installation:selected.id,fingerprint:selected.fingerprint}:{}),missing,capabilities:{headless:!missing.length,decompiler:!missing.length,gui:!missing.length,
   debugger:process.platform==='darwin'?{backend:'system-lldb',requires:'Apple developer tools and OS debugger authorization',checkedBy:'ghidra doctor'}:{backend:'host-debugger',checkedBy:'ghidra doctor'}},
   server:{mode:this.c.profile.values.server?'external':'local',state:this.c.profile.values.server?'configured':server?'running':'stopped',...(server?{pid:server.pid}:{})},processes,installations,retainedStages:stages,lastCheck:lastCheck?{...lastCheck,appliesToSelection:lastCheck.fingerprint===selected?.fingerprint&&!selected?.uninstalledAt}:undefined,
   storage:{runtime:this.root,research:join(this.directory,'workspace'),materials:join(this.directory,'materials')}};
 }
 async download(offline=false){
  const catalog=runtimeCatalog(),cache=join(this.root,'cache'),items=[];
  for(const artifact of [catalog.ghidra,catalog.java]){const path=await cacheArtifact(artifact,cache,this.c.fetch,this.c.signal,offline);items.push({name:artifact.name,path,sha256:artifact.sha256,license:artifact.license});}
  return {state:'downloaded',ghidraVersion:catalog.ghidraVersion,javaVersion:catalog.javaVersion,items};
 }
 private async archive(artifact:RuntimeArtifact,provided:unknown,checksum:unknown,offline:boolean){
  if(provided===undefined)return {path:await cacheArtifact(artifact,join(this.root,'cache'),this.c.fetch,this.c.signal,offline),artifact};
  const path=await realpath(resolve(this.c.cwd,text(provided,4096))),cache=join(this.root,'cache');
  await mkdir(cache,{recursive:true,mode:0o700});const temporary=join(cache,'local.partial-'+randomUUID());
  const source=await open(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
   const metadata=await source.stat();if(!metadata.isFile()||metadata.size>2*1024**3)fail('invalid','Local runtime archive must be a regular file no larger than two GiB.');
   const target=await open(temporary,'wx',0o600);let size=0;
   try{for await(const chunk of source.createReadStream({autoClose:false})){if((size+=chunk.length)>2*1024**3)fail('limit','Local runtime archive grew beyond two GiB.');await target.writeFile(chunk);}await target.sync();}finally{await target.close();}
   const hash=await fileSha256(temporary);
   if(checksum!==undefined&&hash!==text(checksum,64).toLowerCase())fail('binding','Local runtime archive differs from its expected SHA256.');
   const format=(await readMagic(temporary))==='504b'?'zip':'tgz',owned=join(cache,hash+'.'+format);
   if(existsSync(owned)){if(await fileSha256(owned)!==hash)fail('binding','Existing local-archive cache entry is corrupt; remove it before retrying.');}
   else await rename(temporary,owned);
   return {path:owned,artifact:{...artifact,sha256:hash,format} as RuntimeArtifact};
  }finally{await source.close();await rm(temporary,{force:true});}

 }
 private async cleanupProbes(){
  // A killed owner may leave a disposable validation server alive. Its authenticated
  // receipt, not PID existence, authorizes recovery; no research repository is touched.
  for(const parent of ['stages','checks']){
   let names:string[];try{names=await readdir(join(this.root,parent));}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')continue;throw error;}
   for(const name of names){if(!/^[a-f0-9-]{36}$/.test(name))continue;
    const root=join(this.root,parent,name,...(parent==='stages'?['validation']:[]));
    if(existsSync(join(root,'server/local.json'))){
     if(await realpath(root)!==resolve(root))fail('binding','Retained runtime probe moved outside its owned storage.');
     await stopLocalServer(root,this.c);
    }
   }
  }
 }
 async install(o:Record<string,unknown>){
  await this.cleanupProbes();
  if(o.executable&&o.archive)fail('invalid','Choose --executable or --archive.');
  if(o.archiveSha256&&!o.archive||o.javaArchiveSha256&&!o.javaArchive)fail('invalid','Archive checksum requires its archive path.');
  const catalog=runtimeCatalog(),offline=Boolean(o.offline),external=o.executable?await externalGhidra(resolve(this.c.cwd,text(o.executable,4096))):undefined;
  const ghidra=external?undefined:await this.archive(catalog.ghidra,o.archive,o.archiveSha256,offline);
  const java=o.java?await realpath(resolve(this.c.cwd,text(o.java,4096))):undefined;
  if(java&&o.javaArchive)fail('invalid','Choose --java or --java-archive.');
  const jdk=java?undefined:await this.archive(catalog.java,o.javaArchive,o.javaArchiveSha256,offline);
  const identity=digest({schema:1,platform:process.platform,architecture:process.arch,external,java,ghidra:ghidra?.artifact.sha256,jdk:jdk?.artifact.sha256,bridge:pinnedMcpJar});
  const installation=join(this.root,'installations',identity),temporary=join(this.root,'stages',randomUUID());
  await mkdir(temporary,{recursive:true,mode:0o700});
  let selected:RuntimeSelection|undefined,complete=false;
  try{
   let inputs:NativeInputs;
   if(existsSync(join(installation,'ready.json'))){
    const receipt=object(JSON.parse(await readFile(join(installation,'ready.json'),'utf8')));
    inputs=await nativeInputs({...this.c.profile.values,java:java??receipt.java,ghidraHome:external??join(installation,'ghidra')});
    if(inputs.fingerprint!==receipt.fingerprint)fail('binding','Installed runtime differs from its verified installation receipt.');
   }else{
    let ghidraHome=external;
    if(ghidra){
     const extracted=join(temporary,'ghidra-extract');await extractArchive(ghidra.path,extracted,ghidra.artifact.format);
     const found=await findRoot(extracted,'Ghidra/application.properties');if(!found)fail('configuration','Archive omitted a complete Ghidra installation.');
     await rename(found,join(temporary,'ghidra'));await rm(extracted,{recursive:true,force:true});ghidraHome=join(temporary,'ghidra');
     const host=process.arch==='arm64'?'mac_arm_64':'mac_x86_64';
     if(process.platform==='darwin'&&!existsSync(join(ghidraHome,'Ghidra/Features/Decompiler/os',host,'decompile'))){
      const bottle=await cacheArtifact(catalog.ghidra,join(this.root,'cache'),this.c.fetch,this.c.signal,offline),nativeRoot=join(temporary,'native-extract');
      await extractArchive(bottle,nativeRoot,'tgz');const nativeHome=join(nativeRoot,catalog.ghidra.root);
      for(const module of ['Decompiler','FileFormats'])await cp(join(nativeHome,'Ghidra/Features',module,'os',host),join(ghidraHome,'Ghidra/Features',module,'os',host),{recursive:true,errorOnExist:true});
      await rm(nativeRoot,{recursive:true,force:true});
     }
    }
    let javaPath=java;
    if(jdk){const extracted=join(temporary,'jdk-extract');await extractArchive(jdk.path,extracted,jdk.artifact.format);
     const home=await findRoot(extracted,'bin/java'+suffix);if(!home)fail('configuration','Java archive omitted a JDK.');await rename(home,join(temporary,'jdk'));await rm(extracted,{recursive:true,force:true});javaPath=join(temporary,'jdk/bin/java'+suffix);}
    inputs=await nativeInputs({...this.c.profile.values,java:javaPath,ghidraHome});
    await this.probe(inputs,join(temporary,'validation'));
    await rm(join(temporary,'validation'),{recursive:true,force:true});
    const receipt={schema:1,id:identity,ghidraVersion:inputs.ghidraVersion,fingerprint:inputs.fingerprint,java:java??join(installation,'jdk/bin/java'+suffix),ghidraHome:external??join(installation,'ghidra'),
     archives:[...(ghidra?[{sha256:ghidra.artifact.sha256,source:o.archive?'local':catalog.ghidra.url}]:[]),...(jdk?[{sha256:jdk.artifact.sha256,source:o.javaArchive?'local':catalog.java.url}]:[])],verifiedAt:new Date().toISOString(),checks:['jdk','native-decompiler','local-server-reader-publisher-authority']};
    await runtimeWrite(join(temporary,'ready.json'),receipt);await mkdir(dirname(installation),{recursive:true,mode:0o700});
    if(existsSync(installation))fail('binding','Incomplete installation directory is retained; inspect it before removing it.');
    await rename(temporary,installation);
    if(process.platform!=='win32'){const parent=await open(dirname(installation),'r');try{await parent.sync();}finally{await parent.close();}}
   }
   selected={schema:1,mode:external?'external':'managed',id:identity,ghidraHome:external??join(installation,'ghidra'),java:java??join(installation,'jdk/bin/java'+suffix),fingerprint:inputs.fingerprint,selectedAt:new Date().toISOString()};
   await runtimeWrite(join(this.root,'selection.json'),selected);
   complete=true;return {state:'installed',...selected,checks:['jdk','native-decompiler','local-server-reader-publisher-authority']};
  }catch(error){
   await runtimeWrite(join(temporary,'failure.json'),{state:'failed',code:error instanceof CliError?error.code:'installation',message:error instanceof Error?error.message:'Runtime installation failed'});
   if(error instanceof CliError)throw new CliError(error.message,{code:error.code,result:{...(error.result&&typeof error.result==='object'?error.result:{}),diagnostics:temporary}});throw error;
  }finally{if(complete)await rm(temporary,{recursive:true,force:true});}
 }
 async uninstall(purgeCache=false){
  await this.cleanupProbes();
  const selected=runtimeSelection(this.directory);if(!selected)fail('configuration','No managed selection exists; externally configured profile paths are never removed.');
  if(selected.id){if(!/^[a-f0-9]{64}$/.test(selected.id))fail('binding','Invalid installation identity.');await rm(join(this.root,'installations',selected.id),{recursive:true,force:true});}
  if(purgeCache)await rm(join(this.root,'cache'),{recursive:true,force:true});
  await runtimeWrite(join(this.root,'selection.json'),{...selected,uninstalledAt:new Date().toISOString()});
  // Retain the selection: an explicit external profile must never become an implicit fallback.
  return {state:'uninstalled',mode:selected.mode,externalInstallationPreserved:selected.mode==='external',researchPreserved:true,materialsPreserved:true,cachePreserved:!purgeCache};
 }
 private async probe(inputs:NativeInputs,root:string){
  await mkdir(root,{recursive:true,mode:0o700});const classes=await nativeHelpers(root,inputs),log=join(root,'doctor.log');
  let output;
  try{output=await exec(inputs.java,['-Djava.awt.headless=true','-Dghidra.home='+inputs.ghidraHome,...nativeJvmDirectories(root),'-cp',classes+delimiter+inputs.classpath,'InsightRuntimeDoctor'],
    {cwd:root,env:{PATH:dirname(inputs.java),HOME:root,TMPDIR:root},timeout:90000,maxBuffer:1024*1024,signal:this.c.signal});}
  catch(error){await runtimeWrite(log,{failure:String((error as {stderr?:string}).stderr??error)});fail('configuration','Native decompiler probe failed; the diagnostic stage is retained.',{diagnostics:log});}
  const value=object(JSON.parse(output.stdout));if(value.state!=='ready'||value.decompiler!==true||value.expectedReturn!==42)fail('partial','Native decompiler probe did not verify its expected result.');
  const probeContext={...this.c,profile:{...this.c.profile,values:{...this.c.profile.values,server:undefined}}};
  const server=new GhidraServer(root,inputs,probeContext);
  try{const result=await server.administration('connect',{});if(result.connected!==true||result.mode!=='local')fail('partial','Owned server probe did not connect.');
   const checked=await server.administration('status',{});if(checked.connected!==true)fail('partial','Owned server identity/authority probe failed.');
  }finally{await server.stop();}
  return value;
 }
 async doctor(){
  await this.cleanupProbes();
  const root=join(this.root,'checks',randomUUID()),values=runtimeValues(this.directory,this.c.profile.values);
  const inputs=await nativeInputs(values),native=await this.probe(inputs,root);let debuggerCheck:Record<string,unknown>={state:'host_specific'};
  if(process.platform==='darwin')try{const checked=await exec('/usr/bin/lldb',['--no-lldbinit','--batch','-o','script import lldb,sys; print("INSIGHT_LLDB_PYTHON_OK")'],{env:{PATH:'/usr/bin:/bin',HOME:root,TMPDIR:root},timeout:30000,maxBuffer:65536});
   debuggerCheck={state:checked.stdout.includes('INSIGHT_LLDB_PYTHON_OK')?'ready':'missing',backend:'system-lldb'};
  }catch{debuggerCheck={state:'missing',backend:'system-lldb',reason:'Apple developer tools or debugger authorization is unavailable'};}
  const result={state:'verified',fingerprint:inputs.fingerprint,ghidraVersion:inputs.ghidraVersion,checkedAt:new Date().toISOString(),headless:native.headless,decompiler:native.decompiler,server:true,debugger:debuggerCheck,diagnostics:root};
  await runtimeWrite(join(this.root,'last-check.json'),result);if(debuggerCheck.state==='missing')fail('partial','Static analysis and local server passed; the host debugger is unavailable.',{...result,state:'partial'});return result;
 }
}
function runtimeValuesForStatus(selection:RuntimeSelection,values:Record<string,unknown>){return {...values,java:selection.java,ghidraHome:selection.ghidraHome};}
async function readMagic(path:string){const handle=await open(path,'r');try{const b=Buffer.alloc(2);await handle.read(b,0,2,0);return b.toString('hex');}finally{await handle.close();}}
export function runtimeCommands(exclusive:<T>(c:CommandContext,action:()=>Promise<T>,quiescent?:boolean)=>Promise<T>):CommandDefinition[]{
 const source=[{flags:'--archive <path>',description:'Local Ghidra zip/tar.gz; missing dependencies are downloaded'},
  {flags:'--archive-sha256 <sha256>',description:'Expected SHA256 for the supplied Ghidra archive'},
  {flags:'--java-archive <path>',description:'Local Java 21 JDK zip/tar.gz'},
  {flags:'--java-archive-sha256 <sha256>',description:'Expected SHA256 for the supplied JDK archive'},
  {flags:'--java <path>',description:'Use an external Java 21 JDK executable'},
  {flags:'--executable <path>',description:'Use an external Ghidra launcher or installation directory; never deleted'},
  {flags:'--offline',description:'Use local archives/cache only; never access the network'}];
 return [command('download','Cache the pinned complete Ghidra/JDK distribution without activation',({options:o},c)=>exclusive(c,()=>new RuntimeManager(c).download(Boolean(o.offline)),false),{permission:Permission.Update,options:[source.at(-1)!]}),
  command('install','Prepare, verify and select a complete runtime, including Ghidra Server',({options:o},c)=>exclusive(c,()=>new RuntimeManager(c).install(o)),{permission:Permission.Update,options:source}),
  command('uninstall','Remove selected owned runtime files while preserving research and external installations',({options:o},c)=>exclusive(c,()=>new RuntimeManager(c).uninstall(Boolean(o.purgeCache))),{permission:'Destructive',options:[{flags:'--purge-cache',description:'Also remove owned downloaded archives'}]}),
  command('doctor','Launch a disposable native decompiler and local server probe',(_input,c)=>exclusive(c,()=>new RuntimeManager(c).doctor(),false),{permission:Permission.Update})];
}
