import {command,Permission,type CommandDefinition} from '@eyeauras/cli-factory';
import {readFile,readdir,lstat,realpath,mkdir,open,rename,rm,utimes,chmod} from 'node:fs/promises';
import {readFileSync,mkdirSync,realpathSync,constants} from 'node:fs';
import {join,resolve,basename,delimiter} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {fail,id,object,stable,text} from './model.js';

interface ModuleFile {name:string;sha256:string;size:number}
interface Extension {name:string;version:string;sha256:string;files:ModuleFile[];enabled:boolean}
interface ExtensionState {schema:1;modules:Extension[]}
const empty=():ExtensionState=>({schema:1,modules:[]});
const hex=(value:unknown)=>{if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))fail('invalid','Expected a lowercase SHA256.');return value;};
export function extensionState(directory:string):ExtensionState {
  let data;try{const bytes=readFileSync(join(directory,'extensions','active.json'));if(bytes.length>2097152)fail('limit','Extension manifest exceeds 2 MiB.');data=JSON.parse(bytes.toString());}
  catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return empty();throw error;}
  const state=object(data);if(state.schema!==1||!Array.isArray(state.modules)||state.modules.length>32)fail('binding','Managed extension manifest is malformed.');
  const names=new Set<string>();
  for(const item of state.modules){const m=object(item);if(!/^[A-Za-z][A-Za-z0-9_-]{0,79}$/.test(String(m.name))||names.has(String(m.name))||m.version!=='12.1.2'||typeof m.enabled!=='boolean'||!Array.isArray(m.files)||!m.files.length||m.files.length>8192)fail('binding','Managed extension identity is malformed.');
    names.add(String(m.name));hex(m.sha256);
    const paths=new Set<string>();let total=0;for(const item of m.files){const f=object(item);modulePath(f.name);hex(f.sha256);if(paths.has(String(f.name))||!Number.isSafeInteger(f.size)||Number(f.size)<0)fail('binding','Managed extension file manifest is malformed.');paths.add(String(f.name));total+=Number(f.size);}
    if(total>268435456||!paths.has('Module.manifest')||!paths.has('extension.properties'))fail('binding','Managed extension omitted its module metadata or exceeded 256 MiB.');
    if(createHash('sha256').update(stable(m.files)).digest('hex')!==m.sha256)fail('binding','Managed extension content identity changed.');
  }
  return state as unknown as ExtensionState;
}
function modulePath(value:unknown):string {
  const name=text(value,1024);if(name.includes('\\')||name.includes(':')||name.split('/').some(p=>!p||p==='.'||p==='..'||p.startsWith('.'))||name.split('/').length>16)fail('invalid','Extension files require ordinary relative module paths.');return name;
}
async function tree(directory:string):Promise<ModuleFile[]> {
  if((await lstat(directory)).isSymbolicLink()||!(await lstat(directory)).isDirectory())fail('invalid','Extension input must be an ordinary unpacked SDK module directory.');
  const files:ModuleFile[]=[];let size=0;
  async function walk(path:string,prefix:string){for(const entry of (await readdir(path,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
    const name=modulePath(prefix+entry.name),file=join(path,entry.name);if(entry.isDirectory())await walk(file,name+'/');
    else if(entry.isFile()){
      if(files.length>=8192)fail('limit','Extension exceeds 8192 files.');const handle=await open(file,'r');
      try{const s=await handle.stat();size+=s.size;if(!s.isFile()||size>268435456)fail('limit','Extension exceeds 256 MiB.');const hash=createHash('sha256');for await(const bytes of handle.createReadStream({autoClose:false}))hash.update(bytes);files.push({name,sha256:hash.digest('hex'),size:s.size});}finally{await handle.close();}
    }else fail('invalid','Extension symlinks and special files are unsupported.');
  }}
  await walk(directory,'');return files;
}
export async function inspectExtension(directory:string):Promise<Extension> {
  const files=await tree(directory);if(!files.some(f=>f.name==='Module.manifest')||!files.some(f=>f.name==='extension.properties'))fail('invalid','Expected Module.manifest and extension.properties at the module root.');
  const properties=await readFile(join(directory,'extension.properties'),'utf8');
  const property=(name:string)=>new RegExp('^'+name+'\\s*=\\s*([^\\r\\n]+)','m').exec(properties)?.[1]?.trim();
  const name=property('name'),version=property('version');if(!name||!/^[A-Za-z][A-Za-z0-9_-]{0,79}$/.test(name)||basename(directory)!==name||version!=='12.1.2')fail('configuration','Extension directory/name must agree and version must be exactly 12.1.2.');
  return {name,version,sha256:createHash('sha256').update(stable(files)).digest('hex'),files,enabled:true};
}
export function extensionDirectory(directory:string,module:Extension){return join(directory,'extensions','modules',module.sha256,module.name);}
/** Verify immutable owned copies; a changed input never joins an existing JVM's classpath. */
export async function managedExtensions(directory?:string){
  if(!directory)return [];
  const result=[];for(const module of extensionState(directory).modules.filter(m=>m.enabled)){
    const root=extensionDirectory(directory,module);if(await realpath(root)!==resolve(root)||stable(await tree(root))!==stable(module.files))fail('binding','Managed extension bytes changed; restore the original module before continuing.');
    result.push({...module,root});
  }return result;
}
const mutations=new Map<string,Promise<unknown>>();
export class Extensions {
  readonly directory:string;
  constructor(directory:string){mkdirSync(directory,{recursive:true,mode:0o700});this.directory=realpathSync.native(directory);}
  list(){return {items:extensionState(this.directory).modules.map(({files,...m})=>({...m,fileCount:files.length})),runtimeBoundary:'Stop the IPC owner after changing the enabled module set. Saved contexts and pending work remain retained.'};}
  private async write(state:ExtensionState){
    const root=join(this.directory,'extensions');await mkdir(root,{recursive:true,mode:0o700});if(await realpath(root)!==resolve(root))fail('binding','Extension storage moved outside the profile.');
    if(Buffer.byteLength(stable(state))>2097152)fail('limit','Combined extension manifest exceeds 2 MiB.');
    const temp=join(root,'active-'+randomUUID()+'.json'),file=await open(temp,'wx',0o600);try{await file.writeFile(stable(state));await file.sync();}finally{await file.close();}
    await rename(temp,join(root,'active.json'));if(process.platform!=='win32'){const dir=await open(root,'r');try{await dir.sync();}finally{await dir.close();}}
  }
  private async ordered<T>(action:()=>Promise<T>):Promise<T>{const previous=mutations.get(this.directory),task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);mutations.set(this.directory,task);try{return await task;}finally{if(mutations.get(this.directory)===task)mutations.delete(this.directory);}}
  install(directory:string,expected:string){return this.ordered(()=>this.consume(directory,expected));}
  private async consume(directory:string,expected:string){
    hex(expected);const module=await inspectExtension(directory);if(module.sha256!==expected)fail('binding','Extension differs from the inspected content SHA256.');
    const state=extensionState(this.directory),existing=state.modules.find(m=>m.name===module.name);
    if(existing&&existing.sha256!==module.sha256)fail('conflict','Extension name is already pinned to different bytes; use another profile or module name.');
    const root=extensionDirectory(this.directory,module),stage=join(this.directory,'extensions','staging-'+randomUUID(),module.name);
    await mkdir(stage,{recursive:true,mode:0o700});
    try{
      const directories=new Set<string>([stage]);
      for(const f of module.files){const path=join(stage,f.name),parent=resolve(path,'..');await mkdir(parent,{recursive:true,mode:0o700});
        for(let d=parent;d.startsWith(stage);d=resolve(d,'..'))directories.add(d);
        const source=await open(join(directory,f.name),constants.O_RDONLY|(constants.O_NOFOLLOW??0)),out=await open(path,'wx',0o600);let count=0;const hash=createHash('sha256');
        try{if(!(await source.stat()).isFile())fail('binding','Extension input changed its file kind.');
          for await(const chunk of source.createReadStream({autoClose:false})){count+=chunk.length;if(count>f.size)fail('binding','Extension input grew during consumption.');hash.update(chunk);await out.writeFile(chunk);}
          if(count!==f.size||hash.digest('hex')!==f.sha256)fail('binding','Extension input changed during consumption.');
          await utimes(path,946684800,946684800);await chmod(path,0o400);await out.sync();
        }finally{await source.close();await out.close();}
      }
      if(process.platform!=='win32')for(const path of [...directories].sort((a,b)=>b.length-a.length)){const dir=await open(path,'r');try{await dir.sync();}finally{await dir.close();}}
      if(stable(await tree(stage))!==stable(module.files))fail('binding','Extension input changed while being consumed.');
      await mkdir(resolve(root,'..'),{recursive:true,mode:0o700});
      let present;try{present=await lstat(root);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
      if(present){if(present.isSymbolicLink()||!present.isDirectory()||stable(await tree(root))!==stable(module.files))fail('binding','Existing extension storage differs from its content identity.');}
      else await rename(stage,root);
      if(process.platform!=='win32')for(const path of [resolve(root,'..'),resolve(root,'../..')]){const dir=await open(path,'r');try{await dir.sync();}finally{await dir.close();}}
      if(!existing){if(state.modules.length>=32)fail('limit','At most 32 managed modules per profile.');state.modules.push(module);state.modules.sort((a,b)=>a.name.localeCompare(b.name));await this.write(state);}
      return {state:'installed',name:module.name,sha256:module.sha256,enabled:existing?.enabled??true,restartRequired:!existing};
    }finally{await rm(resolve(stage,'..'),{recursive:true,force:true});}
  }
  enable(name:string,enabled:boolean){return this.ordered(()=>this.change(name,enabled));}
  private async change(name:string,enabled:boolean){id(name);const state=extensionState(this.directory),module=state.modules.find(m=>m.name===name);if(!module)fail('notFound','Managed extension is not installed.');
    if(enabled){const root=extensionDirectory(this.directory,module);if(stable(await tree(root))!==stable(module.files))fail('binding','Managed extension bytes changed.');}
    const changed=module.enabled!==enabled;module.enabled=enabled;if(changed)await this.write(state);
    return {state:enabled?'enabled':'disabled',name,sha256:module.sha256,restartRequired:changed};
  }
}
export function extensionCommands(service:(c:import('@eyeauras/cli-factory').CommandContext)=>Extensions):CommandDefinition[]{return [command('extensions','Pin unpacked Ghidra SDK extension modules in this profile',[
  command('inspect','Hash a ready-built module without executing extension code',async({options:o},c)=>{const {files,...m}=await inspectExtension(resolve(c.cwd,text(o.directory,4096)));return {...m,fileCount:files.length,size:files.reduce((n,f)=>n+f.size,0)};},{permission:Permission.ReadOnly,options:[{flags:'--directory <path>',description:'Unpacked standard SDK extension module',required:true}]}),
  command('install','Consume the inspected module; stop the IPC owner before using changed runtime inputs',({options:o},c)=>service(c).install(resolve(c.cwd,text(o.directory,4096)),text(o.sha256,64)),{permission:'Destructive',options:[{flags:'--directory <path>',description:'Unpacked standard SDK extension module',required:true},{flags:'--sha256 <sha>',description:'Content SHA256 returned by extensions inspect',required:true}]}),
  command('list','List pinned managed modules and enablement',(_i,c)=>service(c).list(),{permission:Permission.ReadOnly}),
  ...(['enable','disable'] as const).map(name=>command(name,'Change the enabled module set for the next IPC owner',({options:o},c)=>service(c).enable(text(o.name,80),name==='enable'),{permission:'Destructive',options:[{flags:'--name <name>',description:'Installed managed module name',required:true}]})),
])];}
export const extensionJvmArguments=(roots:string[])=>roots.length?['-Dghidra.external.modules='+roots.join(delimiter)]:[];

export function extensionInventoryCommands(backend:(c:import('@eyeauras/cli-factory').CommandContext)=>()=>Promise<import('./research.js').ResearchBackend>):CommandDefinition[]{return [command('extensions','Inspect enabled SDK capabilities',[
  command('capabilities','List actual native language/compiler, analyzer or plugin identities',async({options:o},c)=>{
    const kind=text(o.kind);if(!['languages','analyzers','plugins'].includes(kind))fail('invalid','kind must be languages, analyzers or plugins.');
    const limit=Number(o.limit),offset=Number(o.offset);if(!Number.isSafeInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>2147483647)fail('invalid','Invalid inventory page.');
    const native=await backend(c)();if(!native.sdkFile)fail('configuration','Native extension discovery is unavailable.');return native.sdkFile('extension-inventory',{kind,filter:o.filter===undefined?'':text(o.filter,512),limit,offset});
  },{permission:Permission.ReadOnly,options:[{flags:'--kind <kind>',description:'languages, analyzers or plugins',required:true},{flags:'--filter <text>',description:'Literal identity or description filter'},{flags:'--limit <count>',description:'Page size 1–100',defaultValue:50},{flags:'--offset <count>',description:'Page offset',defaultValue:0}]})
])];}
