import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {join,resolve,dirname} from 'node:path';import {release} from 'node:os';import {open,mkdir,writeFile} from 'node:fs/promises';
import {ToolInstaller} from './tool-runtime/installer.js';import {defineTool,lifecycleCommands} from './tool-runtime/definition.js';
import {catalogArtifact} from './tool-runtime/catalog.js';import {fileSha256} from './tool-runtime/archives.js';import {runTool} from './tool-runtime/run.js';
import {fail,text,id} from './model.js';import {number} from './research.js';import type {Workspace} from './workspace.js';
const utilities=['llvm-readobj','llvm-objdump','llvm-nm','llvm-pdbutil'] as const;
type Utility=typeof utilities[number];
const executable=(primary:string,name:Utility)=>name==='llvm-readobj'?primary:join(dirname(primary),name+(process.platform==='win32'?'.exe':''));
export function llvmInstaller(c:CommandContext){return new ToolInstaller(c,{id:'llvm',primary:'llvm',components:()=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'||Number(release().split('.')[0])<23)fail('unsupported','Managed LLVM utilities require macOS 14+ ARM64; select an external compatible llvm-readobj with its three sibling utilities.');
 return {llvm:catalogArtifact('2599cb40282085a61a3d8b50003d75d556010d764c05a9bf30e45a7c7b5b7861')};
},launch:roots=>({executable:join(roots.llvm!,'bin/llvm-readobj'),arguments:[],environment:{}}),
 externalInputs:async primary=>{const hashes:Record<string,string>={};for(const name of utilities)try{hashes[name]=await fileSha256(executable(primary,name),c.signal);}catch{c.signal.throwIfAborted();fail('configuration','External LLVM requires all four pinned sibling utilities in the executable directory.',{missing:name});}return hashes;},
 probe:async(launch,context)=>{const versions:Record<string,string>={};for(const name of utilities){const r=await runTool(context,{tool:'llvm',role:'version',executable:executable(launch.executable,name),arguments:['--version'],maxOutputBytes:65536,timeoutMs:30000});
 if(!/\bLLVM version 23\.1\.3\b/.test(r.stdout))fail('configuration','The selected LLVM family must provide version 23.1.3.',{utility:name});versions[name]='23.1.3';}return {versions,managedMinimumMacOS:'14.0'};}});}
export function llvmAddress(value:unknown){const v=text(value,18);if(!/^0x[0-9a-fA-F]{1,16}$/.test(v))fail('invalid','Address must be an explicit 0x-prefixed unsigned virtual address.');return BigInt(v);}
async function format(path:string){const file=await open(path,'r'),magic=Buffer.alloc(4);try{await file.read(magic,0,4,0);}finally{await file.close();}
 if(magic.subarray(0,2).toString()==='MZ')return 'pe';if(magic.toString('hex')==='7f454c46')return 'elf';
 if(['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(magic.toString('hex')))return 'macho';return 'other';}
export function llvmCommands(workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{
 const definition=defineTool({id:'llvm',description:'Inspect native binary structure, symbols, instructions and PDBs',components:[{id:'llvm',version:'23.1.3',artifacts:[]}],lifecycle:{download:(o,c)=>llvmInstaller(c).download(Boolean(o.offline)),install:(o,c)=>llvmInstaller(c).install(o),uninstall:(o,c)=>llvmInstaller(c).uninstall(Boolean(o.purgeCache)),doctor:(_o,c)=>llvmInstaller(c).doctor(),status:(_o,c)=>llvmInstaller(c).status()}});
 const common=[{flags:'--target <id>',description:'Reuse an immutable research target'},{flags:'--output <file>',description:'Write full bounded native text to a new ordinary file'},
 {flags:'--limit <count>',description:'Maximum native text lines returned (1–400)',defaultValue:100},{flags:'--offset <count>',description:'Skip native text lines',defaultValue:0},
 {flags:'--filter <text>',description:'Select matching native lines; surrounding context may be outside the selection'},{flags:'--timeout-seconds <seconds>',description:'Deadline per native process (1–600)',defaultValue:120}];
 const operation=(name:string,options:NonNullable<CommandDefinition['options']>=[])=>command(name+' [input]','Native '+name+' through pinned LLVM utilities',async({args,options:o},c)=>{
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');const w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target)),input=await w.artifacts.verify(target.input);
  const kind=await format(input),timeoutMs=number(o.timeoutSeconds,600,1)*1000,limit=number(o.limit,400,1),offset=number(o.offset,10000000,0);
  const calls:{utility:Utility;arguments:string[]}[]=[];
  if(name==='headers'||name==='sections')calls.push({utility:'llvm-readobj',arguments:[name==='headers'?'--file-header':'--sections',input]});
  if(name==='imports'){
   if(kind==='pe')calls.push({utility:'llvm-readobj',arguments:['--coff-imports',input]});
   else if(kind==='elf')calls.push({utility:'llvm-readobj',arguments:['--needed-libs',input]},{utility:'llvm-nm',arguments:['--dynamic','--undefined-only','--format=posix',input]});
   else if(kind==='macho')calls.push({utility:'llvm-objdump',arguments:['--macho','--dylibs-used',input]},{utility:'llvm-nm',arguments:['--undefined-only','--format=posix',input]});
   else fail('unsupported','Import linkage view requires a PE, ELF or Mach-O image.');
  }
  if(name==='exports'){
   if(kind==='pe')calls.push({utility:'llvm-readobj',arguments:['--coff-exports',input]});
   else if(kind==='elf'||kind==='macho')calls.push({utility:'llvm-nm',arguments:[...(kind==='elf'?['--dynamic']:[]),'--defined-only','--extern-only','--format=posix',input]});
   else fail('unsupported','Export linkage view requires a PE, ELF or Mach-O image.');
  }
  if(name==='symbols')calls.push({utility:'llvm-nm',arguments:['--format=posix',...(o.undefinedOnly?['--undefined-only']:[]),input]});
  if(name==='disassemble'){const start=llvmAddress(o.address),length=number(o.bytes,4096,1),end=start+BigInt(length);if(end>0xffffffffffffffffn)fail('invalid','Disassembly interval overflows a 64-bit address.');calls.push({utility:'llvm-objdump',arguments:['--disassemble','--demangle','--start-address=0x'+start.toString(16),'--stop-address=0x'+end.toString(16),input]});}
  if(name==='pdb'){
   const view=text(o.view,16);if(!['summary','modules','globals','publics','symbols','types'].includes(view))fail('invalid','PDB view must be summary, modules, globals, publics, symbols or types.');
   if(o.typeIndex&&view!=='types'||o.symbol&&view!=='globals')fail('invalid','type-index is for types; symbol is for globals.');
   if(o.typeIndex&&llvmAddress(o.typeIndex)>0xffffffffn)fail('invalid','PDB type index exceeds 32 bits.');
   const flags=view==='types'?(o.typeIndex?['--types','--type-index=0x'+llvmAddress(o.typeIndex).toString(16)]:['--type-stats']):['--'+view];
   if(o.module!==undefined)flags.push('--modi='+number(o.module,1000000,0));if(o.symbol)flags.push('--global-name='+text(o.symbol,1024));calls.push({utility:'llvm-pdbutil',arguments:['dump',...flags,input]});
  }
  return llvmInstaller(c).use(async selected=>{
   const results=[];for(const call of calls)results.push({...call,result:await runTool(c,{tool:'llvm',role:name,installation:selected.id,executable:executable(selected.executable,call.utility),arguments:call.arguments,environment:selected.environment,target:target.id,timeoutMs})});
   const content=results.map(r=>r.utility+'\n'+r.result.stdout).join('\n'),base={state:'completed',target:target.id,inputSha256:target.binarySha256,fileFormat:kind,format:'native-text',processes:results.map(r=>({utility:r.utility,process:r.result.process,diagnostics:r.result.diagnostics,elapsedMs:r.result.elapsedMs}))};
   if(o.output){const output=resolve(c.cwd,text(o.output,4096));await mkdir(dirname(output),{recursive:true,mode:0o700});await writeFile(output,content,{flag:'wx',mode:0o600});return {...base,output,bytes:Buffer.byteLength(content)};}
   const all=content.trimEnd().split(/\r?\n/),lines=o.filter?all.filter(l=>l.includes(text(o.filter,1024))):all;return {...base,content:lines.slice(offset,offset+limit).join('\n'),totalLines:lines.length,offset,limit,truncated:offset+limit<lines.length};
  });
 },{permission:Permission.Update,options:[...common,...options]});
 return [command('llvm',definition.description,[...lifecycleCommands(definition),...['headers','sections','imports','exports'].map(n=>operation(n)),operation('symbols',[{flags:'--undefined-only',description:'Only undefined symbols'}]),operation('disassemble',[{flags:'--address <virtual-address>',description:'Start virtual address, not a file offset',required:true},{flags:'--bytes <count>',description:'Byte interval (1–4096)',defaultValue:128}]),operation('pdb',[{flags:'--view <name>',description:'summary, modules, globals, publics, symbols or types',defaultValue:'summary'},{flags:'--module <index>',description:'Focus a compiland by its numeric module index'},{flags:'--symbol <name>',description:'Exact global symbol name'},{flags:'--type-index <0x-index>',description:'Inspect one hexadecimal type record instead of type statistics'}])])];
}
