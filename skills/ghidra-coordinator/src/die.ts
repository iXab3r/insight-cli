import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {dirname,join,resolve} from 'node:path';import {release} from 'node:os';import {mkdir,writeFile,stat} from 'node:fs/promises';
import {ToolInstaller} from './tool-runtime/installer.js';import {treeFingerprint} from './tool-runtime/store.js';
import {defineTool,lifecycleCommands} from './tool-runtime/definition.js';import {catalogArtifact} from './tool-runtime/catalog.js';import {runTool} from './tool-runtime/run.js';import {fileSha256} from './tool-runtime/archives.js';
import {fail,text,id} from './model.js';import {number} from './research.js';import type {Workspace} from './workspace.js';
const frameworks=['QtConcurrent','QtCore','QtCore5Compat','QtNetwork','QtQml'];
const contents=(executable:string)=>dirname(dirname(executable));
export function dieInstaller(c:CommandContext){return new ToolInstaller(c,{id:'die',primary:'die',components:()=>{
 if(process.platform!=='darwin'||process.arch!=='arm64'||Number(release().split('.')[0])<22)fail('unsupported','Managed DiE requires macOS 13+ ARM64.');
 return {die:catalogArtifact('5fc9f1d870b4c791ae688a07ccbae0dcdf677eedeeb6ae732bbc83eac61148af')};
},launch:roots=>({executable:join(roots.die!,'MacOS/diec'),arguments:[],environment:{}}),externalInputs:async executable=>{
 const root=contents(executable),inputs:Record<string,string>={};
 // The database is executable signature code: fingerprint it as part of the external tool.
 for(const name of ['db','db_custom'])inputs['Resources/'+name]=await treeFingerprint(join(root,'Resources',name));
 inputs['Resources/qt.conf']=await fileSha256(join(root,'Resources/qt.conf'));
 for(const path of ['MacOS/qt.conf','Info.plist','PlugIns'])try{const at=join(root,path);inputs[path]=(await stat(at)).isDirectory()?await treeFingerprint(at):await fileSha256(at);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 if(process.platform==='darwin')for(const name of frameworks)inputs[name]=await treeFingerprint(join(root,'Frameworks',name+'.framework'));
 return inputs;
},probe:async(launch,context)=>{
 const root=contents(launch.executable);await stat(join(root,'Resources/db/_init'));
 const r=await runTool(context,{tool:'die',role:'version',executable:launch.executable,arguments:['--version'],maxOutputBytes:65536,timeoutMs:30000});
 if(!/\b3\.21\b/.test(r.stdout))fail('configuration','The selected Detect It Easy console must provide version 3.21 with its adjacent Resources/db database.');
 return {version:'3.21',database:'adjacent Resources/db',managedMinimumMacOS:'13.0',signaturesAreHeuristic:true};
}});}
/** Upstream may append signature errors after its JSON while exiting zero. Never discard them. */
export function dieJson(stdout:string,stderr:string){
 const start=stdout.search(/\S/);if(start<0||stdout[start]!=='{')fail('binding','DiE did not return a JSON object; inspect the retained native process diagnostics.');
 let depth=0,string=false,escaped=false,end=-1;
 for(let i=start;i<stdout.length;i++){const ch=stdout[i];if(string){if(escaped)escaped=false;else if(ch==='\\')escaped=true;else if(ch==='"')string=false;}else if(ch==='"')string=true;else if(ch==='{')depth++;else if(ch==='}'&&--depth===0){end=i+1;break;}}
 if(end<0)fail('binding','DiE returned incomplete JSON; inspect the retained native process diagnostics.');
 let data:Record<string,unknown>;try{data=JSON.parse(stdout.slice(start,end));}catch{fail('binding','DiE returned malformed JSON; inspect the retained native process diagnostics.');}
 const diagnostics=[stdout.slice(end).trim(),stderr.trim()].filter(Boolean);
 return {data,diagnostics,complete:diagnostics.length===0};
}
export function dieFindings(data:Record<string,unknown>){
 if(!Array.isArray(data.detects))fail('binding','DiE omitted its detection array; retained output is not a complete classification.');
 const rows:Record<string,string>[]=[];
 for(const group of data.detects){
  if(!group||typeof group!=='object'||typeof group.filetype!=='string'||!Array.isArray(group.values))fail('binding','DiE returned an unsupported detection schema.');
  for(const value of group.values){if(!value||typeof value!=='object'||['name','type','version','info','string'].some(k=>typeof value[k]!=='string'))fail('binding','DiE returned an unsupported signature record.');
   rows.push({fileType:group.filetype,offset:String(group.offset??''),region:String(group.parentfilepart??''),...Object.fromEntries(['name','type','version','info','string'].map(k=>[k,value[k]]))});
  }
 }
 return rows;
}
export function dieCommands(workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{
 const definition=defineTool({id:'die',description:'Classify binaries and retain compiler, runtime or packer signature evidence',components:[{id:'die',version:'3.21',artifacts:[]}],lifecycle:{download:(o,c)=>dieInstaller(c).download(Boolean(o.offline)),install:(o,c)=>dieInstaller(c).install(o),uninstall:(o,c)=>dieInstaller(c).uninstall(Boolean(o.purgeCache)),doctor:(_o,c)=>dieInstaller(c).doctor(),status:(_o,c)=>dieInstaller(c).status()}});
 return [command('die',definition.description,[...lifecycleCommands(definition),command('classify [input]','Read input format/architecture and signature evidence without running the input',async({args,options:o},c)=>{
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply exactly one input path or --target.');
  const limit=number(o.limit,400,1),offset=number(o.offset,1000000,0),timeoutMs=number(o.timeoutSeconds,600,1)*1000;
  const w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target)),input=await w.artifacts.verify(target.input);
  return dieInstaller(c).use(async selected=>{
   const database=join(contents(selected.executable),'Resources/db'),calls=[];
   for(const mode of ['info','scan']){
    const result=await runTool(c,{tool:'die',role:mode,installation:selected.id,executable:selected.executable,arguments:['--json','--database',database,...(mode==='info'?['--info']:[...(o.deep?['--deepscan']:[]),...(o.heuristic?['--heuristicscan']:[])]),input],environment:selected.environment,target:target.id,timeoutMs});
    calls.push({mode,result,parsed:dieJson(result.stdout,result.stderr)});
   }
   const info=calls[0]!.parsed.data.data as {Info?:unknown}|undefined;
   if(!info?.Info||typeof info.Info!=='object'||Array.isArray(info.Info))fail('binding','DiE omitted its file information view.');
   const findings=dieFindings(calls[1]!.parsed.data),diagnostics=calls.flatMap(call=>call.parsed.diagnostics.map(message=>({view:call.mode,message}))),complete=diagnostics.length===0;
   const base={state:complete?'completed':'partial',complete,target:target.id,inputSha256:target.binarySha256,information:info.Info,diagnostics,coverage:'Heuristic signatures are evidence; Unknown or no match does not prove absence of packing, obfuscation or a runtime.',processes:calls.map(call=>({view:call.mode,process:call.result.process,diagnostics:call.result.diagnostics,elapsedMs:call.result.elapsedMs}))};
   if(o.output){const output=resolve(c.cwd,text(o.output,4096)),content=JSON.stringify({...base,findings},null,2)+'\n';await mkdir(dirname(output),{recursive:true,mode:0o700});await writeFile(output,content,{flag:'wx',mode:0o600});return {...base,output,bytes:Buffer.byteLength(content),totalFindings:findings.length};}
   return {...base,findings:findings.slice(offset,offset+limit),totalFindings:findings.length,offset,limit,truncated:offset+limit<findings.length};
  });
 },{permission:Permission.Update,options:[{flags:'--target <id>',description:'Reuse an immutable research target'},{flags:'--deep',description:'Enable deeper signature scanning'},{flags:'--heuristic',description:'Enable optional heuristic scanning'},{flags:'--output <file>',description:'Save the full bounded classification and all warnings to a new JSON file'},{flags:'--limit <count>',description:'Maximum signature findings (1–400)',defaultValue:100},{flags:'--offset <count>',description:'Skip signature findings',defaultValue:0},{flags:'--timeout-seconds <seconds>',description:'Deadline per native view (1–600)',defaultValue:120}]})])];
}
