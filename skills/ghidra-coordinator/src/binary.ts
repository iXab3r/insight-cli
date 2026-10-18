import {command,Permission,CliError,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,writeFile,copyFile,readFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {release} from 'node:os';
import {randomUUID} from 'node:crypto';
import {runTool} from './tool-runtime/run.js';
import {atomicWrite} from './tool-runtime/store.js';
import {fileSha256} from './tool-runtime/archives.js';
import {fail,text,id} from './model.js';
import {number} from './research.js';
import type {Workspace} from './workspace.js';
const helper=fileURLToPath(new URL('../../runtime/native/binary/insight-binary-darwin-arm64',import.meta.url));
export function binaryCommands(workspace:(c:CommandContext)=>Workspace):CommandDefinition[]{
 const run=(mode:'query'|'edit-subsystem')=>command(mode+' [input]',mode==='query'?'Inspect bounded PE, ELF or thin Mach-O metadata without executing the input':'Change one expected PE subsystem field in a new copy and independently read it back',async({args,options:o},c)=>{
  if(process.platform!=='darwin'||process.arch!=='arm64'||Number(release().split('.')[0])<23)fail('unsupported','The packaged LIEF facade is currently verified on macOS14+ ARM64; input formats are PE, ELF and thin Mach-O.');
  if(Boolean(args.input)===Boolean(o.target))fail('invalid','Supply one binary input or --target.');
  const view=mode==='query'?text(o.view??'overview',16):undefined;if(view&&!['overview','sections','libraries','imports','exports'].includes(view))fail('invalid','Use overview, sections, libraries, imports or exports.');
  const limit=number(o.limit??50,500,1),offset=number(o.offset??0,1000000),w=workspace(c),target=args.input?await w.importTarget(resolve(c.cwd,text(args.input,4096))):w.target(id(o.target));if(target.input.size>64*1024**2)fail('limit','Structured binary input exceeds 64 MiB.');const input=await w.artifacts.verify(target.input);
  const directory=join(c.appArguments.AppDataDirectory,'runtime/binary/queries',randomUUID()),plan=join(directory,'plan.json'),edited=join(directory,'edited.exe');let edit;
  if(mode==='edit-subsystem'){if(!o.output)fail('invalid','Copy-only editing requires --output FILE.');const values:Record<string,number>={gui:2,console:3},expected=values[text(o.expectSubsystem,16)],value=values[text(o.subsystem,16)];if(!expected||!value||expected===value)fail('invalid','Choose a different gui/console subsystem and an explicit --expect-subsystem.');edit={expectedSubsystem:expected,subsystem:value,output:edited};}
  await atomicWrite(plan,{schema:1,mode,input,view,filter:o.filter===undefined?undefined:text(o.filter,4096),limit,offset,...edit});
  const result=await runTool(c,{tool:'binary',role:mode,executable:helper,arguments:[plan],timeoutMs:60000,maxOutputBytes:8*1024**2,nativeDeadline:true,target:target.id,metadata:{view,helperSha256:await fileSha256(helper)}});
  let observation;try{observation=JSON.parse(result.stdout);}catch{throw new CliError('Binary parser did not return complete bounded JSON.',{code:'tool.partial',result:{process:result.process,diagnostics:result.diagnostics}});}
  if(!['completed','partial'].includes(observation?.state)||typeof observation.complete!=='boolean')fail('partial','Binary query receipt was not verified.',{process:result.process,diagnostics:result.diagnostics});if(await fileSha256(input)!==target.binarySha256)fail('binding','Immutable binary changed during inspection.');
  const warnings=result.stderr.trim(),value={...observation,...(warnings?{state:'partial',complete:false,reason:'native_parser_diagnostics',warnings:warnings.slice(0,4096),warningsTruncated:warnings.length>4096}:{}),target:target.id,inputSha256:target.binarySha256,process:result.process,elapsedMs:result.elapsedMs,diagnostics:result.diagnostics};
  if(mode==='edit-subsystem'){
   if(!value.complete)fail('partial','Native parser diagnostics prevent accepting the copied edit.',value);
   const before=await readFile(input),after=await readFile(edited),at=Number(BigInt(observation.fieldOffset));if(after.length!==before.length||!Number.isSafeInteger(at)||at<0||at+2>before.length)fail('binding','Copied PE edit did not retain its field bounds.');for(let n=0;n<before.length;n++)if(n!==at&&n!==at+1&&before[n]!==after[n])fail('binding','Copied PE edit changed bytes outside the declared field.');
   const output=resolve(c.cwd,text(o.output,4096));await mkdir(dirname(output),{recursive:true,mode:0o700});await copyFile(edited,output,constants.COPYFILE_EXCL);return {...value,output,outputSha256:await fileSha256(output),originalPreserved:true};
  }
  if(o.output){const output=resolve(c.cwd,text(o.output,4096)),content=JSON.stringify(value,null,2)+'\n';await mkdir(dirname(output),{recursive:true,mode:0o700});await writeFile(output,content,{flag:'wx',mode:0o600});return {state:value.state,complete:value.complete,reason:value.reason,target:target.id,output,bytes:Buffer.byteLength(content),process:result.process,diagnostics:result.diagnostics};}
  return value;
 },{permission:Permission.Update,options:[{flags:'--target <id>',description:'Reuse immutable input bytes'},{flags:'--output <file>',description:mode==='query'?'Save this bounded page to a new JSON file':'Required new executable copy; never overwrite an existing file'},...(mode==='query'?[{flags:'--view <kind>',description:'overview, sections, libraries, imports or exports',defaultValue:'overview'},{flags:'--filter <text>',description:'Literal metadata name substring before pagination'},{flags:'--limit <count>',description:'Return 1–500 rows',defaultValue:50},{flags:'--offset <count>',description:'Skip matching rows',defaultValue:0}]:[{flags:'--expect-subsystem <kind>',description:'Required current PE subsystem: gui or console',required:true},{flags:'--subsystem <kind>',description:'Required different PE subsystem: gui or console',required:true}])]});
 return [command('binary','Structured binary metadata and guarded copy-only edits',[run('query'),run('edit-subsystem')])];
}
