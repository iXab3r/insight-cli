// Internal bounded collector process, never a second public CLI or persistent service.
import {pathToFileURL} from 'node:url';
import {processIdentity} from './tool-runtime/identity.js';
import {inheritedDeadlineEnvironment} from './tool-runtime/deadline.js';
import {mkdir} from 'node:fs/promises';import {join} from 'node:path';
interface Configuration {module:string;mode:'probe'|'modules'|'exports'|'observe';pid?:number;expectedBirth?:string;moduleName?:string;source?:string;durationMs?:number;deadlineUnixSeconds:number}
async function main(){
 let input='';for await(const chunk of process.stdin){input+=chunk;if(Buffer.byteLength(input)>2*1024**2)throw Error('Collector request exceeds two MiB');}
 const config=JSON.parse(input) as Configuration;
 // Set this after Node starts: only SDK helper execs load the constructor, not the target.
 const receipts=join(process.env.HOME!,'native-deadlines');await mkdir(receipts,{mode:0o700});Object.assign(process.env,await inheritedDeadlineEnvironment(config.deadlineUnixSeconds,receipts));
 // This import is intentionally isolated in an owned child; native addon faults cannot crash the owner.
 const frida=await import(pathToFileURL(config.module).href) as any;
 const emit=(value:unknown)=>process.stdout.write(JSON.stringify(value)+'\n');
 if(config.mode==='probe'){const version=await frida.getLocalDevice();emit({kind:'probe',protocol:1,version:'17.24.0',device:version.type});return;}
 const cancellable=new frida.Cancellable();let session:any,script:any,detached=false,finished=false,error=false,unloaded=false,sessionDetached=false,loaded=false,interrupted=false,count=0;
 const duration=config.durationMs??1000,deadline=setTimeout(()=>cancellable.cancel(),duration+5000);let resolveDone!:()=>void;
 const done=new Promise<void>(ok=>resolveDone=ok);let observation:NodeJS.Timeout|undefined;
 const stop=()=>{interrupted=true;error=true;emit({kind:'interrupted',signal:'SIGTERM'});resolveDone();if(!loaded)cancellable.cancel();};process.once('SIGTERM',stop);
 try{
  if(!config.pid||(await processIdentity(config.pid))?.birth!==config.expectedBirth)throw Error('Target birth identity changed before attach');
  session=await frida.attach(config.pid,{},cancellable);session.detached.connect((reason:string,crash:unknown)=>{detached=true;if(!finished){error=true;emit({kind:'detached',reason,crash:Boolean(crash)});resolveDone();}});
  let source=config.source;
  if(config.mode==='modules')source='send({kind:"modules",items:Process.enumerateModules().map(m=>({name:m.name,path:m.path,base:m.base.toString(),size:m.size}))});';
  if(config.mode==='exports')source='send({kind:"exports",module:'+JSON.stringify(config.moduleName)+',items:Process.getModuleByName('+JSON.stringify(config.moduleName)+').enumerateExports()});';
  // Keep user source untouched (strict directives and source line numbers matter).
  const bootstrap=await session.createScript('send(Frida.version);',{},cancellable);let versionTimer:NodeJS.Timeout|undefined;
  const version=new Promise<string>((ok,bad)=>{bootstrap.message.connect((message:any)=>message.type==='send'?ok(message.payload):bad(new Error('Frida runtime version probe failed')));versionTimer=setTimeout(()=>bad(new Error('Frida runtime version probe timed out')),5000);});void version.catch(()=>{});
  try{await bootstrap.load(cancellable);const actual=await version;emit({kind:'runtime',version:actual});if(actual!=='17.24.0')throw Error('Frida runtime version differs from 17.24.0');}finally{if(versionTimer)clearTimeout(versionTimer);await bootstrap.unload(cancellable);}
  script=await session.createScript(source,{},cancellable);
  script.message.connect((message:any,data:Buffer|null)=>{
   if(++count>10000){error=true;if(count===10001)emit({kind:'limit',message:'Collector exceeded 10000 messages'});resolveDone();return;}
   if(message.type==='error'){error=true;resolveDone();}
   emit({kind:'message',message,...(data?{binaryBase64:data.toString('base64')}:{})});
   if(config.mode!=='observe'&&message.type==='send'&&message.payload?.kind===config.mode)resolveDone();
  });
  await script.load(cancellable);loaded=true;emit({kind:'loaded'});observation=setTimeout(resolveDone,duration);await done;
 }finally{
  if(observation)clearTimeout(observation);finished=true;
  const cleanup=new frida.Cancellable(),cleanupDeadline=setTimeout(()=>cleanup.cancel(),2000);
  try{if(script&&!detached){await script.unload(cleanup);unloaded=true;}}catch(e){error=true;emit({kind:'cleanup-error',message:String(e)});}
  try{if(session&&!detached){await session.detach(cleanup);sessionDetached=true;}}catch(e){error=true;emit({kind:'cleanup-error',message:String(e)});}
  clearTimeout(cleanupDeadline);cleanup.cancel();clearTimeout(deadline);cancellable.cancel();process.off('SIGTERM',stop);
 }
 emit({kind:'completed',complete:!error&&unloaded&&sessionDetached,detached,scriptUnloaded:unloaded,sessionDetached});
 if(interrupted)process.exitCode=130;
}
main().catch(error=>{process.stderr.write(String(error)+'\n');process.exitCode=1;});
