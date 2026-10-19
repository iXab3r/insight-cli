/** Internal POSIX exec gate, not a daemon. The record exists before the requested executable runs. */
import {createReadStream} from 'node:fs';
import {readFile,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {atomicWrite,readJson} from './store.js';
import {processIdentity} from './identity.js';
async function main(){
 const [directory,id,fd]=process.argv.slice(2);if(!directory||!id||!/^[a-f0-9-]{36}$/.test(id))throw Error('Invalid launch identity');
 const root=await realpath(directory),path=join(root,'runtime/processes',id+'.json');
 const record=await readJson<Record<string,unknown>>(path);if(!record||record.id!==id||record.pid||record.ownerPid!==process.ppid)throw Error('Launch owner changed');
 let input='';for await(const b of createReadStream('',{fd:Number(fd),autoClose:true})){input+=b.toString();if(input.length>4*1024**2)throw Error('Launch input exceeds its bound');}
 // Factory's stable profile remains local while the complete runtime tree can be
 // an authorized analysis-storage alias. Child paths must still stay inside it.
 if(await realpath(String(record.root))!==join(await realpath(join(root,'runtime')),'runs',id))throw Error('Launch storage changed');
 const plan=JSON.parse(input) as {executable:string;arguments:string[];environment:Record<string,string>;nonce:string};
 if(plan.executable!==record.executable)throw Error('Launch executable changed');
 const identity=await processIdentity(process.pid);if(!identity)throw Error('Launch process identity unavailable');
 Object.assign(record,{pid:process.pid,identity:identity.birth,strongIdentity:identity.strong,processGroup:identity.group,phase:'armed'});await atomicWrite(path,record);
 await atomicWrite(join(String(record.root),'armed.json'),{pid:process.pid,nonce:plan.nonce});
 for(let i=0;i<400;i++){
  const grant=await readJson<{nonce:string}>(join(String(record.root),'go.json'));
  if(grant?.nonce===plan.nonce){
   try{process.execve!(plan.executable,[plan.executable,...plan.arguments],plan.environment);}
   catch(error){Object.assign(record,{state:'failed',phase:'exec_failed',launchError:(error as NodeJS.ErrnoException).code??'exec',endedAt:new Date().toISOString()});await atomicWrite(path,record);throw Error('Owned executable could not start');}
  }
  try{process.kill(Number(record.ownerPid),0);}catch{Object.assign(record,{state:'failed',phase:'owner_lost_before_exec'});await atomicWrite(path,record);return;}
  await delay(25);
 }
 Object.assign(record,{state:'failed',phase:'launch_grant_timeout'});await atomicWrite(path,record);
}
await main().catch(()=>{process.stderr.write('Owned tool launch gate failed.\n');process.exitCode=1;});
