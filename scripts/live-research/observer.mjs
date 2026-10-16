// Native identity/CPU observation only; no research results are obtained from internal state.
import {readFile,appendFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {exec} from '../business/public-cli.mjs';
const path=process.argv[2],initial=JSON.parse(await readFile(path,'utf8'));
const seconds=text=>text.split(':').reduce((n,p)=>60*n+Number(p),0);
const deadline=Date.now()+3600000;
while(Date.now()<deadline) {
 const t=JSON.parse(await readFile(path,'utf8'));if(t.state!=='researching')break;
 const cpu={};
 for(const {pid} of initial.native) {
  const r=await exec('ps',['-p',String(pid),'-o','time=,command=']);
  const [time,...command]=r.stdout.trim().split(/\s+/);
  if(!command.join(' ').includes('InsightHeadlessMain')||!command.join(' ').includes(initial.profile))throw Error('Observed process ownership changed');
  cpu[pid]=seconds(time);
 }
 await appendFile(join(initial.directory,'native-observations.jsonl'),JSON.stringify({monotonicNs:process.hrtime.bigint().toString(),utc:new Date().toISOString(),cpu})+'\n',{mode:0o600});
 await delay(1000);
}
