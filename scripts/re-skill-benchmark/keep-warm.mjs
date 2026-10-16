// Test-side warm-process control. Ordinary ReadOnly metadata; no target-specific queries.
import {readFile,appendFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {PublicCli,json} from '../business/public-cli.mjs';
const trial=process.argv[2],initial=await json(trial),m=await json(initial.manifest);
const stamp=()=>({monotonicNs:process.hrtime.bigint().toString(),utc:new Date().toISOString()});
const emit=row=>appendFile(join(initial.directory,'maintenance.jsonl'),JSON.stringify(row)+'\n',{mode:0o600});
const cli=new PublicCli(m,join(initial.directory,'maintenance-calls'),initial.profile),deadline=Date.now()+3600000;
await emit({phase:'started',at:stamp()});
while(Date.now()<deadline){
 const t=await json(trial);if(t.state==='passed'){await emit({phase:'stopped',reason:'task-finished',at:stamp()});console.log('Warm control maintenance finished');process.exit(0);}
 const started=stamp();try{const value=await cli.call(['targets','list','--limit','1']);if(value.items.length!==1)throw Error('Expected one owned target');await emit({phase:'call',started,ended:stamp(),ok:true});}
 catch(error){await emit({phase:'call',started,ended:stamp(),ok:false});throw error;}
 await delay(15000);
}
throw Error('Warm control deadline expired; retain diagnostics');
