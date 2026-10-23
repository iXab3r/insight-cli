// Counterbalance build order as well as transport order; all native work is disposable.
import assert from 'node:assert/strict';
import {parseArgs} from 'node:util';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {nativeProofGuard} from './native-proof-guard.mjs';
import {compareRecordedPair} from './benchmark-cli-compare.mjs';
const {values:o}=parseArgs({options:{before:{type:'string'},after:{type:'string'},root:{type:'string'},java:{type:'string'},'ghidra-home':{type:'string'},rounds:{type:'string',default:'24'},'ack-disposable':{type:'boolean'}}});
nativeProofGuard(o['ack-disposable']);for(const k of ['before','after','root','java','ghidra-home'])assert.ok(o[k],k);
const rounds=Number(o.rounds);assert.ok(Number.isSafeInteger(rounds)&&rounds>=4&&rounds<=100);
const root=resolve(o.root),gates=join(root,'gates');await mkdir(root);await mkdir(gates);
const runner=fileURLToPath(new URL('benchmark-cli-overhead.mjs',import.meta.url)),client=join(resolve(o.after),'dist/src/persistent-client.js');
const exits=[];let failure;
const wait=async name=>{const until=Date.now()+600000;for(;;){if(failure)throw failure;if(Date.now()>until)throw Error('Benchmark gate timeout');try{await readFile(join(gates,name));return;}catch(e){if(e.code!=='ENOENT')throw e;}await delay(100);}};
const start=label=>{
 const child=spawn(process.execPath,[runner,'--ack-disposable','--package',resolve(o[label]),'--persistent-client',client,'--root',join(root,label),'--java',resolve(o.java),'--ghidra-home',resolve(o['ghidra-home']),'--rounds',String(rounds),'--round-gates',gates,'--label',label],{stdio:'inherit'});
 const exit=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>code===0?resolve():reject(Error(label+' benchmark failed '+code)));});exit.catch(e=>{failure=e;});exits.push(exit);
};
try{
 start('before');await wait('before.ready');start('after');await wait('after.ready');
 for(let round=0;round<rounds;round++)for(const label of round%2?['after','before']:['before','after']){
  await writeFile(join(gates,label+'.'+round+'.go'),'go\n');await wait(label+'.'+round+'.done');
 }
 await writeFile(join(gates,'complete'),'complete\n');await Promise.all(exits);
 await writeFile(join(root,'result.json'),JSON.stringify(await compareRecordedPair(root),null,2)+'\n',{mode:0o600});
 console.log('Counterbalanced installed before/after workload PASS');
}finally{await writeFile(join(gates,'cancel'),'cancel\n');await Promise.allSettled(exits);}
