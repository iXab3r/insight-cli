import { Store } from '../src/store.js';
import { Coordinator, type Publisher } from '../src/coordinator.js';
import { readFileSync, writeFileSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { key, type Target, type Binding, type FindingRecord } from '../src/model.js';
const [directory, phase] = process.argv.slice(2);
if (!directory || !phase) throw Error('Missing synthetic crash arguments');
const identity={profile:'default',server:'ghidra://127.0.0.1:14100',repository:'alpha',programPath:'/fixture.exe',binarySha256:'a'.repeat(64),language:'x86:LE:64:default',compilerSpec:'windows',imageBase:'140000000'};
const store=new Store(directory,'default',identity.server),target=store.register(identity);
store.putWorker('reader',target.id,{pid:process.pid,endpoint:'http://127.0.0.1:19000',projectDirectory:'/synthetic',identity,version:1,role:'reader'});
store.submit({requestId:'accepted-request',findingId:'accepted-finding',targetId:target.id,identity,workerId:'reader',baselineVersion:1,address:'140001000',kind:'eol',before:null,after:'Synthetic accepted finding',evidence:'Synthetic evidence'});
const path=join(directory,'synthetic-remote.json');
const persist=(value:unknown)=>{const fd=openSync(path,'w',0o600);try{writeFileSync(fd,JSON.stringify(value));fsyncSync(fd);}finally{closeSync(fd);}};
persist({version:1,values:{},markers:[]});let values:Record<string,string|null>={};
const binding=(t:Target):Binding=>({pid:process.pid,endpoint:'http://127.0.0.1:19000',projectDirectory:directory,identity:t,version:1,role:'publisher'});
const publisher:Publisher={
 open:async t=>binding(t),checkout:async t=>({identity:t,version:1,values:{}}),read:async(t,_b,f)=>({identity:t,version:1,values:Object.fromEntries(f.map(x=>[key(x),values[key(x)]??null]))}),
 apply:async(_t,_b,f)=>{values[key(f)]=f.after;},save:async()=>persist({version:1,values,markers:[]}),
 checkIn:async(_t,_b,batchId)=>{persist({version:2,values,markers:[batchId]});return 2;},
 published:async(t,f)=>({identity:t,version:2,values}),history:async(_t,id)=>JSON.parse(readFileSync(path,'utf8')).markers.includes(id)?[2]:[],released:async()=>true,release:async()=>{},complete:async()=>{},abandon:async()=>{},
};
await new Coordinator(store,publisher,async name=>{if(name===phase)process.kill(process.pid,'SIGKILL');}).integrate(target.id);
store.close();
