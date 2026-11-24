// Business workflows use installed public CLI processes only. No product imports or MCP calls.
import assert from 'node:assert/strict';
import {writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {PublicCli} from '../business/public-cli.mjs';
import {extendedWorkflow,extendedOutcomes} from './extended-workflows.mjs';
import {regions,navigationBaseline,inline} from './rich-findings.mjs';
import {fixtureFor} from './fixtures.mjs';

const definition=v=>v&&typeof v==='object'&&Array.isArray(v.fields)?{name:v.name,size:v.size,alignment:v.alignment,fields:v.fields.map(({offset,size,type,name})=>({offset,size,type,name}))}:null;
const exact=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const singleField=(name,type,size)=>({name,size,alignment:1,fields:[{offset:0,size,type,name:'count'}]});

export const outcomes = [
 'Each agent sees only its own unpublished name',
 'A fresh agent reads both function names',
 'A fresh agent reads both complete structure definitions',
 'A fresh agent reads both revised types and neither retired type',
 'Float survives receiving, delivery and fresh readback',
 'Double survives receiving, delivery and fresh readback',
 'Incoming and private findings survive further work and delivery',
 'Incoming findings appear without publishing another revision',
 'The same checkout retains findings and can deliver more work',
 'Private reads remain stable until an explicit receive',
 'The agreed name is delivered without a false conflict',
 'All private work survives and no partial result is delivered',
 'The conflict identifies the function and all three alternatives',
 'The chosen name and unrelated findings are delivered and usable',
 'The chosen type and unrelated findings are delivered and usable',
 'Original-request retry leaves exactly one accepted revision',
 'Verified delivery releases the copy and continued work is fresh',
 'The conflict identifies the type and all three alternatives',
 'Saved private and shared findings remain usable and deliverable',
 'The private worker is offline and delivery goes through service',
 ...extendedOutcomes
];

const baseline = `import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;import ghidra.program.model.address.*;import ghidra.program.model.symbol.SourceType;
public class BusinessBaseline extends GhidraScript {public void run() throws Exception {
 for(int i=0;i<3;i++) {var at=toAddr(0x1000+0x20*i);
 currentProgram.getFunctionManager().createFunction("baseline_"+i,at,new AddressSet(at,at.add(15)),SourceType.USER_DEFINED);
 var t=new StructureDataType("Record"+i,0);t.add(IntegerDataType.dataType,"count",null);currentProgram.getDataTypeManager().addDataType(t,DataTypeConflictHandler.DEFAULT_HANDLER);
 var o=new StructureDataType("Obsolete"+i,0);o.add(IntegerDataType.dataType,"old",null);currentProgram.getDataTypeManager().addDataType(o,DataTypeConflictHandler.DEFAULT_HANDLER);}
}}`;
const typeChange=(index,kind='LongLong',retire=true)=>`import ghidra.app.script.GhidraScript;import ghidra.program.model.data.*;
public class BusinessTypeChange extends GhidraScript {public void run() throws Exception {
 var m=currentProgram.getDataTypeManager();var t=(Structure)m.getDataType("/Record${index}");
 t.replace(0,${kind}DataType.dataType,${kind==='Double'||kind==='LongLong'?8:4},"count",null);
 ${retire?`m.remove(m.getDataType("/Obsolete${index}"),monitor);`:''}
}}`;

export async function workflow(id,m,directory,record) {
 const n=Number(id.slice(3)),cli=new PublicCli(m,directory),checks=[];
 const check=(expectation,condition,observed)=>{checks.push({expectation,passed:!!condition,...(observed===undefined?{}:{observed})});record.checks=checks;assert.ok(condition,expectation+(observed===undefined?'':': '+JSON.stringify(observed)));};
 const scope=(s,words,args=[],options)=>cli.scoped(s,words,args,options);
 const script=(s,code)=>scope(s,'scripts run-inline',['--code',code]);
 const rename=(s,name,at='1000')=>scope(s,'functions rename',['--address',at,'--name',name]);
 const name=async(s,at='1000')=>(await scope(s,'functions get',['--address',at])).name;
 const comment=(s,text,at='1040')=>cli.comment(s,at,text);
 const text=(s,at='1040')=>cli.readComment(s,at);
 const merge=(s,args=[],options)=>scope(s,'merge',args,options);
 const receive=(s,options)=>scope(s,'refresh',[],options);
 const layout=async(s,t)=>(await scope(s,'types struct-layout',['--name',t])).value;
 const checkout=async s=>(await cli.status(s)).ghidra.checkout;
 const history=target=>cli.history(target);
 let a,b,input,failure;
 const reader=async()=>cli.fresh(a.target);
 const reopen=async s=>{const value=await cli.call(['ghidra','open',...cli.selectors(s)]);cli.scopes.push(value);return value;};
 const closeAll=()=>cli.cleanup();
 try {
  // Different immutable bytes make each scenario a separate server program, even in one repository.
  const fixture=fixtureFor(id);input=join(m.directory,fixture.name);const bytes=fixture.bytes;record.inputFile=fixture.name;await writeFile(input,bytes);
  record.inputSha256=createHash('sha256').update(bytes).digest('hex');
  a=await cli.open(input,'new',fixture.options);
  record.target=a.target;await script(a,baseline);
  if([23,25,26].includes(n))await script(a,regions);
  if(n===22)await script(a,navigationBaseline);
  await merge(a);await reopen(a);b=await cli.open(input);
  const ca=await checkout(a),cb=await checkout(b);
  check('Agents have independent server checkouts of one program',a.target===b.target&&a.session!==b.session&&ca.id!==cb.id&&ca.baseRevision===cb.baseRevision);
  if(n===1){
   const workers=(await cli.call(['tools','processes','--tool','ghidra','--target',a.target])).items.filter(p=>p.role==='context'&&p.state==='running');
   const wa=workers.find(p=>p.session===a.session),wb=workers.find(p=>p.session===b.session);
   check('Two distinct verified native workers investigate simultaneously',!!wa&&!!wb&&wa.pid!==wb.pid);
   const edit=(who,label,peerPid)=>inline(`var began=java.time.Instant.now();
    var own=java.nio.file.Path.of(${JSON.stringify(join(m.directory,'GS-01-'+who+'.ready'))});
    var peer=java.nio.file.Path.of(${JSON.stringify(join(m.directory,'GS-01-'+(who==='a'?'b':'a')+'.ready'))});
    var temp=java.nio.file.Path.of(own.toString()+".tmp");java.nio.file.Files.writeString(temp,Long.toString(ProcessHandle.current().pid()),java.nio.file.StandardOpenOption.CREATE_NEW);
    java.nio.file.Files.move(temp,own,java.nio.file.StandardCopyOption.ATOMIC_MOVE);
    long deadline=System.nanoTime()+60000000000L;
    while(!java.nio.file.Files.exists(peer)){monitor.checkCancelled();if(System.nanoTime()>deadline)throw new IllegalStateException("Other native worker did not enter its investigation");Thread.sleep(10);}
    expect(java.nio.file.Files.readString(peer).equals("${peerPid}"),"Peer native identity");
    currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000)).setName("${label}",SourceType.USER_DEFINED);
    var ended=java.time.Instant.now();var billion=BigInteger.valueOf(1000000000L);
    println("{\\"pid\\":"+ProcessHandle.current().pid()+",\\"startedNanos\\":\\""+BigInteger.valueOf(began.getEpochSecond()).multiply(billion).add(BigInteger.valueOf(began.getNano()))+"\\",\\"endedNanos\\":\\""+BigInteger.valueOf(ended.getEpochSecond()).multiply(billion).add(BigInteger.valueOf(ended.getNano()))+"\\"}");`);
   const results=await Promise.all([script(a,edit('a','private_a',wb.pid)),script(b,edit('b','private_b',wa.pid))]);
   const intervals=results.map(r=>JSON.parse(r.value.output.trim()));
   const latestStart=intervals.map(v=>BigInt(v.startedNanos)).reduce((a,b)=>a>b?a:b),earliestEnd=intervals.map(v=>BigInt(v.endedNanos)).reduce((a,b)=>a<b?a:b);
   check('Work actually overlaps inside both native processes',intervals[0].pid===wa.pid&&intervals[1].pid===wb.pid&&earliestEnd>latestStart,intervals);
   check('Each agent retains its own name',await name(a)==='private_a'&&await name(b)==='private_b');
   const r=await reader();check('Unpublished findings are absent for a fresh agent',await name(r)==='baseline_0');
  } else if(n===2){
   await Promise.all([rename(a,'finding_a'),rename(b,'finding_b','1020')]);await merge(a);await merge(b);
   const r=await reader();check('Both complementary names are independently readable',await name(r)==='finding_a'&&await name(r,'1020')==='finding_b');
  } else if(n===3){
   for(const [s,t] of [[a,'FindingA'],[b,'FindingB']])await scope(s,'types create-struct',['--name',t,'--fields',JSON.stringify([{name:'kind',type:'int'},{name:'value',type:'double'}])]);
   await merge(a);await merge(b);const r=await reader();
   for(const t of ['FindingA','FindingB']){const v=await layout(r,t);check(t+' retains its exact definition',exact(definition(v),{name:t,size:12,alignment:1,fields:[{offset:0,size:4,type:'int',name:'kind'},{offset:4,size:8,type:'double',name:'value'}]}),v);}
  } else if(n===4){
   await script(a,typeChange(0));await script(b,typeChange(1));await merge(a);await merge(b);const r=await reader();
   for(const i of [0,1]){const v=await layout(r,'Record'+i);check('Revised Record'+i+' retains its exact definition',exact(definition(v),singleField('Record'+i,'longlong',8)),v);}
   const absent=await script(r,inline('expect(currentProgram.getDataTypeManager().getDataType("/Obsolete0")==null&&currentProgram.getDataTypeManager().getDataType("/Obsolete1")==null,"Both retired definitions must be absent");println("BOTH_RETIRED_TYPES_ABSENT");'));
   check('A successful fresh read proves both retired types are absent',absent.value?.success===true&&absent.value.output?.includes('BOTH_RETIRED_TYPES_ABSENT'),absent.value);
  } else if(n===5||n===6){
   const kind=n===5?'float':'double',peer=n===5?'double':'float';
   await scope(a,'functions set-function-prototype',['--address','1000','--prototype',kind+' baseline_0(void)']);
   await scope(b,'functions set-function-prototype',['--address','1020','--prototype',peer+' baseline_1(void)']);await comment(b,'Independent note');
   await merge(a);await receive(b);const v=await scope(b,'functions get',['--address','1000']);check('Received signature preserves '+kind,v.signature===kind+' baseline_0(void)',v.signature);
   check('Private note survives incoming signature',await text(b)==='Independent note');await merge(b);const r=await reader();
   const published=await scope(r,'functions get',['--address','1000']);check('Published signature and independent note are readable',published.signature===kind+' baseline_0(void)'&&await text(r)==='Independent note',published.signature);
   const peerPublished=await scope(r,'functions get',['--address','1020']);check('The other first-time numeric type is preserved too',peerPublished.signature===peer+' baseline_1(void)',peerPublished.signature);
  } else if(n===7){
   await rename(a,'colleague');await comment(b,'In progress');await merge(a);await receive(b);
   check('Incoming name and private note coexist',await name(b)==='colleague'&&await text(b)==='In progress');
   await rename(b,'continued','1020');await merge(b);const r=await reader();
   check('Continued investigation delivers all findings',await name(r)==='colleague'&&await name(r,'1020')==='continued'&&await text(r)==='In progress');
  } else if(n===8||n===10){
   await rename(a,'incoming');await merge(a);const before=(await history(a.target)).versions.length;
   if(n===10)check('Reads do not silently receive findings',await name(b)==='baseline_0');
   await receive(b);check('Explicit receive obtains the published name',await name(b)==='incoming');
   check('Receiving does not publish another revision',(await history(a.target)).versions.length===before);
  } else if(n===9){
   await rename(b,'saved_private');await cli.close(a);await cli.close(b);await cli.call(['ipc-server','stop'],{global:true});await reopen(b);
   const resumed=await checkout(b);check('The exact saved checkout is reopened',resumed.id===cb.id&&resumed.baseRevision===cb.baseRevision);
   check('Saved private finding survives owner restart',await name(b)==='saved_private');await comment(b,'Further work');await merge(b);const r=await reader();
   check('Resumed investigation delivers old and new work',await name(r)==='saved_private'&&await text(r)==='Further work');
  } else if(n===11){
   await rename(a,'agreed');await rename(b,'agreed');await merge(a);const v=await merge(b);
   check('Identical findings do not conflict',['merged','empty'].includes(v.state),v);const r=await reader();check('Agreed result is readable',await name(r)==='agreed');
  } else if([12,13,14,15,18].includes(n)){
   const typeCase=n===15||n===18;
   if(typeCase){await script(a,typeChange(0,'Float',false));await script(b,typeChange(0,'Double',false));}
   else {await rename(a,'choice_a');await rename(b,'choice_b');}
   await comment(a,'Unrelated A','1020');await comment(b,'Unrelated B');await merge(a);
   const before=(await history(a.target)).versions.length,conflict=await receive(b,{allowFailure:true});
   check('A genuine conflicting receive is reported',conflict.code!==0&&conflict.value?.state==='conflict',conflict.value);
   const readPrivate=async()=>typeCase?(await layout(b,'Record0')).fields?.[0]?.type==='double':await name(b)==='choice_b';
   check('Conflicting private work and unrelated work remain saved',await readPrivate()&&await text(b)==='Unrelated B');
   const denied=await merge(b,[],{allowFailure:true});check('Unresolved set cannot be delivered',denied.code!==0&&denied.value?.state==='conflict',denied.value);
   let r=await reader();check('No partial delivery and no extra revision',await text(r)===null&&await text(r,'1020')==='Unrelated A'&&(await history(a.target)).versions.length===before);
   if(n===12){await cli.close(r);await cli.close(b);await reopen(b);check('Conflict and entire private set survive reopening',(await cli.status(b)).ghidra.conflicts.length>0&&await readPrivate()&&await text(b)==='Unrelated B');}
   if(n===13||n===18){
    const details=(await cli.status(b)).ghidra.conflicts;
    check(typeCase?'The conflict identifies Record0 and original/local/shared definitions':'The conflict identifies address 1000 and original/local/shared names',
     details.some(c=>typeCase?
      exact(definition(c.original),singleField('Record0','int',4))&&exact(definition(c.local),singleField('Record0','double',8))&&exact(definition(c.shared),singleField('Record0','float',4)):
      String(c.address).replace(/^0x/,'').replace(/^0+/,'')==='1000'&&c.original==='baseline_0'&&c.local==='choice_b'&&c.shared==='choice_a'),details);
   }
   if(n===14||n===15){
    // An explicit agent decision: preserve B's conflicting finding and both unrelated notes.
    // The current shared copy already contains A's note. Apply selected B values through public operations.
    if(typeCase){const selected=await layout(b,'Record0');check('Agent can inspect the exact selected definition',exact(definition(selected),singleField('Record0','double',8)),selected);await script(r,typeChange(0,'Double',false));}
    else {const selected=await name(b);check('Agent can inspect both names',selected==='choice_b'&&await name(r)==='choice_a');await rename(r,selected);}
    await comment(r,await text(b));await merge(r);await scope(b,'changes discard');await cli.close(r);
    r=await reader();check('Chosen finding and both unrelated notes are independently readable',(typeCase?exact(definition(await layout(r,'Record0')),singleField('Record0','double',8)):await name(r)==='choice_b')&&await text(r)==='Unrelated B'&&await text(r,'1020')==='Unrelated A');
    await receive(a);await rename(a,'continued_a','1020');await merge(a);await receive(b);await rename(b,'continued_b','1040');await merge(b);await cli.close(r);r=await reader();
    check('Both original agents continue without losing the settled result or unrelated work',await name(r,'1020')==='continued_a'&&await name(r,'1040')==='continued_b'&&(typeCase?exact(definition(await layout(r,'Record0')),singleField('Record0','double',8)):await name(r)==='choice_b')&&await text(r)==='Unrelated B'&&await text(r,'1020')==='Unrelated A');
   }
  } else if(n===16){
   await comment(b,'Reply was lost');const before=(await history(a.target)).versions.length,request='business-lost-reply';
   await merge(b,['--request-id',request],{discardReply:true});const r=await reader();check('Delivery is independently established after the lost reply',await text(r)==='Reply was lost');
   await merge(b,['--request-id',request]);check('Original request creates exactly one accepted revision',(await history(a.target)).versions.length===before+1);
  } else if(n===17){
   await rename(b,'first_delivery');await merge(b);const delivered=await checkout(b);check('Verified delivery releases the original checkout',delivered.state==='dropped');
   await reopen(b);const next=await checkout(b);check('Continued work receives a new current checkout',next.id!==cb.id&&next.state!=='dropped');
   await rename(b,'next_delivery','1020');await merge(b);const r=await reader();check('Both contribution cycles remain readable',await name(r)==='first_delivery'&&await name(r,'1020')==='next_delivery');
  } else if(n===19){
   const serverBefore=(await cli.call(['tools','processes','--tool','ghidra'])).items.find(p=>p.role==='server'&&p.state==='running');
   check('The owned repository service has a verified process identity',!!serverBefore);
   await rename(a,'before_server_restart');await merge(a);await comment(b,'Saved during restart');await closeAll();
   await cli.call(['ghidra','server','stop']);const stopped=await cli.call(['ghidra','server','status']);check('The owned repository service is stopped',stopped.connected===false);
   await cli.call(['ghidra','server','connect']);const serverAfter=(await cli.call(['tools','processes','--tool','ghidra'])).items.find(p=>p.role==='server'&&p.state==='running');
   check('Restart uses a new owned server process identity',!!serverAfter&&serverAfter.id!==serverBefore.id);
   await reopen(b);check('Private work survives owned server restart',await text(b)==='Saved during restart');await receive(b);await merge(b);
   const r=await reader();check('Restarted repository retains and combines both findings',await name(r)==='before_server_restart'&&await text(r)==='Saved during restart');
  } else if(n===20){
   await script(b,`import ghidra.app.script.GhidraScript;public class WorkerBoundary extends GhidraScript {public void run()throws Exception {
    if(currentProgram.getDomainFile().getParent().getProjectData().getRepository().isConnected())throw new SecurityException("Private worker is connected");
    for(String k:System.getenv().keySet())if(k.matches("(?i).*(SERVER_PASSWORD|PUBLISHER_PASSWORD).*"))throw new SecurityException("Publication credential in worker");
    currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000)).setName("credentialless_finding",ghidra.program.model.symbol.SourceType.USER_DEFINED);
   }}`);
   const r=await reader();check('Offline worker edits remain private',await name(b)==='credentialless_finding'&&await name(r)==='baseline_0');await cli.close(r);await merge(b);const fresh=await reader();check('Service delivery makes the finding shared',await name(fresh)==='credentialless_finding');
  } else await extendedWorkflow(n,{a,b,cli,m,scope,script,rename,name,comment,text,merge,receive,reader,reopen,checkout,history,check});
 } catch(e){failure=e;throw e;}
 finally {
  try{await closeAll();record.cleanupComplete=true;
   if(input){assert.equal(createHash('sha256').update(await readFile(input)).digest('hex'),record.inputSha256,'Immutable fixture changed');record.inputUnchanged=true;}
  }catch(e){if(failure)throw new AggregateError([failure,e],'Business expectation and cleanup failed');throw e;}
 }
 record.checks=checks;
}
