import {readdir} from 'node:fs/promises';
import {join,relative,isAbsolute} from 'node:path';
import {richEdit,richReadback,inline} from './rich-findings.mjs';

// Session status exposes a number; repository administration exposes a decimal string.
export const hasServerCheckout=(listing,id)=>listing.checkouts.some(c=>c.id===String(id));

export const extendedOutcomes=[
 'Both data models retain their definitions and executable bindings',
 "Both agents' evidence remains navigable and retains its meaning",
 'Both corrections retain code, regions and execution assumptions',
 'Neither byte correction nor supporting private work is lost',
 'Deletion versus revision requires a decision and preserves work',
 'Revision versus deletion requires a decision and preserves work',
 "One shared function retains all three agents' complementary findings",
 'Both simultaneous contributions become independently readable',
 'One private copy survives iterations and is removed after delivery',
 'Contributions and copies are attributable under separate authority',
 'Incoming float and private double survive without a silent winner',
 'Incoming double and private float survive without a silent winner'
];

export async function extendedWorkflow(n,h){
 const {a,b,cli,m,scope,script,rename,name,comment,text,merge,receive,reader,reopen,checkout,history,check}=h;
 const readScript=async(s,code,marker)=>{const result=await script(s,code);check('Fresh public readback verifies '+marker,result.value?.success===true&&result.value.output?.includes(marker),result.value);};
 if(n>=21&&n<=23){
  const kind={21:'model',22:'navigation',23:'execution'}[n];
  await Promise.all([script(a,richEdit(kind,0)),script(b,richEdit(kind,1))]);await merge(a);await receive(b);await merge(b);
  const r=await reader();await readScript(r,richReadback(kind),'BUSINESS_READBACK_'+kind.toUpperCase()+'_BOTH_AGENTS');
 } else if(n===24||n===25||n===26){
  const bytes=n===24,latest=n===25?'null':'"changed description"',local=n===25?'"changed description"':'null';
  const edit=(s,value)=>script(s,inline(bytes?`currentProgram.getMemory().setByte(toAddr(0x1130),(byte)${value});`:`currentProgram.getMemory().getBlock(toAddr(0x2000)).setComment(${value});`));
  const inspect=(s,value,marker)=>readScript(s,inline((bytes?`expect(Byte.toUnsignedInt(currentProgram.getMemory().getByte(toAddr(0x1130)))==${value},"Saved byte");`:`expect(java.util.Objects.equals(currentProgram.getMemory().getBlock(toAddr(0x2000)).getComment(),${value}),"Saved region description");`)+`println("${marker}");`),marker);
  await edit(a,bytes?'17':latest);await edit(b,bytes?'34':local);await comment(a,'Shared supporting finding','1020');await comment(b,'Private supporting finding');
  await merge(a);const before=(await history(a.target)).versions.length,held=await checkout(b),conflict=await receive(b,{allowFailure:true});
  check('Contradictory analysis requires an explicit decision',conflict.code!==0&&conflict.value?.state==='conflict',conflict.value);
  await inspect(b,bytes?'34':local,'PRIVATE_VALUE_RETAINED');const r=await reader();await inspect(r,bytes?'17':latest,'SHARED_VALUE_RETAINED');
  check('Neither unrelated private work nor shared work is lost',await text(b)==='Private supporting finding'&&await text(r)===null&&await text(r,'1020')==='Shared supporting finding');
  check('Refused receive retains ancestry and creates no publication',(await checkout(b)).id===held.id&&(await history(a.target)).versions.length===before);
 } else if(n===27){
  const c=await cli.fresh(a.target);
  await rename(a,'joint_finding');
  await script(b,inline('currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000)).setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);'));
  await script(c,inline('currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000)).addLocalVariable(new LocalVariableImpl("reconstructed_local",LongLongDataType.dataType,-64,currentProgram),SourceType.USER_DEFINED);'));
  await merge(a);await merge(b);await merge(c);const r=await reader();
  await readScript(r,inline(`var f=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000));
   expect(f.getName().equals("joint_finding"),"Combined function name");expect(f.getReturnType().getName().equals("uint"),"Combined result type");
   expect(java.util.Arrays.stream(f.getLocalVariables()).anyMatch(v->v.getName().equals("reconstructed_local")&&v.getDataType().isEquivalent(LongLongDataType.dataType)&&v.getDataType().getLength()==8&&v.isStackVariable()&&v.getStackOffset()==-64),"Combined local variable type and stack storage");
   println("JOINT_FINDING_FROM_THREE_AGENTS");`),'JOINT_FINDING_FROM_THREE_AGENTS');
 } else if(n===28){
  await rename(a,'parallel_a');await rename(b,'parallel_b','1020');const before=(await history(a.target)).versions.length,start=cli.calls.length;
  await Promise.all([merge(a),merge(b)]);const calls=cli.calls.slice(start),r=await reader();
  check('Both simultaneous delivery requests complete',calls.length===2&&Math.min(...calls.map(c=>c.ended))>Math.max(...calls.map(c=>c.started)));
  check('Both findings are shared with exactly two new revisions',await name(r)==='parallel_a'&&await name(r,'1020')==='parallel_b'&&(await history(a.target)).versions.length===before+2);
 } else if(n===29){
  async function inventory(){const result=[];async function walk(at){for(const e of await readdir(at,{withFileTypes:true})){const path=join(at,e.name);if(e.isDirectory()){if(e.name.endsWith('.rep'))result.push(path);await walk(path);}else if(/\.(gpr|gzf)$/i.test(e.name))result.push(path);}}await walk(m.workspace);return result.sort();}
  const before=await inventory(),held=await checkout(b),server=await cli.call(['ghidra','server','status']);
  const checkouts=()=>cli.call(['ghidra','server','checkouts','--repository',server.repository,'--path','/'+a.target+'.bin']);
  const initial=await checkouts();
  check('The repository lists B\'s exact checkout before delivery',hasServerCheckout(initial,held.id));
  for(let i=0;i<3;i++){await rename(b,'iteration_'+i);await scope(b,'save');await cli.close(b);await reopen(b);check('Iteration '+i+' reuses the saved server checkout',(await checkout(b)).id===held.id&&await name(b)==='iteration_'+i);}
  const after=await inventory();check('Repeated commands do not accumulate full program copies',JSON.stringify(after)===JSON.stringify(before),{before:before.length,after:after.length});
  check('Repeated commands do not accumulate server checkouts',(await checkouts()).checkouts.length===initial.checkouts.length);
  const worker=(await cli.call(['tools','processes','--tool','ghidra','--session',b.session,'--target',b.target])).items.find(p=>p.role==='context'&&p.state==='running');
  const root=worker?.metadata?.contextRoot;check('The private project is bound to B\'s actual native worker',typeof root==='string'&&relative(m.workspace,root)!==''&&!relative(m.workspace,root).startsWith('..')&&!isAbsolute(relative(m.workspace,root)));
  const ownedPair=[join(root,'view.gpr'),join(root,'view.rep')];check('B\'s exact project and database are present before delivery',ownedPair.every(p=>before.includes(p)));
  await merge(b);const released=await checkouts();check('Verified delivery releases the actual server checkout',!hasServerCheckout(released,held.id));
  const dropped=await inventory(),expected=before.filter(p=>!ownedPair.includes(p));
  check('Verified delivery removes B\'s exact project/database with no replacement copies',JSON.stringify(dropped)===JSON.stringify(expected),{before:before.length,after:dropped.length,expected:expected.length});
 } else if(n===30){
  const server=await cli.call(['ghidra','server','status']),repository=server.repository;
  const permissions=await cli.call(['ghidra','server','admin','permissions','--repository',repository]);
  check('Owned repository separates read and publication authority',permissions.users.some(u=>u.name==='reader'&&u.access===0)&&permissions.users.some(u=>u.name==='publisher'&&u.access===2)&&permissions.anonymous===false,permissions);
  const copies=await cli.call(['ghidra','server','checkouts','--repository',repository,'--path','/'+a.target+'.bin']);
  const heldA=await checkout(a),heldB=await checkout(b);check('Repository lists both independent checkouts',hasServerCheckout(copies,heldA.id)&&hasServerCheckout(copies,heldB.id));
  const before=await history(a.target);await rename(b,'auditable_finding');await merge(b);const after=await history(a.target),latest=after.versions.reduce((a,b)=>a.version>b.version?a:b);
  check('Repository records one attributable contribution',after.versions.length===before.versions.length+1&&latest.user==='publisher'&&typeof latest.comment==='string'&&latest.comment.startsWith('insight native '),latest);
  const r=await reader();check('Recorded contribution is independently usable',await name(r)==='auditable_finding');
 } else if(n===31||n===32){
  const incoming=n===31?'float':'double',privateType=n===31?'double':'float';
  await scope(a,'functions set-function-prototype',['--address','1000','--prototype',incoming+' baseline_0(void)']);
  await scope(b,'functions set-function-prototype',['--address','1000','--prototype',privateType+' baseline_0(void)']);
  await comment(b,'Private note with conflicting signature');await merge(a);const before=(await history(a.target)).versions.length;
  const conflict=await receive(b,{allowFailure:true});check('First-time float/double disagreement is refused',conflict.code!==0&&conflict.value?.state==='conflict',conflict.value);
  const r=await reader(),shared=await scope(r,'functions get',['--address','1000']),local=await scope(b,'functions get',['--address','1000']);
  check('Both exact result types and private notes survive the disagreement',shared.signature===incoming+' baseline_0(void)'&&local.signature===privateType+' baseline_0(void)'&&await text(b)==='Private note with conflicting signature'&&await text(r)===null,{shared:shared.signature,local:local.signature});
  check('Rejected signature receive creates no revision',(await history(a.target)).versions.length===before);
 } else throw Error('Unknown extended workflow '+n);
}
