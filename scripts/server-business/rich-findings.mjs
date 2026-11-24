// Public inline-script inputs and explicit golden assertions for richer research outcomes.
// These are agent operations, never a test-side merger or a product/backend import.
const imports=`import ghidra.app.script.GhidraScript;import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.math.BigInteger;`;
const wrap=body=>`${imports}
public class RichBusinessFinding extends GhidraScript {
 void expect(boolean v,String message){if(!v)throw new IllegalStateException(message);}
 public void run()throws Exception {${body}}
}`;

export const regions=wrap(`for(int i=0;i<2;i++){
 var start=toAddr(0x2000+0x1000*i);var block=currentProgram.getMemory().getBlock(start);
 expect(block!=null&&block.getStart().equals(start),"Loader-established region "+i);
 block.setComment("original description");
}`);

export const navigationBaseline=wrap(`for(int i=0;i<2;i++){
 var at=toAddr(0x1200+0x20*i);currentProgram.getMemory().setBytes(at,new byte[]{(byte)0xb8,(byte)(0x40+i),0,0,0,(byte)0xc3});
 expect(new DisassembleCommand(at,null,true).applyTo(currentProgram,monitor),"Known clue instruction");
}`);

export function richEdit(kind,i){
 if(kind==='model')return wrap(`var m=currentProgram.getDataTypeManager();
 var e=new EnumDataType("Status${i}",4);e.add("ACTIVE",${i+1});var status=m.addDataType(e,DataTypeConflictHandler.DEFAULT_HANDLER);
 var u=new UnionDataType("Payload${i}");u.add(IntegerDataType.dataType,"number",null);u.add(DoubleDataType.dataType,"measurement",null);
 var payload=m.addDataType(u,DataTypeConflictHandler.DEFAULT_HANDLER);
 var alias=m.addDataType(new TypedefDataType("PayloadAlias${i}",payload),DataTypeConflictHandler.DEFAULT_HANDLER);
 var record=(Structure)m.getDataType("/Record${i}");record.add(status,"status",null);record.add(alias,"payload",null);
 currentProgram.getListing().createData(toAddr(${0x1100+0x40*i}),record);
 currentProgram.getFunctionManager().getFunctionAt(toAddr(${0x1000+0x20*i})).setReturnType(new PointerDataType(record,m),SourceType.USER_DEFINED);`);
 if(kind==='navigation')return wrap(`var p=currentProgram;var at=toAddr(${0x1100+0x40*i});var code=toAddr(${0x1000+0x20*i});
 var ns=p.getSymbolTable().createNameSpace(p.getGlobalNamespace(),"module_${i}",SourceType.USER_DEFINED);
 var f=p.getFunctionManager().getFunctionAt(code);f.setParentNamespace(ns);f.addTag("reviewed_${i}");
 p.getSymbolTable().createLabel(at,"record_${i}",ns,SourceType.USER_DEFINED);
 p.getReferenceManager().addMemoryReference(at,code,RefType.DATA,SourceType.USER_DEFINED,0);
 p.getBookmarkManager().setBookmark(at,BookmarkType.NOTE,"investigation_${i}","verified clue ${i}");
 p.getListing().setComment(code,CommentType.EOL,"evidence ${i}");
 p.getEquateTable().createEquate("meaning_${i}",${0x40+i}).addReference(toAddr(${0x1200+0x20*i}),1);
 p.getUsrPropertyManager().createStringPropertyMap("evidence_${i}").add(at,"source ${i}");
 p.getOptions("Investigation").setString("agent${i}","conclusion ${i}");
 var tree=p.getListing().createRootModule("investigation_${i}");tree.createFragment("reviewed_${i}").move(code,code.add(15));`);
 if(kind==='execution')return wrap(`var p=currentProgram;var at=toAddr(${0x1200+0x20*i});
 p.getMemory().setBytes(at,new byte[]{(byte)0xb8,(byte)${0x40+i},0,0,0,(byte)0xc3});
 expect(new DisassembleCommand(at,null,true).applyTo(p,monitor),"Patched code must disassemble");
 expect(p.getFunctionManager().createFunction("corrected_${i}",at,new AddressSet(at,at.add(5)),SourceType.USER_DEFINED)!=null,"New function");
 expect(p.getFunctionManager().removeFunction(toAddr(${0x1000+0x20*i})),"Retired function");
 var block=p.getMemory().getBlock(toAddr(${0x2000+0x1000*i}));block.setName("region_${i}");block.setComment("verified region ${i}");block.setWrite(true);
 p.getProgramContext().setValue(p.getRegister("RAX"),at,at,BigInteger.valueOf(${100+i}));
 var external=p.getExternalManager().addExtFunction("library_${i}","external_${i}",null,SourceType.USER_DEFINED);
 external.getFunction().setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED);
 p.getExternalManager().setExternalPath("library_${i}","/owned/library_${i}",true);`);
 throw Error('Unknown rich finding kind');
}

export function richReadback(kind){
 let body='var p=currentProgram;var m=p.getDataTypeManager();';
 for(const i of [0,1]){
  if(kind==='model')body+=`{
   var record=(Structure)m.getDataType("/Record${i}");var status=(ghidra.program.model.data.Enum)m.getDataType("/Status${i}");
   var payload=(Union)m.getDataType("/Payload${i}");var alias=(TypeDef)m.getDataType("/PayloadAlias${i}");
   expect(record.getNumComponents()==3,"Record ${i} fields");expect(status.getValue("ACTIVE")==${i+1},"Enum ${i} value");
   expect(record.getLength()==16&&record.getComponent(0).getOffset()==0&&record.getComponent(0).getLength()==4&&record.getComponent(0).getFieldName().equals("count")&&record.getComponent(0).getDataType().getName().equals("int"),"Record ${i} original count field");
   expect(record.getComponent(1).getOffset()==4&&record.getComponent(1).getFieldName().equals("status")&&record.getComponent(2).getOffset()==8&&record.getComponent(2).getFieldName().equals("payload"),"Record ${i} dependent field layout");
   expect(payload.getNumComponents()==2&&payload.getLength()==8,"Union ${i} alternatives");
   expect(payload.getComponent(0).getFieldName().equals("number")&&payload.getComponent(0).getDataType().getName().equals("int")&&payload.getComponent(0).getLength()==4,"Union ${i} numeric alternative");
   expect(payload.getComponent(1).getFieldName().equals("measurement")&&payload.getComponent(1).getDataType().getName().equals("double")&&payload.getComponent(1).getLength()==8,"Union ${i} measurement alternative");
   expect(m.getID(alias.getBaseDataType())==m.getID(payload),"Typedef ${i} binding");
   expect(m.getID(record.getComponent(1).getDataType())==m.getID(status),"Record ${i} enum binding");
   expect(m.getID(record.getComponent(2).getDataType())==m.getID(alias),"Record ${i} alias binding");
   expect(m.getID(p.getListing().getDataAt(toAddr(${0x1100+0x40*i})).getDataType())==m.getID(record),"Defined data ${i} binding");
   var pointer=(Pointer)p.getFunctionManager().getFunctionAt(toAddr(${0x1000+0x20*i})).getReturnType();
   expect(m.getID(pointer.getDataType())==m.getID(record),"Signature ${i} binding");
  }`;
  else if(kind==='navigation')body+=`{
   var at=toAddr(${0x1100+0x40*i});var code=toAddr(${0x1000+0x20*i});
   var ns=p.getSymbolTable().getNamespace("module_${i}",p.getGlobalNamespace());expect(ns!=null,"Namespace ${i}");
   var f=p.getFunctionManager().getFunctionAt(code);expect(f.getParentNamespace().equals(ns),"Function ${i} namespace");
   expect(!p.getSymbolTable().getSymbols("record_${i}",ns).isEmpty(),"Label ${i}");
   expect(java.util.Arrays.stream(p.getReferenceManager().getReferencesFrom(at)).anyMatch(r->r.getToAddress().equals(code)&&r.getReferenceType()==RefType.DATA),"Reference ${i}");
   expect("verified clue ${i}".equals(p.getBookmarkManager().getBookmark(at,BookmarkType.NOTE,"investigation_${i}").getComment()),"Bookmark ${i}");
   expect("evidence ${i}".equals(p.getListing().getComment(CommentType.EOL,code)),"Comment ${i}");
   expect(p.getEquateTable().getEquate("meaning_${i}").getValue()==${0x40+i}&&p.getEquateTable().getEquate("meaning_${i}").getReferenceCount()==1,"Equate ${i}");
   expect("source ${i}".equals(p.getUsrPropertyManager().getStringPropertyMap("evidence_${i}").getString(at)),"Property ${i}");
   expect("conclusion ${i}".equals(p.getOptions("Investigation").getString("agent${i}",null)),"Option ${i}");
   expect(p.getListing().getFragment("investigation_${i}","reviewed_${i}").contains(code),"Tree ${i}");
   expect(f.getTags().stream().anyMatch(t->t.getName().equals("reviewed_${i}")),"Tag ${i}");
  }`;
  else if(kind==='execution')body+=`{
   var at=toAddr(${0x1200+0x20*i});var bytes=new byte[6];p.getMemory().getBytes(at,bytes);
   expect(java.util.Arrays.equals(bytes,new byte[]{(byte)0xb8,(byte)${0x40+i},0,0,0,(byte)0xc3}),"Code ${i} bytes");
   expect(p.getListing().getInstructionAt(at)!=null,"Code ${i} disassembly");
   expect("corrected_${i}".equals(p.getFunctionManager().getFunctionAt(at).getName()),"New function ${i}");
   expect(p.getFunctionManager().getFunctionAt(toAddr(${0x1000+0x20*i}))==null,"Retired function ${i}");
   var block=p.getMemory().getBlock(toAddr(${0x2000+0x1000*i}));
   expect(block.getName().equals("region_${i}")&&"verified region ${i}".equals(block.getComment())&&block.isWrite(),"Region ${i}");
   expect(BigInteger.valueOf(${100+i}).equals(p.getProgramContext().getValue(p.getRegister("RAX"),at,false)),"Register ${i}");
   var ext=p.getExternalManager().getUniqueExternalLocation("library_${i}","external_${i}");
   expect(ext!=null&&"int".equals(ext.getFunction().getReturnType().getName()),"External function ${i}");
   expect("/owned/library_${i}".equals(p.getExternalManager().getExternalLibraryPath("library_${i}")),"External path ${i}");
  }`;
  else throw Error('Unknown rich finding kind');
 }
 return wrap(body+`println("BUSINESS_READBACK_${kind.toUpperCase()}_BOTH_AGENTS");`);
}

export const inline=wrap;
