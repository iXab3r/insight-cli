import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.util.*;

/** Native API edits and independent bounded observations; no merge implementation. */
public class ExtendedMergeCases {
    static Address at(Program p,long n){return NativeMergeFixture.address(p,n);}
    static long code(int i){return 0x1200+0x20*i;}
    static long data(int i){return 0x4000+0x100*i;}
    static Map<String,Object> fields(Structure s){
        return Map.of("length",s.getLength(),"fields",Arrays.stream(s.getComponents()).map(c->Map.of(
            "name",c.getFieldName(),"type",c.getDataType().getName(),"offset",c.getOffset())).toList());
    }
    static void edit(Program p,int i)throws Exception{
        var manager=p.getDataTypeManager();
        Structure record=(Structure)manager.getDataType("/Record"+i);
        EnumDataType status=new EnumDataType("Status"+i,4);status.add("ZERO",0);status.add("ACTOR",i+1);
        var keptEnum=manager.addDataType(status,DataTypeConflictHandler.DEFAULT_HANDLER);
        UnionDataType payload=new UnionDataType("Payload"+i);
        payload.add(IntegerDataType.dataType,"number",null);payload.add(LongLongDataType.dataType,"wide",null);
        var keptUnion=manager.addDataType(payload,DataTypeConflictHandler.DEFAULT_HANDLER);
        var alias=manager.addDataType(new TypedefDataType("PayloadAlias"+i,keptUnion),DataTypeConflictHandler.DEFAULT_HANDLER);
        record.add(keptEnum,"status",null);record.add(alias,"payload",null);
        NativeMergeFixture.require(p.getFunctionManager().removeFunction(at(p,0x1800+0x20*i)),"Native function deletion failed");
        NativeMergeFixture.require(manager.remove(manager.getDataType("/Obsolete"+i),TaskMonitor.DUMMY),"Native type deletion failed");
        manager.getDataType("/RenameMe"+i).setName("Renamed"+i);
        Namespace ns=p.getSymbolTable().createNameSpace(p.getGlobalNamespace(),"module_actor"+i,SourceType.USER_DEFINED);
        Function f=p.getFunctionManager().getFunctionAt(at(p,0x1000+0x20*i));
        f.setParentNamespace(ns);
        f.addLocalVariable(new LocalVariableImpl("local_"+i,IntegerDataType.dataType,-16-8*i,p),SourceType.USER_DEFINED);
        f.addTag("tag_actor"+i);
        p.getMemory().setBytes(at(p,code(i)),new byte[]{(byte)0xb8,(byte)(0x40+i),0,0,0,(byte)0xc3});
        NativeMergeFixture.require(new DisassembleCommand(at(p,code(i)),null,true).applyTo(p,TaskMonitor.DUMMY),"Native disassembly failed");
        Function created=p.getFunctionManager().createFunction("new_actor_"+i,at(p,code(i)),new AddressSet(at(p,code(i)),at(p,code(i)+5)),SourceType.USER_DEFINED);
        NativeMergeFixture.require(created!=null,"Function creation failed");
        p.getListing().createData(at(p,data(i)),record);
        p.getMemory().setByte(at(p,data(i)+0x30),(byte)(0x41+i));
        p.getSymbolTable().createLabel(at(p,data(i)),"record_"+i,ns,SourceType.USER_DEFINED);
        p.getReferenceManager().addMemoryReference(at(p,data(i)),f.getEntryPoint(),RefType.DATA,SourceType.USER_DEFINED,0);
        p.getBookmarkManager().setBookmark(at(p,data(i)),BookmarkType.NOTE,"actor_"+i,"native bookmark "+i);
        p.getListing().setComment(at(p,code(i)),CommentType.EOL,"comment_"+i);
        p.getEquateTable().createEquate("equate_actor"+i,0x40+i).addReference(at(p,code(i)),1);
        p.getUsrPropertyManager().createStringPropertyMap("map_actor"+i).add(at(p,data(i)),"property_"+i);
        p.getOptions("NativeMergeProof").setString("actor"+i,"option_"+i);
        ProgramModule tree=p.getListing().createRootModule("tree_actor"+i);
        tree.createFragment("fragment_actor"+i).move(at(p,code(i)),at(p,code(i)+5));
        var block=p.getMemory().getBlock(at(p,0x6000+0x100*i));
        block.setName("region_actor"+i);block.setComment("native region "+i);block.setWrite(true);
        p.getProgramContext().setValue(p.getRegister("RAX"),at(p,code(i)),at(p,code(i)),BigInteger.valueOf(100+i));
        var ext=p.getExternalManager().addExtFunction("lib_actor"+i,"external_"+i,null,SourceType.USER_DEFINED);
        ext.getFunction().setReturnType(keptEnum,SourceType.USER_DEFINED);
        p.getExternalManager().setExternalPath("lib_actor"+i,"/owned/lib_actor"+i,true);
    }
    static void jointEdit(Program p,int actor)throws Exception{
        Function f=p.getFunctionManager().getFunctionAt(at(p,0x1000));
        if(actor==0){f.setName("joint_function",SourceType.USER_DEFINED);p.getMemory().getBlock(at(p,0x6000)).setComment(null);}
        else if(actor==1){f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);f.getParameter(0).setName("joint_parameter",SourceType.USER_DEFINED);}
        else f.addLocalVariable(new LocalVariableImpl("joint_local",LongLongDataType.dataType,-64,p),SourceType.USER_DEFINED);
    }
    static void conflictEdit(Program p,int actor,String kind)throws Exception{
        if(kind.equals("function"))p.getFunctionManager().getFunctionAt(at(p,0x1000)).setReturnType(
            new PointerDataType(p.getDataTypeManager().getDataType("/Record"+actor),p.getDataTypeManager()),SourceType.USER_DEFINED);
        else if(kind.equals("builtin-return")||kind.equals("builtin-return-reverse")){
            boolean useFloat=(actor==0)==kind.equals("builtin-return");
            p.getFunctionManager().getFunctionAt(at(p,kind.equals("builtin-return-reverse")?0x1020:0x1000)).setReturnType(
                useFloat?FloatDataType.dataType:DoubleDataType.dataType,SourceType.USER_DEFINED);
        }
        else if(kind.equals("bytes"))p.getMemory().setByte(at(p,0x4f00),(byte)(0x10+actor));
        else if(kind.equals("block-comment"))p.getMemory().getBlock(at(p,0x6100)).setComment(actor==0?null:"changed_comment");
        else if(kind.equals("block-comment-clear"))p.getMemory().getBlock(at(p,0x6200)).setComment(actor==0?"changed_comment":null);
        else throw new IllegalArgumentException("Unknown native conflict case");
    }
    static Map<String,Object> inspect(Program p){
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<3;i++){
            Map<String,Object> row=new LinkedHashMap<>();
            Function f=p.getFunctionManager().getFunctionAt(at(p,0x1000+0x20*i));
            row.put("functionPath",f.getName(true));
            row.put("locals",Arrays.stream(f.getLocalVariables()).map(v->Map.of("name",v.getName(),"type",v.getDataType().getName(),"storage",v.getVariableStorage().toString())).toList());
            row.put("tags",f.getTags().stream().map(FunctionTag::getName).sorted().toList());
            var listing=p.getListing();var dtm=p.getDataTypeManager();
            row.put("returnTypeId",dtm.getID(f.getReturnType()));
            row.put("returnStorage",f.getReturn().getVariableStorage().toString());
            var instruction=listing.getInstructionAt(at(p,code(i)));row.put("instruction",instruction==null?null:instruction.toString());
            row.put("comment",listing.getComment(CommentType.EOL,at(p,code(i))));
            var created=p.getFunctionManager().getFunctionAt(at(p,code(i)));row.put("createdFunction",created==null?null:created.getName());
            var defined=listing.getDataAt(at(p,data(i)));row.put("definedData",defined==null?null:defined.getDataType().getName());
            row.put("record",fields((Structure)dtm.getDataType("/Record"+i)));
            var status=dtm.getDataType("/Status"+i);row.put("enumValue",status==null?null:((ghidra.program.model.data.Enum)status).getValue("ACTOR"));
            var union=dtm.getDataType("/Payload"+i);row.put("union",union==null?null:((Union)union).getNumComponents());
            var alias=dtm.getDataType("/PayloadAlias"+i);row.put("typedef",alias==null?null:((TypeDef)alias).getBaseDataType().getName());
            if(status!=null&&union!=null&&alias!=null)row.put("newTypeIdentities",Map.of(
                "enum",status.getUniversalID().toString(),"union",union.getUniversalID().toString(),"typedef",alias.getUniversalID().toString()));
            row.put("deletedFunctionAbsent",p.getFunctionManager().getFunctionAt(at(p,0x1800+0x20*i))==null);
            row.put("deletedTypeAbsent",dtm.getDataType("/Obsolete"+i)==null);
            row.put("renamedType",dtm.getDataType("/RenameMe"+i)==null&&dtm.getDataType("/Renamed"+i)!=null);
            var ns=p.getSymbolTable().getNamespace("module_actor"+i,p.getGlobalNamespace());
            row.put("label",ns==null?null:!p.getSymbolTable().getSymbols("record_"+i,ns).isEmpty());
            row.put("references",Arrays.stream(p.getReferenceManager().getReferencesFrom(at(p,data(i)))).map(r->Map.of("to",r.getToAddress().toString(),"kind",r.getReferenceType().toString(),"source",r.getSource().toString())).toList());
            var bookmark=p.getBookmarkManager().getBookmark(at(p,data(i)),BookmarkType.NOTE,"actor_"+i);row.put("bookmark",bookmark==null?null:bookmark.getComment());
            var equate=p.getEquateTable().getEquate("equate_actor"+i);row.put("equate",equate==null?null:Map.of("value",equate.getValue(),"references",equate.getReferenceCount()));
            var property=p.getUsrPropertyManager().getStringPropertyMap("map_actor"+i);row.put("property",property==null?null:property.getString(at(p,data(i))));
            row.put("option",p.getOptions("NativeMergeProof").getString("actor"+i,null));
            var tree=listing.getRootModule("tree_actor"+i);row.put("tree",tree==null?null:Arrays.stream(tree.getChildren()).map(Group::getName).sorted().toList());
            var fragment=listing.getFragment("tree_actor"+i,"fragment_actor"+i);row.put("fragmentContainsCode",fragment==null?null:fragment.contains(at(p,code(i))));
            var block=p.getMemory().getBlock(at(p,0x6000+0x100*i));row.put("block",Map.of("name",block.getName(),"comment",block.getComment()==null?"":block.getComment(),"write",block.isWrite()));
            row.put("register",p.getProgramContext().getValue(p.getRegister("RAX"),at(p,code(i)),false));
            var ext=p.getExternalManager().getUniqueExternalLocation("lib_actor"+i,"external_"+i);row.put("external",ext==null?null:Map.of("name",ext.getLabel(),"returnType",ext.getFunction().getReturnType().getName()));
            if(defined!=null&&status!=null&&union!=null&&alias!=null&&ext!=null&&f.getParameterCount()>0){
                DataType record=dtm.getDataType("/Record"+i);
                DataType pointerTarget=((Pointer)f.getParameter(0).getDataType()).getDataType();
                row.put("typeBindings",Map.of("signatureRecord",dtm.getID(pointerTarget)==dtm.getID(record),
                    "definedRecord",dtm.getID(defined.getDataType())==dtm.getID(record),
                    "recordEnum",dtm.getID(((Structure)record).getComponent(2).getDataType())==dtm.getID(status),
                    "recordAlias",dtm.getID(((Structure)record).getComponent(3).getDataType())==dtm.getID(alias),
                    "aliasUnion",dtm.getID(((TypeDef)alias).getBaseDataType())==dtm.getID(union),
                    "externalEnum",dtm.getID(ext.getFunction().getReturnType())==dtm.getID(status)));
            }
            row.put("externalPath",p.getExternalManager().getExternalLibraryPath("lib_actor"+i));
            try{row.put("patchedByte",Byte.toUnsignedInt(p.getMemory().getByte(at(p,data(i)+0x30))));}catch(Exception e){throw new IllegalStateException(e);}
            result.put("actor"+i,row);
        }
        try{result.put("conflictByte",Byte.toUnsignedInt(p.getMemory().getByte(at(p,0x4f00))));}catch(Exception e){throw new IllegalStateException(e);}
        return result;
    }
}
