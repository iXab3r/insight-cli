package insight;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.task.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Selected typed SDK workflows. Every edit is verified again on an immutable saved Program. */
public class InsightSdkTools {
    public static class Rejected extends Exception {
        public Rejected(Exception cause) {super("SDK transaction rolled back",cause);}
    }
    public static String text(JsonObject p, String key) {
        return p.has(key) && !p.get(key).isJsonNull() ? p.get(key).getAsString() : "";
    }
    static int integer(JsonObject p, String key, int fallback, int max) {
        int n=p.has(key)?p.get(key).getAsInt():fallback;
        if(n<1||n>max)throw new IllegalArgumentException("Invalid "+key+" bound");
        return n;
    }
    static Address at(Program program, String value) {
        Address address=program.getAddressFactory().getAddress(value);
        if(address==null)throw new IllegalArgumentException("Address is not in this program's address spaces");
        return address;
    }
    static byte[] hex(String value) {
        if(value.isEmpty()||value.length()>8192||!value.matches("(?:[a-fA-F0-9]{2})+"))
            throw new IllegalArgumentException("Expected 1–4096 complete hex bytes");
        return HexFormat.of().parseHex(value);
    }
    static byte[] bytes(Program program, Address start, int size) throws Exception {
        byte[] bytes=new byte[size];
        if(program.getMemory().getBytes(start,bytes)!=size)throw new IllegalStateException("Incomplete memory range");
        return bytes;
    }
    static String hash(Program program, Address start, long size) throws Exception {
        if(size<1||size>16777216)throw new IllegalArgumentException("Memory verification bound is 16 MiB");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        for(long offset=0;offset<size;){int count=(int)Math.min(65536,size-offset);hash.update(bytes(program,start.add(offset),count));offset+=count;}
        return HexFormat.of().formatHex(hash.digest());
    }
    static MemoryBlock block(Program program, String name) {
        // Ghidra's name lookup cache can retain a removed block until transaction completion.
        MemoryBlock block=Arrays.stream(program.getMemory().getBlocks()).filter(value->value.getName().equals(name)).findFirst().orElse(null);
        if(block==null)throw new IllegalArgumentException("Memory block does not exist");
        return block;
    }
    static Map<String,Object> blockState(Program program, MemoryBlock b) throws Exception {
        Map<String,Object> row=new LinkedHashMap<>();
        row.put("name",b.getName());row.put("start",b.getStart().toString());row.put("end",b.getEnd().toString());
        row.put("size",b.getSize());row.put("initialized",b.isInitialized());row.put("overlay",b.isOverlay());
        row.put("read",b.isRead());row.put("write",b.isWrite());row.put("execute",b.isExecute());
        row.put("sha256",b.isInitialized()?hash(program,b.getStart(),b.getSize()):null);return row;
    }
    static void require(boolean condition, String message) {
        if(!condition)throw new IllegalStateException(message);
    }
    static Namespace namespace(Program program,String path) {
        Namespace current=program.getGlobalNamespace();
        if(path.isEmpty()||path.equals("Global"))return current;
        for(String name:path.split("::",-1)){
            if(name.isEmpty())throw new IllegalArgumentException("Invalid namespace path");
            current=program.getSymbolTable().getNamespace(name,current);
            if(current==null)throw new IllegalArgumentException("Namespace does not exist");
        }
        return current;
    }
    static Map<String,Object> namespaceState(Namespace value) {
        return Map.of("path",value.getName(true),"name",value.getName(),"kind",value.getSymbol().getSymbolType().toString(),
            "parent",value.getParentNamespace().isGlobal()?"":value.getParentNamespace().getName(true));
    }
    static ExternalLocation external(Program program,JsonObject p) {
        ExternalLocation value=program.getExternalManager().getUniqueExternalLocation(text(p,"library"),text(p,"label"));
        if(value==null)throw new IllegalArgumentException("External location is absent or ambiguous");return value;
    }
    static Map<String,Object> externalState(ExternalLocation value) {
        Map<String,Object> row=new LinkedHashMap<>();row.put("library",value.getLibraryName());row.put("label",value.getLabel());
        row.put("address",value.getAddress()==null?null:value.getAddress().toString());row.put("function",value.isFunction());
        row.put("symbol_address",value.getExternalSpaceAddress().toString());row.put("source",value.getSource().toString());return row;
    }
    static byte[] assembly(Program program,JsonObject p) throws Exception {
        JsonArray input=p.getAsJsonArray("instructions");
        if(input==null||input.isEmpty()||input.size()>64)throw new IllegalArgumentException("Assembly requires 1–64 instructions");
        var assembler=Assemblers.getAssembler(program);Address address=at(program,text(p,"address"));
        var output=new java.io.ByteArrayOutputStream();
        for(JsonElement row:input){String line=row.getAsString();if(line.length()>512||line.contains("\n"))throw new IllegalArgumentException("Instruction is not bounded single-line text");
            byte[] value=assembler.assembleLine(address,line);output.write(value);address=address.add(value.length);}
        if(output.size()>4096)throw new IllegalArgumentException("Assembly exceeds 4096 bytes");return output.toByteArray();
    }
    public static Object read(Program program,String operation,JsonObject p,TaskMonitor monitor) throws Exception {
        switch(operation) {
            case "block-state": return blockState(program,block(program,text(p,"name")));
            case "assembly-preview": {
                byte[] value=assembly(program,p);
                return Map.of("address",at(program,text(p,"address")).toString(),"bytes_hex",HexFormat.of().formatHex(value),
                    "size",value.length,"language",program.getLanguageID().toString(),"context_aware",true);
            }
            case "context-read": {
                Register register=program.getRegister(text(p,"register"));
                if(register==null)throw new IllegalArgumentException("Unknown processor register");
                Address start=at(program,text(p,"address")),end=p.has("end_address")?at(program,text(p,"end_address")):start;
                if(!start.getAddressSpace().equals(end.getAddressSpace())||start.compareTo(end)>0)throw new IllegalArgumentException("Invalid context range");
                List<Object> rows=new ArrayList<>();var ranges=program.getProgramContext().getRegisterValueAddressRanges(register,start,end);
                int limit=integer(p,"limit",100,1000);
                while(ranges.hasNext()&&rows.size()<limit){AddressRange range=ranges.next();var value=program.getProgramContext().getRegisterValue(register,range.getMinAddress());
                    var explicit=program.getProgramContext().getNonDefaultValue(register,range.getMinAddress());
                    rows.add(Map.of("start",range.getMinAddress().toString(),"end",range.getMaxAddress().toString(),"known",value.hasValue(),"explicit",explicit!=null&&explicit.hasAnyValue(),
                        "value","0x"+value.getUnsignedValueIgnoreMask().toString(16),"mask","0x"+value.getValueMask().toString(16)));}
                return Map.of("register",register.getName(),"bits",register.getBitLength(),"ranges",rows,"complete",!ranges.hasNext());
            }
            case "namespace-list": {
                Namespace parent=namespace(program,text(p,"parent"));var iter=program.getSymbolTable().getSymbols(parent);
                int limit=integer(p,"limit",100,1000),visited=0,budget=integer(p,"max_scan",10000,200000);List<Object> rows=new ArrayList<>();
                while(iter.hasNext()&&rows.size()<limit&&visited<budget){monitor.checkCancelled();Symbol symbol=iter.next();visited++;
                    if(symbol.getSymbolType()==SymbolType.NAMESPACE||symbol.getSymbolType()==SymbolType.CLASS)rows.add(namespaceState((Namespace)symbol.getObject()));}
                return Map.of("items",rows,"visited",visited,"complete",!iter.hasNext());
            }
            case "external-list": {
                var manager=program.getExternalManager();List<Object> rows=new ArrayList<>();int limit=integer(p,"limit",100,1000);
                String library=text(p,"library");
                if(library.isEmpty()){String[] names=manager.getExternalLibraryNames();for(int i=0;i<Math.min(names.length,limit);i++){
                    Map<String,Object> row=new LinkedHashMap<>();row.put("name",names[i]);row.put("path",manager.getExternalLibraryPath(names[i]));rows.add(row);}
                    return Map.of("items",rows,"complete",names.length<=limit);}
                var iter=manager.getExternalLocations(library);while(iter.hasNext()&&rows.size()<limit){monitor.checkCancelled();rows.add(externalState(iter.next()));}
                return Map.of("items",rows,"complete",!iter.hasNext());
            }
            case "decompiler-ir": return decompile(program,p,monitor);
            case "type-layout": return InsightSdkTypes.layout(program.getDataTypeManager().getDataType(text(p,"path")));
            default: throw new IllegalArgumentException("Unknown typed SDK read");
        }
    }
    public static Object mutate(Program program,String operation,JsonObject p,TaskMonitor monitor) throws Exception {
        int transaction=program.startTransaction("insight "+operation);boolean committed=false,closed=false;
        try {
            var memory=program.getMemory();var symbols=program.getSymbolTable();var externals=program.getExternalManager();
            switch(operation) {
                case "type-structure": case "type-settings": case "type-archive-import":InsightSdkTypes.edit(program,operation,p,monitor);break;
                case "patch-bytes": case "assemble": {
                    Address start=at(program,text(p,"address"));byte[] expected=hex(text(p,"expect_hex"));
                    byte[] desired=operation.equals("assemble")?assembly(program,p):hex(text(p,"bytes_hex"));
                    if(expected.length!=desired.length)throw new IllegalArgumentException("Expected and replacement lengths must match");
                    require(Arrays.equals(bytes(program,start,expected.length),expected),"Memory byte precondition changed");
                    program.getListing().clearCodeUnits(start,start.add(desired.length-1),false,monitor);memory.setBytes(start,desired);break;
                }
                case "split-block": {
                    MemoryBlock original=block(program,text(p,"name"));require(hash(program,original.getStart(),original.getSize()).equals(text(p,"expect_sha256")),"Block content precondition changed");
                    require(original.getStart().equals(at(program,text(p,"expect_start")))&&original.getSize()==p.get("expect_size").getAsLong(),"Block layout precondition changed");
                    Address split=at(program,text(p,"split_address"));memory.split(original,split);memory.getBlock(split).setName(text(p,"new_name"));break;
                }
                case "move-block": {
                    MemoryBlock original=block(program,text(p,"name"));require(hash(program,original.getStart(),original.getSize()).equals(text(p,"expect_sha256")),"Block content precondition changed");
                    require(original.getStart().equals(at(program,text(p,"expect_start")))&&original.getSize()==p.get("expect_size").getAsLong(),"Block layout precondition changed");
                    memory.moveBlock(original,at(program,text(p,"address")),monitor);break;
                }
                case "join-blocks": {
                    MemoryBlock first=block(program,text(p,"name")),second=block(program,text(p,"second_name"));
                    require(first.getSize()==p.get("expect_size").getAsLong()&&second.getSize()==p.get("second_size").getAsLong(),"Block sizes changed");
                    require(first.getEnd().next().equals(second.getStart()),"Blocks must be adjacent in the declared order");
                    require(hash(program,first.getStart(),first.getSize()).equals(text(p,"expect_sha256"))&&hash(program,second.getStart(),second.getSize()).equals(text(p,"second_sha256")),"Block contents changed");
                    memory.join(first,second);break;
                }
                case "context-set": {
                    Register register=program.getRegister(text(p,"register"));if(register==null)throw new IllegalArgumentException("Unknown processor register");
                    Address start=at(program,text(p,"address")),end=at(program,text(p,"end_address"));
                    program.getProgramContext().setValue(register,start,end,new BigInteger(text(p,"value").replaceFirst("^0x",""),16));break;
                }
                case "context-clear": {
                    Register register=program.getRegister(text(p,"register"));if(register==null)throw new IllegalArgumentException("Unknown processor register");
                    program.getProgramContext().remove(at(program,text(p,"address")),at(program,text(p,"end_address")),register);break;
                }
                case "namespace-create": {
                    Namespace parent=namespace(program,text(p,"parent"));
                    if(p.has("class")&&p.get("class").getAsBoolean())symbols.createClass(parent,text(p,"name"),SourceType.USER_DEFINED);
                    else symbols.createNameSpace(parent,text(p,"name"),SourceType.USER_DEFINED);break;
                }
                case "namespace-update": {
                    Namespace value=namespace(program,text(p,"path"));require(!value.isGlobal()&&!value.isExternal()&&!value.getSymbol().getSymbolType().equals(SymbolType.FUNCTION),"Only ordinary namespaces/classes can be edited");
                    value.getSymbol().setNameAndNamespace(text(p,"new_name"),namespace(program,text(p,"parent")),SourceType.USER_DEFINED);break;
                }
                case "namespace-delete": {
                    Namespace value=namespace(program,text(p,"path"));require(!value.isGlobal()&&!value.isExternal()&&!value.getSymbol().getSymbolType().equals(SymbolType.FUNCTION),"Only ordinary namespaces/classes can be deleted");
                    require(!symbols.getSymbols(value).hasNext(),"Namespace must be empty");require(value.getSymbol().delete(),"Namespace deletion was refused");break;
                }
                case "library-create": externals.addExternalLibraryName(text(p,"name"),SourceType.USER_DEFINED);break;
                case "library-update": {
                    require(externals.contains(text(p,"name")),"External library does not exist");
                    if(p.has("new_name"))externals.updateExternalLibraryName(text(p,"name"),text(p,"new_name"),SourceType.USER_DEFINED);
                    if(p.has("path"))externals.setExternalPath(p.has("new_name")?text(p,"new_name"):text(p,"name"),text(p,"path"),true);break;
                }
                case "library-delete": require(externals.removeExternalLibrary(text(p,"name")),"Library is absent or still contains external locations");break;
                case "external-create": {
                    require(externals.contains(text(p,"library")),"Create the explicit external library first");
                    require(externals.getExternalLocations(text(p,"library"),text(p,"label")).isEmpty(),"External label already exists");
                    Address address=p.has("address")?at(program,text(p,"address")):null;
                    if(p.has("function")&&p.get("function").getAsBoolean())externals.addExtFunction(text(p,"library"),text(p,"label"),address,SourceType.USER_DEFINED);
                    else externals.addExtLocation(text(p,"library"),text(p,"label"),address,SourceType.USER_DEFINED);break;
                }
                case "external-update": {
                    ExternalLocation value=external(program,p);value.setLocation(text(p,"new_label"),p.has("address")?at(program,text(p,"address")):value.getAddress(),SourceType.USER_DEFINED);break;
                }
                case "external-delete": {
                    ExternalLocation value=external(program,p);Address address=value.getExternalSpaceAddress();
                    require(!program.getReferenceManager().hasReferencesTo(address),"External location has retained references");
                    if(value.isFunction())program.getFunctionManager().removeFunction(address);
                    Symbol remaining=symbols.getPrimarySymbol(address);
                    if(remaining!=null)require(remaining.delete(),"External location deletion was refused");break;
                }
                default: throw new IllegalArgumentException("Unknown typed SDK edit");
            }
            Object verified=verify(program,operation,p,monitor);committed=true;return Map.of("success",true,"effect",verified);
        } catch(Exception failure) {
            // A rejection receipt is emitted only after native rollback returned successfully.
            closed=true;program.endTransaction(transaction,false);throw new Rejected(failure);
        } finally {if(!closed)program.endTransaction(transaction,committed);}
    }
    public static Object verify(Program program,String operation,JsonObject p,TaskMonitor monitor) throws Exception {
        switch(operation) {
            case "type-structure": case "type-settings": case "type-archive-import":return InsightSdkTypes.verify(program,operation,p,monitor);
            case "patch-bytes": case "assemble": {
                byte[] desired=operation.equals("assemble")?assembly(program,p):hex(text(p,"bytes_hex"));
                Address address=at(program,text(p,"address"));require(Arrays.equals(bytes(program,address,desired.length),desired),"Saved replacement bytes differ");
                return Map.of("verified",true,"address",address.toString(),"bytes_hex",HexFormat.of().formatHex(desired),"size",desired.length);
            }
            case "move-block": {
                MemoryBlock value=block(program,text(p,"name"));require(value.getStart().equals(at(program,text(p,"address")))&&value.getSize()==p.get("expect_size").getAsLong(),"Saved moved layout differs");
                require(hash(program,value.getStart(),value.getSize()).equals(text(p,"expect_sha256")),"Saved moved bytes differ");return blockState(program,value);
            }
            case "split-block": {
                MemoryBlock first=block(program,text(p,"name")),second=block(program,text(p,"new_name"));
                require(first.getStart().equals(at(program,text(p,"expect_start")))&&second.getStart().equals(at(program,text(p,"split_address")))&&first.getEnd().next().equals(second.getStart())&&first.getSize()+second.getSize()==p.get("expect_size").getAsLong(),"Saved split layout differs");
                require(hash(program,first.getStart(),first.getSize()+second.getSize()).equals(text(p,"expect_sha256")),"Saved split bytes differ");
                return Map.of("first",blockState(program,first),"second",blockState(program,second));
            }
            case "join-blocks": {
                MemoryBlock value=block(program,text(p,"name"));long size=p.get("expect_size").getAsLong(),other=p.get("second_size").getAsLong();
                require(value.getSize()==size+other&&Arrays.stream(program.getMemory().getBlocks()).noneMatch(item->item.getName().equals(text(p,"second_name"))),"Saved joined layout differs");
                require(hash(program,value.getStart(),size).equals(text(p,"expect_sha256"))&&hash(program,value.getStart().add(size),other).equals(text(p,"second_sha256")),"Saved joined bytes differ");return blockState(program,value);
            }
            case "context-set": case "context-clear": {
                Register register=program.getRegister(text(p,"register"));Address start=at(program,text(p,"address")),end=at(program,text(p,"end_address"));
                var context=program.getProgramContext();BigInteger expected=operation.equals("context-clear")?null:new BigInteger(text(p,"value").replaceFirst("^0x",""),16);
                Address cursor=start;
                for(int visited=0;cursor.compareTo(end)<=0;visited++){
                    if(visited>=65536)throw new IllegalArgumentException("Context verification exceeds 65536 bytes");
                    if(expected==null){var explicit=context.getNonDefaultValue(register,cursor);require(explicit==null||!explicit.hasAnyValue(),"Saved explicit processor context remains");}
                    else require(Objects.equals(context.getValue(register,cursor,false),expected),"Saved processor context differs");cursor=cursor.next();
                }
                return Map.of("verified",true,"register",register.getName(),"start",start.toString(),"end",end.toString());
            }
            case "namespace-create": case "namespace-update": {
                String name=operation.equals("namespace-create")?text(p,"name"):text(p,"new_name"),parent=text(p,"parent");
                Namespace value=namespace(program,parent.isEmpty()?name:parent+"::"+name);
                if(operation.equals("namespace-create"))require(value.getSymbol().getSymbolType()==(p.has("class")&&p.get("class").getAsBoolean()?SymbolType.CLASS:SymbolType.NAMESPACE),"Saved namespace kind differs");return namespaceState(value);
            }
            case "namespace-delete": {
                String path=text(p,"path");int i=path.lastIndexOf("::");Namespace parent=namespace(program,i<0?"":path.substring(0,i));
                require(program.getSymbolTable().getNamespace(i<0?path:path.substring(i+2),parent)==null,"Saved namespace still exists");return Map.of("deleted",true);
            }
            case "library-create": case "library-update": {
                String name=p.has("new_name")?text(p,"new_name"):text(p,"name");var manager=program.getExternalManager();require(manager.contains(name),"Saved library is absent");
                if(p.has("path"))require(Objects.equals(manager.getExternalLibraryPath(name),text(p,"path")),"Saved library path differs");
                return Map.of("name",name,"path",Objects.toString(manager.getExternalLibraryPath(name),""));
            }
            case "library-delete": require(!program.getExternalManager().contains(text(p,"name")),"Saved library still exists");return Map.of("deleted",true);
            case "external-create": case "external-update": {
                String label=p.has("new_label")?text(p,"new_label"):text(p,"label");var value=program.getExternalManager().getUniqueExternalLocation(text(p,"library"),label);
                require(value!=null,"Saved external location is absent or ambiguous");
                if(p.has("address"))require(at(program,text(p,"address")).equals(value.getAddress()),"Saved external address differs");
                if(p.has("function"))require(value.isFunction()==p.get("function").getAsBoolean(),"Saved external kind differs");return externalState(value);
            }
            case "external-delete": require(program.getExternalManager().getExternalLocations(text(p,"library"),text(p,"label")).isEmpty(),"Saved external location remains");return Map.of("deleted",true);
            default:throw new IllegalArgumentException("Unknown saved SDK verification");
        }
    }
    static Map<String,Object> varnode(Varnode value) {
        return Map.of("space",value.getAddress().getAddressSpace().getName(),"offset","0x"+Long.toUnsignedString(value.getOffset(),16),"size",value.getSize(),"unique_id",value instanceof VarnodeAST ast?ast.getUniqueId():-1);
    }
    static Object decompile(Program program,JsonObject p,TaskMonitor monitor) throws Exception {
        Function function=program.getFunctionManager().getFunctionAt(at(program,text(p,"address")));
        if(function==null)throw new IllegalArgumentException("No function starts at this address");
        String style=p.has("simplification")?text(p,"simplification"):"decompile";
        if(!List.of("decompile","normalize","firstpass","register","paramid").contains(style))throw new IllegalArgumentException("Unknown simplification style");
        int limit=integer(p,"max_ops",1000,10000),seconds=integer(p,"timeout_seconds",30,120);
        DecompInterface decompiler=new DecompInterface();
        try {
            DecompileOptions options=new DecompileOptions();options.grabFromProgram(program);options.setMaxPayloadMBytes(8);options.setMaxInstructions(200000);
            if(p.has("options")){JsonObject values=p.getAsJsonObject("options");for(String key:values.keySet()){
                switch(key){case "eliminate_unreachable":options.setEliminateUnreachable(values.get(key).getAsBoolean());break;
                    case "respect_read_only":options.setRespectReadOnly(values.get(key).getAsBoolean());break;
                    case "infer_constant_pointers":options.setInferConstantPointers(values.get(key).getAsBoolean());break;
                    case "split_structures":options.setSplitStructures(values.get(key).getAsBoolean());break;
                    case "split_arrays":options.setSplitArrays(values.get(key).getAsBoolean());break;
                    default:throw new IllegalArgumentException("Unknown decompiler option");}}}
            decompiler.setOptions(options);decompiler.setSimplificationStyle(style);decompiler.toggleSyntaxTree(true);
            decompiler.toggleCCode(p.has("c_code")&&p.get("c_code").getAsBoolean());
            require(decompiler.openProgram(program),"Decompiler could not open the program");
            DecompileResults result=decompiler.decompileFunction(function,seconds,monitor);
            if(!result.decompileCompleted())return Map.of("completed",false,"timed_out",result.isTimedOut(),"diagnostic",result.getErrorMessage(),"operations",List.of());
            HighFunction high=result.getHighFunction();List<Object> rows=new ArrayList<>();var iter=high.getPcodeOps();
            while(iter.hasNext()&&rows.size()<limit){monitor.checkCancelled();PcodeOpAST op=iter.next();List<Object> inputs=new ArrayList<>();for(Varnode input:op.getInputs())inputs.add(varnode(input));
                Map<String,Object> row=new LinkedHashMap<>();row.put("opcode",op.getMnemonic());row.put("address",op.getSeqnum().getTarget().toString());row.put("order",op.getSeqnum().getTime());
                row.put("block",op.getParent().getIndex());row.put("inputs",inputs);row.put("output",op.getOutput()==null?null:varnode(op.getOutput()));rows.add(row);}
            Map<String,Object> out=new LinkedHashMap<>();out.put("completed",true);out.put("operations",rows);out.put("ir_complete",!iter.hasNext());out.put("simplification",style);
            out.put("language",program.getLanguageID().toString());out.put("address",function.getEntryPoint().toString());out.put("diagnostic",result.getErrorMessage());
            if(p.has("c_code")&&p.get("c_code").getAsBoolean()){String c=result.getDecompiledFunction().getC();out.put("c_code",c.substring(0,Math.min(c.length(),131072)));out.put("c_complete",c.length()<=131072);}
            return out;
        } finally {decompiler.dispose();}
    }
    public static Object compare(Program first,Program second,JsonObject p,TaskMonitor monitor) throws Exception {
        Map<String,Integer> categories=new LinkedHashMap<>();categories.put("bytes",ProgramDiffFilter.BYTE_DIFFS);categories.put("code_units",ProgramDiffFilter.CODE_UNIT_DIFFS);
        categories.put("comments",ProgramDiffFilter.COMMENT_DIFFS);categories.put("symbols",ProgramDiffFilter.SYMBOL_DIFFS);categories.put("functions",ProgramDiffFilter.FUNCTION_DIFFS);
        categories.put("references",ProgramDiffFilter.REFERENCE_DIFFS);categories.put("context",ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS);categories.put("properties",ProgramDiffFilter.USER_DEFINED_DIFFS);
        JsonArray requested=p.has("categories")?p.getAsJsonArray("categories"):new Gson().toJsonTree(List.of("bytes","comments","symbols","functions")).getAsJsonArray();
        if(requested.isEmpty()||requested.size()>categories.size())throw new IllegalArgumentException("Select 1–8 diff categories");
        int limit=integer(p,"max_ranges",100,1000),seconds=integer(p,"timeout_seconds",30,120);List<Object> rows=new ArrayList<>();boolean complete=true;
        TimeoutTaskMonitor bounded=TimeoutTaskMonitor.timeoutIn(seconds,TimeUnit.SECONDS,monitor);
        try {
            ProgramDiff diff=new ProgramDiff(first,second);
            for(JsonElement item:requested){String category=item.getAsString();Integer filter=categories.get(category);if(filter==null)throw new IllegalArgumentException("Unknown diff category");
                AddressSetView differences=diff.getDifferences(new ProgramDiffFilter(filter),bounded);List<Object> ranges=new ArrayList<>();var iterator=differences.getAddressRanges();
                while(iterator.hasNext()&&ranges.size()<limit){AddressRange range=iterator.next();ranges.add(Map.of("start",range.getMinAddress().toString(),"end",range.getMaxAddress().toString(),"length",Long.toUnsignedString(range.getLength())));}
                boolean categoryComplete=!iterator.hasNext();complete&=categoryComplete;rows.add(Map.of("category",category,"ranges",ranges,"complete",categoryComplete));}
        } finally {bounded.finished();}
        return Map.of("algorithm","ghidra.ProgramDiff","categories",rows,"complete",complete,"read_only",true,
            "memory_only_first",first.getMemory().subtract(second.getMemory()).toString(),"memory_only_second",second.getMemory().subtract(first.getMemory()).toString());
    }
}
