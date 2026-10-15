import com.google.gson.*;
import com.xebyte.core.ServiceUtils;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

/** Inspect the committed private snapshot, rather than trusting a mutation acknowledgment. */
class InsightSnapshotInspect {
  static String string(JsonObject request,String name) {return request.has(name)?request.get(name).getAsString():"";}
  static Map<String,Object> type(DataType value) {
    Map<String,Object> out=new LinkedHashMap<>();out.put("name",value.getName());out.put("path",value.getPathName());
    out.put("size",value.getLength());out.put("category",value.getCategoryPath().getPath());out.put("kind",value.getClass().getSimpleName());
    if(value instanceof Composite composite) {
      List<Object> fields=new ArrayList<>();
      for(var field:composite.getDefinedComponents()) {Map<String,Object> f=new LinkedHashMap<>();
        f.put("name",field.getFieldName());f.put("type",field.getDataType().getName());f.put("offset",field.getOffset());f.put("size",field.getLength());fields.add(f);}
      out.put("fields",fields);
    }
    if(value instanceof ghidra.program.model.data.Enum enumeration) {
      Map<String,Object> members=new LinkedHashMap<>();for(String name:enumeration.getNames())members.put(name,Long.toString(enumeration.getValue(name)));
      out.put("values",members);
    }
    if(value instanceof FunctionDefinition function) {
      out.put("returnType",function.getReturnType().getName());
      out.put("arguments",Arrays.stream(function.getArguments()).map(arg->arg.getDataType().getName()).toList());
    }
    if(value instanceof Array array){out.put("elementType",array.getDataType().getName());out.put("elementCount",array.getNumElements());}
    if(value instanceof Pointer pointer)out.put("pointerBase",pointer.getDataType()==null?"void":pointer.getDataType().getName());
    if(value instanceof TypeDef alias)out.put("typedefBase",alias.getBaseDataType().getName());
    return out;
  }
  static Object inspect(ProgramDB program,JsonObject request) throws Exception {
    String kind=string(request,"kind"),name=string(request,"name"),address=string(request,"address");
    if(kind.equals("sdk"))return insight.InsightSdkTools.verify(program,string(request,"operation"),request.getAsJsonObject("parameters"),TaskMonitor.DUMMY);
    var at=address.isEmpty()?null:program.getAddressFactory().getAddress(address);
    if(!address.isEmpty()&&at==null)throw new IllegalArgumentException("Invalid inspection address");
    if(kind.equals("debugger_bookmarks")){
      List<String> rows=new ArrayList<>();var gson=new Gson();
      for(String type:List.of("BreakpointEnabled","BreakpointDisabled")){
        var bookmarks=program.getBookmarkManager().getBookmarksIterator(type);
        while(bookmarks.hasNext()){if(rows.size()>=100000)throw new IllegalArgumentException("Debugger bookmark inventory too large");var bookmark=bookmarks.next();
          rows.add(gson.toJson(Arrays.asList(bookmark.getAddress().toString(),type,bookmark.getCategory(),bookmark.getComment())));}
      }
      Collections.sort(rows);byte[] hash=java.security.MessageDigest.getInstance("SHA-256").digest(gson.toJson(rows).getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return Map.of("count",rows.size(),"fingerprint",HexFormat.of().formatHex(hash));
    }
    if(kind.equals("type")||kind.equals("resolve_type")) {
      DataType value=kind.equals("resolve_type")?ServiceUtils.resolveDataType(program.getDataTypeManager(),name):
        ServiceUtils.findDataTypeByNameInAllCategories(program.getDataTypeManager(),name);
      return value==null?Map.of("exists",false):Map.of("exists",true,"type",type(value));
    }
    if(kind.equals("data")) {
      if(at==null)throw new IllegalArgumentException();var data=program.getListing().getDefinedDataAt(at);
      return data==null?Map.of("exists",false):Map.of("exists",true,"type",data.getDataType().getName(),"size",data.getLength(),"details",type(data.getDataType()),"isString",data.hasStringValue());
    }
    if(kind.equals("import_check")) {
      try(var expected=new StandAloneDataTypeManager("ExpectedImport",program.getDataTypeManager().getDataOrganization())) {
        int transaction=expected.startTransaction("Parse expected types");
        var parser=new ghidra.app.util.cparser.C.CParser(expected,true,new DataTypeManager[]{program.getDataTypeManager()});
        try{parser.parse(string(request,"source"));}finally{expected.endTransaction(transaction,true);}
        if(!parser.didParseSucceed())throw new IllegalArgumentException("Expected import did not parse");
        List<Object> types=new ArrayList<>();var iter=expected.getAllDataTypes();
        while(iter.hasNext()){if(types.size()>10000)throw new IllegalArgumentException("Import too large");var wanted=iter.next();
          var actual=program.getDataTypeManager().getDataType(wanted.getPathName());
          types.add(Map.of("name",wanted.getName(),"path",wanted.getPathName(),"matches",actual!=null&&wanted.isEquivalent(actual),"expected",type(wanted),"actual",actual==null?Map.of():type(actual)));}
        return Map.of("types",types,"count",types.size());
      }
    }
    if(kind.equals("category"))return Map.of("exists",program.getDataTypeManager().getCategory(new CategoryPath(name))!=null);
    if(kind.equals("memory")) {
      var memory=program.getMemory();var block=name.isEmpty()?memory.getBlock(at):memory.getBlock(name);
      if(block==null)return Map.of("exists",false);
      Map<String,Object> out=new LinkedHashMap<>();out.put("exists",true);out.put("name",block.getName());out.put("start",block.getStart().toString());
      out.put("size",block.getSize());out.put("read",block.isRead());out.put("write",block.isWrite());out.put("execute",block.isExecute());
      out.put("volatile",block.isVolatile());out.put("initialized",block.isInitialized());out.put("overlay",block.isOverlay());out.put("comment",block.getComment());
      out.put("physicalStart",block.getStart().getPhysicalAddress().toString());
      if(request.has("digest_bytes")&&request.get("digest_bytes").getAsBoolean()) {
        if(block.getSize()>16777216L)throw new IllegalArgumentException("Memory digest exceeds 16 MiB verification bound");
        String digest=null;if(block.isInitialized()) {var hash=java.security.MessageDigest.getInstance("SHA-256");long offset=0;
          while(offset<block.getSize()){int count=(int)Math.min(65536,block.getSize()-offset);byte[] bytes=new byte[count];int read=memory.getBytes(block.getStart().add(offset),bytes);if(read!=count)throw new IllegalStateException("Incomplete saved memory read");hash.update(bytes);offset+=count;}
          digest=java.util.HexFormat.of().formatHex(hash.digest());}out.put("sha256",digest);
      }
      return out;
    }
    if(kind.equals("metadata"))return Map.of("imageBase",program.getImageBase().toString(),"sha256",program.getExecutableSHA256(),
      "analyzed",ghidra.program.util.GhidraProgramUtilities.isAnalyzed(program),"functionCount",program.getFunctionManager().getFunctionCount());
    if(kind.equals("function_tags")) {
      return Map.of("tags",program.getFunctionManager().getFunctionTagManager().getAllFunctionTags().stream()
        .map(tag->Map.of("name",tag.getName(),"comment",Objects.toString(tag.getComment(),""))).toList());
    }
    if(kind.equals("function")) {
      var functions=program.getFunctionManager();var function=at==null?null:functions.getFunctionAt(at);
      if(function==null&&!name.isEmpty()){var iter=functions.getFunctions(true);while(iter.hasNext()){var candidate=iter.next();
        if(candidate.getName().equals(name)||candidate.getName(true).equals(name)){if(function!=null)throw new IllegalArgumentException("Ambiguous function");function=candidate;}}}
      if(function==null)return Map.of("exists",false);
      Map<String,Object> out=new LinkedHashMap<>();out.put("exists",true);out.put("name",function.getName());out.put("address",function.getEntryPoint().toString());
      out.put("returnType",function.getReturnType().getName());out.put("signature",function.getSignature().getPrototypeString());
      out.put("defaultCallingConvention",program.getCompilerSpec().getDefaultCallingConvention().getName());
      out.put("namespace",function.getParentNamespace().getName(true));out.put("noReturn",function.hasNoReturn());out.put("callingConvention",function.getCallingConventionName());
      List<Object> variables=new ArrayList<>();for(var variable:function.getAllVariables())variables.add(Map.of("name",variable.getName(),"type",variable.getDataType().getName(),"storage",variable.getVariableStorage().toString(),"parameter",variable instanceof ghidra.program.model.listing.Parameter));
      out.put("variables",variables);out.put("parameters",Arrays.stream(function.getParameters()).map(param->Map.of("name",param.getName(),"type",param.getDataType().getName(),"storage",param.getVariableStorage().toString(),"auto",param.isAutoParameter())).toList());
      out.put("tags",function.getTags().stream().map(tag->Map.of("name",tag.getName(),"comment",Objects.toString(tag.getComment(),""))).toList());
      String prototype=string(request,"prototype");if(!prototype.isEmpty()){
        String[] normalized=com.xebyte.core.FunctionService.extractCallingConvention(prototype);
        var expected=new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(),null).parse(function.getSignature(),normalized[1]);
        out.put("expectedPrototype",Map.of("name",expected.getName(),"returnType",expected.getReturnType().getName(),
          "inlineCallingConvention",normalized[0],"parameters",Arrays.stream(expected.getArguments()).map(param->Map.of("name",Objects.toString(param.getName(),""),"type",param.getDataType().getName())).toList()));}
      return out;
    }
    if(kind.equals("instructions")) {
      if(at==null)throw new IllegalArgumentException();var instruction=program.getListing().getInstructionAt(at);
      return instruction==null?Map.of("exists",false):Map.of("exists",true,"flowOverride",instruction.getFlowOverride().toString(),"length",instruction.getLength(),"mnemonic",instruction.getMnemonicString());
    }
    if(kind.equals("instruction_range")) {
      if(at==null)throw new IllegalArgumentException();var end=program.getAddressFactory().getAddress(string(request,"end_address"));
      if(end==null||!at.getAddressSpace().equals(end.getAddressSpace())||end.compareTo(at)<=0)throw new IllegalArgumentException("Invalid instruction seed");
      long count=0;var iter=program.getListing().getInstructions(new ghidra.program.model.address.AddressSet(at,end.subtract(1)),true);
      while(iter.hasNext()){iter.next();if(++count>1000000)throw new IllegalArgumentException("Instruction seed too large");}
      return Map.of("count",count);
    }
    if(kind.equals("symbols")) {
      List<Object> symbols=new ArrayList<>();
      if(at!=null)for(var symbol:program.getSymbolTable().getSymbols(at))symbols.add(Map.of("name",symbol.getName(),"namespace",symbol.getParentNamespace().getName(true),"primary",symbol.isPrimary(),"kind",symbol.getSymbolType().toString()));
      else {var iter=program.getSymbolTable().getSymbols(name);while(iter.hasNext()){var s=iter.next();symbols.add(Map.of("name",s.getName(),"address",s.getAddress().toString(),"primary",s.isPrimary()));}}
      return Map.of("symbols",symbols);
    }
    if(kind.equals("references")) {
      if(at==null)throw new IllegalArgumentException();List<Object> refs=new ArrayList<>();
      for(var ref:program.getReferenceManager().getReferencesFrom(at))refs.add(Map.of("to",ref.getToAddress().toString(),"type",ref.getReferenceType().toString(),"operand",ref.getOperandIndex(),"source",ref.getSource().toString()));
      return Map.of("references",refs);
    }
    if(kind.equals("property")) {
      var map=program.getUsrPropertyManager().getPropertyMap(name);
      if(map==null)return Map.of("exists",false);
      Map<String,Object> out=new LinkedHashMap<>();out.put("exists",true);out.put("type",map.getClass().getSimpleName());
      if(at!=null) {boolean has=map.hasProperty(at);out.put("hasValue",has);
        if(has){Object value=map instanceof ghidra.program.model.util.StringPropertyMap m?m.getString(at):
          map instanceof ghidra.program.model.util.IntPropertyMap m?Integer.toString(m.getInt(at)):
          map instanceof ghidra.program.model.util.LongPropertyMap m?Long.toString(m.getLong(at)):null;out.put("value",value);}}
      return out;
    }
    if(kind.equals("option")) {
      var options=program.getOptions(string(request,"group"));boolean exists=options.contains(name);
      Map<String,Object> out=new LinkedHashMap<>();out.put("exists",exists);if(exists){out.put("type",options.getType(name).toString());out.put("value",Objects.toString(options.getObject(name,null),null));}return out;
    }
    if(kind.equals("bookmarks")) {
      if(at==null)throw new IllegalArgumentException();List<Object> entries=new ArrayList<>();
      for(var mark:program.getBookmarkManager().getBookmarks(at))entries.add(Map.of("category",mark.getCategory(),"comment",mark.getComment(),"type",mark.getTypeString()));
      return Map.of("bookmarks",entries);
    }
    if(kind.equals("comments")) {
      if(at==null)throw new IllegalArgumentException();Map<String,Object> result=new LinkedHashMap<>();
      result.put("eol",program.getListing().getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT,at));
      result.put("pre",program.getListing().getComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT,at));
      result.put("plate",program.getListing().getComment(ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,at));return result;
    }
    if(kind.equals("function_comments")) {
      var function=at==null?null:program.getFunctionManager().getFunctionAt(at);
      if(function==null&&!name.isEmpty()){var iter=program.getFunctionManager().getFunctions(true);while(iter.hasNext()){var candidate=iter.next();
        if(candidate.getName().equals(name)){if(function!=null)throw new IllegalArgumentException("Ambiguous function");function=candidate;}}}
      if(function==null)throw new IllegalArgumentException("Function missing");
      List<Object> comments=new ArrayList<>();var iter=program.getListing().getInstructions(function.getBody(),true);int count=0;
      while(iter.hasNext()){if(++count>100000)throw new IllegalArgumentException("Function too large for comment inspection");var instruction=iter.next();
        for(int type:new int[]{ghidra.program.model.listing.CodeUnit.PRE_COMMENT,ghidra.program.model.listing.CodeUnit.EOL_COMMENT}){
          String comment=program.getListing().getComment(type,instruction.getAddress());if(comment!=null)comments.add(Map.of("kind",type==ghidra.program.model.listing.CodeUnit.EOL_COMMENT?"eol":"pre","address",instruction.getAddress().toString(),"text",comment));}}
      Map<String,Object> result=new LinkedHashMap<>();result.put("plate",function.getComment());result.put("comments",comments);return result;
    }
    throw new IllegalArgumentException("Unsupported saved-state inspection");
  }
  public static void main(String[] args) {
    var output=System.out;System.setOut(System.err);
    try {
      if(args.length!=2)throw new IllegalArgumentException();String encoded=Files.readString(Path.of(args[1]));if(encoded.length()>65536)throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      DBHandle db=PackedDatabase.getPackedDatabase(Path.of(args[0]).toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
      Object consumer=new Object();ProgramDB program=new ProgramDB(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
      try {output.println(new GsonBuilder().serializeNulls().create().toJson(Map.of("value",inspect(program,JsonParser.parseString(encoded).getAsJsonObject()))));}
      finally {program.release(consumer);}System.exit(0);
    }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"saved_inspection_failed\"}");System.exit(1);}
  }
}
