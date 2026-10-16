import com.google.gson.*;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Read scalar values and conservative dependencies from an immutable saved program. */
class InsightSnapshotFields {
  static final Map<String,Integer> kinds=Map.of("comment.eol",CodeUnit.EOL_COMMENT,"comment.pre",CodeUnit.PRE_COMMENT,
    "comment.post",CodeUnit.POST_COMMENT,"comment.plate",CodeUnit.PLATE_COMMENT,"comment.repeatable",CodeUnit.REPEATABLE_COMMENT);
  public static void main(String[] args) {
    var output=System.out;System.setOut(System.err);
    try {
      if(args.length!=2)throw new IllegalArgumentException();
      String input=Files.readString(Path.of(args[1]));if(input.length()>1048576)throw new IllegalArgumentException();
      JsonArray requests=JsonParser.parseString(input).getAsJsonArray();if(requests.size()>5000)throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      DBHandle db=PackedDatabase.getPackedDatabase(Path.of(args[0]).toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
      Object consumer=new Object();ProgramDB program=new ProgramDB(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
      Map<String,Object> values=new LinkedHashMap<>();
      try {
        for(JsonElement item:requests) {
          JsonObject request=item.getAsJsonObject();String address=request.get("address").getAsString(),field=request.get("field").getAsString();
          if(!field.equals("function.name")&&!kinds.containsKey(field))throw new IllegalArgumentException();
          var at=program.getAddressFactory().getAddress(address);
          var block=at==null?null:program.getMemory().getBlock(at);
          var function=at==null?null:field.equals("function.name")?program.getFunctionManager().getFunctionAt(at):program.getFunctionManager().getFunctionContaining(at);
          boolean exists=block!=null&&(!field.equals("function.name")||function!=null);
          String value=field.equals("function.name")?(function==null?null:function.getName()):
            (at==null?null:program.getListing().getComment(kinds.get(field),at));
          Map<String,Object> dependency=new LinkedHashMap<>();
          if(exists) {
            dependency.put("space",at.getAddressSpace().getName());
            dependency.put("blockStart",block.getStart().toString());dependency.put("blockEnd",block.getEnd().toString());
            dependency.put("blockType",block.getType().toString());
            byte[] bytes=new byte[16];int read=0;
            if(block.isInitialized()) {
              long available=block.getEnd().subtract(at)+1;
              read=program.getMemory().getBytes(at,bytes,0,(int)Math.min(16,available));
            }
            dependency.put("bytes",HexFormat.of().formatHex(Arrays.copyOf(bytes,read)));
            if(function!=null) {
              dependency.put("functionId",function.getID());dependency.put("body",function.getBody().toString());
              dependency.put("namespace",function.getParentNamespace().getName(true));
              dependency.put("returnType",function.getReturnType().getPathName());
              dependency.put("callingConvention",Objects.toString(function.getCallingConventionName(),""));
              dependency.put("parameters",Arrays.stream(function.getParameters()).map(parameter->parameter.getDataType().getPathName()).toList());
            }
          }
          String anchor=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new Gson().toJson(dependency).getBytes(StandardCharsets.UTF_8)));
          Map<String,Object> observed=new LinkedHashMap<>();observed.put("value",value);observed.put("exists",exists);observed.put("dependency",anchor);
          values.put(address+"@"+field,observed);
        }
      }finally{program.release(consumer);}
      output.println(new GsonBuilder().serializeNulls().create().toJson(Map.of("fields",values)));
      System.exit(0);
    }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"snapshot_inspection_failed\"}");System.exit(1);}
  }
}
