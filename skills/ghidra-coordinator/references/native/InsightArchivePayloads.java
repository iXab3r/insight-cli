import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Build the pinned archive contract without networking or archive credentials in the JVM. */
public class InsightArchivePayloads extends GhidraScript {
  @Override public void run() throws Exception {
    JsonObject p=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
    Class<?> service=Class.forName("com.xebyte.core.DocumentationHashService");
    Object instance=service.getConstructors()[0].newInstance(new Object[]{null,null,null});
    var build=service.getDeclaredMethod("buildArchivePayload",Program.class,Function.class,String.class,String.class,String.class);build.setAccessible(true);
    var defaults=service.getDeclaredMethod("isDefaultSymbolName",String.class);defaults.setAccessible(true);
    int offset=p.get("offset").getAsInt(),limit=p.get("limit").getAsInt();
    if(offset<0||limit<1||limit>100)throw new IllegalArgumentException();
    List<Object> rows=new ArrayList<>();int visited=0,skipped=0;boolean more=false;
    Iterable<Function> functions=currentProgram.getFunctionManager().getFunctions(true);
    if(p.has("function")){
      var address=currentProgram.getAddressFactory().getAddress(p.get("function").getAsString());
      var function=address==null?null:currentProgram.getFunctionManager().getFunctionAt(address);
      if(function==null)throw new IllegalArgumentException("No function at the selected address");functions=List.of(function);
    }
    for(var function:functions){
      if(visited++<offset)continue;
      if(rows.size()+skipped>=limit){more=true;visited--;break;}
      if(p.get("skip_default_named").getAsBoolean()&&(Boolean)defaults.invoke(null,function.getName())){skipped++;continue;}
      Object payload=build.invoke(instance,currentProgram,function,p.get("binary_name").getAsString(),p.get("version").getAsString(),p.get("run_id").getAsString());
      if(new Gson().toJson(payload).getBytes(StandardCharsets.UTF_8).length>262144)throw new IllegalArgumentException("Function archive payload exceeds 256 KiB");
      rows.add(payload);
    }
    var result=Map.of("payloads",rows,"visited",Math.min(limit,Math.max(0,visited-offset)),"skipped",skipped,"more",more);
    String json=new Gson().toJson(result);if(json.getBytes(StandardCharsets.UTF_8).length>786432)throw new IllegalArgumentException("Archive page exceeds 768 KiB; reduce the page size");
    println("INSIGHT_ARCHIVE_PAYLOADS "+json);
  }
}
