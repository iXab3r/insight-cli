import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import insight.InsightSdkTools;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Fixed dispatch into compiled facade-owned SDK operations; no caller-supplied source. */
public class InsightSdkScript extends GhidraScript {
    public void run() throws Exception {
        Program peer=null;Object consumer=new Object();
        try {
            JsonObject request=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
            JsonObject p=request.getAsJsonObject("parameters");String operation=request.get("operation").getAsString().substring(5);
            long before=currentProgram.getModificationNumber();Object value;
            if(operation.equals("changes")){
                var file=currentProgram.getDomainFile().getParent().getProjectData().getFile(p.get("peer_program").getAsString());
                if(file==null)throw new IllegalArgumentException("Owned peer snapshot is absent");
                peer=(Program)file.getReadOnlyDomainObject(consumer,-1,monitor);value=InsightSdkTools.compare(currentProgram,peer,p,monitor);
            } else if(request.has("write")&&request.get("write").getAsBoolean())value=InsightSdkTools.mutate(currentProgram,operation,p,monitor);
            else value=InsightSdkTools.read(currentProgram,operation,p,monitor);
            if(!request.has("write")||!request.get("write").getAsBoolean()){
                if(before!=currentProgram.getModificationNumber())throw new IllegalStateException("Read-only SDK operation modified the program");
            }
            println("INSIGHT_QUERY:"+new GsonBuilder().serializeNulls().create().toJson(Map.of("value",value)));
        } catch(Throwable failure) {
            failure.printStackTrace();String detail=failure.getStackTrace().length>0&&failure.getStackTrace()[0].getClassName().equals("insight.InsightSdkTools")?Objects.toString(failure.getMessage(),""):failure.getClass().getSimpleName();
            println("INSIGHT_QUERY:"+new Gson().toJson(Map.of("error",Map.of("code",failure instanceof InsightSdkTools.Rejected?"rejected":failure instanceof IllegalArgumentException?"invalid":"partial","message","Native SDK operation could not establish its result: "+detail.substring(0,Math.min(detail.length(),300))))));
        } finally {if(peer!=null)peer.release(consumer);}
    }
}
