import insight.nativecheckout.InsightSnapshotFields;
import insight.nativecheckout.InsightSnapshotInspect;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import com.google.gson.*;
import java.util.*;
import db.InsightNativeFingerprint;

/** Trusted saved-view inspection in the already owned worker; no repository credentials. */
public class InsightNativeView extends GhidraScript {
    public void run()throws Exception {
        JsonObject q=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        if(currentProgram==null||currentProgram.isChanged())throw new IllegalStateException("Saved program required");
        String fingerprint=InsightNativeFingerprint.of(currentProgram);
        if(q.has("expected")&&!fingerprint.equals(q.get("expected").getAsString()))throw new IllegalStateException("Saved native view changed");
        Object value;
        switch(q.get("operation").getAsString()) {
            case "fingerprint":
                var c=((ProgramDB)currentProgram).getChanges();
                value=Map.of("fingerprint",fingerprint,"version",currentProgram.getDomainFile().getVersion(),"fileId",currentProgram.getDomainFile().getFileID(),
                    "dataTypeChanges",c.getDataTypeChanges(),"dataTypeAdditions",c.getDataTypeAdditions(),"symbolChanges",c.getSymbolChanges(),"symbolAdditions",c.getSymbolAdditions());break;
            case "fields":value=InsightSnapshotFields.inspect((ProgramDB)currentProgram,q.getAsJsonArray("selectors"));break;
            case "inspect":value=InsightSnapshotInspect.inspect((ProgramDB)currentProgram,q.getAsJsonObject("parameters"));break;
            default:throw new IllegalArgumentException();
        }
        if(!fingerprint.equals(InsightNativeFingerprint.of(currentProgram)))throw new IllegalStateException("Native view changed while inspecting");
        println("INSIGHT_NATIVE:"+new GsonBuilder().serializeNulls().create().toJson(Map.of("value",value)));
    }
}
