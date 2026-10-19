import ghidra.app.script.GhidraScript;
import com.google.gson.Gson;
import java.util.Map;

/** Constant-work view observation; do not compile the scanning/decoding helpers for this guard. */
public class InsightResearchView extends GhidraScript {
  public void run() throws Exception {
    monitor.checkCancelled();
    long modification=currentProgram.getModificationNumber();
    var value=Map.of("modification",Long.toString(modification),
      "language",currentProgram.getLanguageID().toString(),
      "compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
      "read_only",Map.of("modification_unchanged",true,"modification",Long.toString(modification)));
    monitor.checkCancelled();
    Object result=currentProgram.getModificationNumber()==modification?Map.of("value",value):
      Map.of("error",Map.of("code","partial","message","Read-only query changed the program modification counter"));
    println("INSIGHT_QUERY:"+new Gson().toJson(result));
  }
}
