import ghidra.app.script.GhidraScript;
import insight.InsightInlineExecutor;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Only fixed trusted code is passed to the upstream script provider. User source is an input file. */
public class InsightInlineScript extends GhidraScript {
    public void run() throws Exception {
        Path request=Path.of(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8));
        InsightInlineExecutor.execute(request,getState(),monitor);
        println("INSIGHT_INLINE_COMPLETE");
    }
}
