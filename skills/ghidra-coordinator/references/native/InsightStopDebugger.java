import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.framework.plugintool.PluginTool;
import java.util.concurrent.TimeUnit;

/** Close only target objects reached through this owned project's debugger services. */
public class InsightStopDebugger extends GhidraScript {
  @Override public void run()throws Exception{
    var project=state.getProject();if(project==null)throw new IllegalStateException("Owned project missing");
    for(PluginTool tool:project.getToolManager().getRunningTools()){
      var traces=tool.getService(DebuggerTraceManagerService.class);var targets=tool.getService(DebuggerTargetService.class);
      if(traces==null||targets==null)continue;
      for(var trace:traces.getOpenTraces()){
        var target=targets.getTarget(trace);if(target!=null&&target.isValid())target.forceTerminateAsync().get(15,TimeUnit.SECONDS);
      }
    }
    println("INSIGHT_DEBUGGER_STOPPED");
  }
}
