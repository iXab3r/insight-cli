import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

/** Idempotent resource startup in this script's owned project; does not launch a debuggee. */
public class InsightStartDebugger extends GhidraScript {
  void prepare(PluginTool tool)throws Exception{
    tool.getService(DebuggerTraceManagerService.class).setAutoCloseOnTerminate(false);
    var programs=tool.getService(ProgramManager.class);if(programs==null||currentProgram==null)return;
    Runnable open=()->{if(!java.util.Arrays.asList(programs.getAllOpenPrograms()).contains(currentProgram))programs.openProgram(currentProgram);};
    if(SwingUtilities.isEventDispatchThread())open.run();else SwingUtilities.invokeAndWait(open);
  }
  @Override public void run()throws Exception{
    var project=state.getProject();if(project==null)throw new IllegalStateException("Owned project missing");
    var manager=project.getToolManager();
    for(PluginTool tool:manager.getRunningTools())if(tool.getService(DebuggerTraceManagerService.class)!=null){prepare(tool);println("INSIGHT_DEBUGGER_READY");return;}
    var template=project.getLocalToolChest().getToolTemplate("Debugger");if(template==null)throw new IllegalStateException("Debugger tool template missing");
    AtomicReference<PluginTool> started=new AtomicReference<>();
    Runnable start=()->started.set(manager.getActiveWorkspace().runTool(template));
    if(SwingUtilities.isEventDispatchThread())start.run();else SwingUtilities.invokeAndWait(start);
    if(started.get()==null||started.get().getService(DebuggerTraceManagerService.class)==null)throw new IllegalStateException("Debugger services unavailable");
    prepare(started.get());
    println("INSIGHT_DEBUGGER_READY");
  }
}
