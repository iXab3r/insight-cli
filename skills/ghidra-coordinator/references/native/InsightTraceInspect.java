import com.google.gson.Gson;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.trace.database.DBTrace;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.*;

/** Independent immutable readback of a packed trace, including its logical owner binding. */
class InsightTraceInspect {
  public static void main(String[] args){var output=System.out;System.setOut(System.err);try{
    Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
    DBHandle db=PackedDatabase.getPackedDatabase(Path.of(args[0]).toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
    Object consumer=new Object();DBTrace trace=new DBTrace(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
    try{var options=trace.getOptions("Insight");
      output.println(new Gson().toJson(Map.of("id",options.getString("Trace ID",""),"target",options.getString("Target",""),"context",options.getString("Context",""),
        "name",trace.getName(),"modules",trace.getModuleManager().getAllModules().size(),"threads",trace.getThreadManager().getAllThreads().size())));
    }finally{trace.release(consumer);}System.exit(0);
  }catch(Throwable error){error.printStackTrace(System.err);output.println("{\"error\":\"trace_readback_failed\"}");System.exit(1);}}
}
