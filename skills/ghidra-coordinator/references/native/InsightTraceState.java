import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.trace.model.Trace;
import ghidra.framework.plugintool.PluginTool;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.swing.SwingUtilities;
import ghidra.program.model.address.AddressSet;
import ghidra.trace.model.memory.TraceMemoryState;

/** Save/restore trace databases independently of the program database and live execution. */
public class InsightTraceState extends GhidraScript {
  static String string(JsonObject p,String key){return p.get(key).getAsString();}
  static void activateAndWait(DebuggerTraceManagerService manager,ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates)throws Exception{
    var pending=new java.util.concurrent.atomic.AtomicReference<java.util.concurrent.CompletableFuture<Void>>();
    Runnable activate=()->pending.set(manager.activateAndNotify(coordinates,DebuggerTraceManagerService.ActivationCause.USER));
    if(SwingUtilities.isEventDispatchThread()){
      activate.run();if(!pending.get().isDone())throw new IllegalStateException("Asynchronous trace navigation requires a background script");pending.get().join();
    }else{SwingUtilities.invokeAndWait(activate);pending.get().get(30,java.util.concurrent.TimeUnit.SECONDS);}
    if(manager.getCurrentTrace()!=coordinates.getTrace())throw new IllegalStateException("Trace selection did not settle");
  }

  static void bind(Trace trace,JsonObject p,boolean create){
    var options=trace.getOptions("Insight");String target=options.getString("Target",null),context=options.getString("Context",null);
    if(target==null&&context==null&&create){int tx=trace.startTransaction("Bind owned trace");try{
      options.setString("Target",string(p,"target"));options.setString("Context",string(p,"context"));options.setString("Trace ID","trace_"+UUID.randomUUID());
    }finally{trace.endTransaction(tx,true);}}
    else if(!string(p,"target").equals(target)||!string(p,"context").equals(context))throw new IllegalArgumentException("Trace belongs to another context");
  }
  void relocateMappings(Trace trace,PluginTool tool)throws Exception{
    var url=ProgramURLUtils.getUrlFromProgram(currentProgram);if(url==null)throw new IllegalStateException("Selected static program has no project URL");
    var options=trace.getOptions("Insight");String previous=options.getString("Static Program URL",null);
    if(previous==null||previous.equals(url.toExternalForm()))return;
    var mappings=trace.getStaticMappingManager();int tx=trace.startTransaction("Relocate owned static mappings");boolean commit=false;
    try{
      for(var mapping:List.copyOf(mappings.getAllEntries()))if(previous.equals(mapping.getStaticProgramURL().toExternalForm())){
        var range=mapping.getTraceAddressRange();var lifespan=mapping.getLifespan();String address=mapping.getStaticAddress();
        mapping.delete();mappings.add(range,lifespan,url,address);
      }
      options.setString("Static Program URL",url.toExternalForm());commit=true;
    }finally{trace.endTransaction(tx,commit);}
    var service=tool.getService(DebuggerStaticMappingService.class);if(service==null)throw new IllegalStateException("Static mapping service unavailable");
    service.changesSettled().get(30,java.util.concurrent.TimeUnit.SECONDS);
  }
  @Override public void run()throws Exception{
    var p=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
    var project=state.getProject();DebuggerTraceManagerService manager=null;PluginTool selected=null;
    for(PluginTool tool:project.getToolManager().getRunningTools()){
      var candidate=tool.getService(DebuggerTraceManagerService.class);
      if(candidate!=null&&(manager==null||!candidate.getOpenTraces().isEmpty())){manager=candidate;selected=tool;}
    }
    if(manager==null)throw new IllegalStateException("Debugger services unavailable");
    var data=project.getProjectData();String operation=string(p,"operation");
    if(Set.of("write_memory","write_register","timeline","objects","object_values","schedule").contains(operation)){
      var trace=manager.getCurrentTrace();if(trace==null)throw new IllegalStateException("No selected trace");bind(trace,p,false);
      Object value=insight.InsightTraceTools.run(trace,manager,selected,p,monitor);
      String encoded=new GsonBuilder().serializeNulls().create().toJson(value);if(encoded.length()>524288)throw new IllegalArgumentException("Trace result exceeds 512 KiB");
      println("INSIGHT_TRACE_STATE "+encoded);return;
    }
    if(operation.equals("breakpoints")){
      var trace=manager.getCurrentTrace();if(trace==null)throw new IllegalStateException("No selected trace");bind(trace,p,false);
      var service=selected.getService(DebuggerLogicalBreakpointService.class);if(service==null)throw new IllegalStateException("Breakpoint service unavailable");
      List<Object> rows=new ArrayList<>();long snap=manager.getCurrentSnap();
      for(var entry:service.getBreakpoints(trace).entrySet())for(var breakpoint:entry.getValue()){
        rows.add(Map.of("address",entry.getKey().toString(),"name",breakpoint.getName(),"kinds",breakpoint.getKinds().stream().map(Enum::name).toList(),"state",breakpoint.computeState().name(),
          "trace_location_count",breakpoint.getTraceBreakpoints(trace).stream().filter(location->!location.isDeleted()&&location.isValid(snap)).count()));
      }
      println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("items",rows)));return;
    }
    if(operation.equals("read_memory")){
      var trace=manager.getCurrentTrace();if(trace==null)throw new IllegalStateException("No selected trace");bind(trace,p,false);
      var at=trace.getBaseAddressFactory().getAddress(string(p,"address"));int size=p.get("size").getAsInt();if(at==null||size<1||size>4096)throw new IllegalArgumentException();
      var targets=selected.getService(DebuggerTargetService.class);var target=targets==null?null:targets.getTarget(trace);
      if(target!=null&&target.isValid())target.readMemory(new AddressSet(at,at.add(size-1)),monitor);
      long snap=manager.getCurrentSnap();for(int i=0;i<size;i++)if(trace.getMemoryManager().getState(snap,at.add(i))!=TraceMemoryState.KNOWN)throw new IllegalStateException("Requested trace memory is not known");
      println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("state","known")));return;
    }
    if(operation.equals("bind_new")){
      var trace=manager.getCurrentTrace();if(trace==null||!trace.getName().equals(string(p,"name"))||trace.getOptions("Insight").getString("Trace ID",null)!=null)throw new IllegalStateException("New launch trace was not established");
      bind(trace,p,true);var url=ProgramURLUtils.getUrlFromProgram(currentProgram);if(url==null)throw new IllegalStateException("Selected static program has no project URL");
      int tx=trace.startTransaction("Bind owned static program");try{trace.getOptions("Insight").setString("Static Program URL",url.toExternalForm());trace.getOptions("Insight").setString("Owned Context Root",string(p,"owned_root"));}finally{trace.endTransaction(tx,true);}
      println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("state","bound")));return;
    }
    if(operation.equals("focus")){
      var thread=manager.getCurrentThread();var object=thread==null?null:thread.getObject();
      if(object==null){var candidates=manager.getCurrentTrace().getObjectManager().getAllObjects().filter(item->item.getSchema().getName().toString().equals("Process")).toList();
        if(candidates.size()!=1)throw new IllegalStateException("Debugger process selection is ambiguous");object=candidates.get(0);}
      activateAndWait(manager,manager.resolveObject(object));
      println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("state","focused")));return;
    }
    if(operation.equals("restore")){
      var folder=data.getRootFolder().getFolder("__insight_traces");if(folder==null)folder=data.getRootFolder().createFolder("__insight_traces");
      for(var entry:p.getAsJsonArray("traces")){
        var saved=entry.getAsJsonObject();String id=string(saved,"id");if(!id.matches("trace_[a-f0-9-]{36}"))throw new IllegalArgumentException();
        Trace trace=null;for(var existing:manager.getOpenTraces())if(id.equals(existing.getOptions("Insight").getString("Trace ID",null)))trace=existing;
        if(trace==null){var file=folder.getFile(id);if(file==null)file=folder.createFile(id,Path.of(string(saved,"input")).toFile(),monitor);trace=manager.openTrace(file,-1);}
        bind(trace,p,false);if(!id.equals(trace.getOptions("Insight").getString("Trace ID",null)))throw new IllegalArgumentException("Restored trace identity changed");
        relocateMappings(trace,selected);
        var coordinates=manager.resolveTrace(trace).snap(Long.parseLong(string(saved,"snap")));
        if(saved.has("thread")){var thread=trace.getThreadManager().getThread(Long.parseLong(string(saved,"thread")));if(thread!=null)coordinates=coordinates.thread(thread);}
        activateAndWait(manager,coordinates);
        if(manager.getCurrentSnap()!=Long.parseLong(string(saved,"snap")))throw new IllegalStateException("Saved trace snap did not restore");
      }
      if(p.has("active"))for(var trace:manager.getOpenTraces())if(string(p,"active").equals(trace.getOptions("Insight").getString("Trace ID",null))){
        activateAndWait(manager,manager.resolveTrace(trace));
      }
      println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("state","restored")));return;
    }
    if(operation.equals("select")){
      String id=string(p,"id");for(var trace:manager.getOpenTraces()){
        bind(trace,p,false);if(id.equals(trace.getOptions("Insight").getString("Trace ID",null))){
          activateAndWait(manager,manager.resolveTrace(trace));
          println("INSIGHT_TRACE_STATE "+new Gson().toJson(Map.of("state","selected","id",id)));return;}
      }
      throw new IllegalArgumentException("Trace not found");
    }
    if(!operation.equals("checkpoint"))throw new IllegalArgumentException();
    Path root=Path.of(string(p,"output")).toRealPath();List<Object> traces=new ArrayList<>();String active=null;
    if(manager.getOpenTraces().size()>64)throw new IllegalArgumentException("Trace count exceeds 64");
    long lockDeadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
    for(var trace:manager.getOpenTraces()){
      bind(trace,p,false);String id=trace.getOptions("Insight").getString("Trace ID",null);if(id==null||!id.matches("trace_[a-f0-9-]{36}"))throw new IllegalArgumentException();
      Path output=root.resolve(id+".gzf");if(Files.exists(output))throw new IllegalArgumentException();
      while(!trace.lock("Insight consistent trace checkpoint")){
        monitor.checkCancelled();if(System.nanoTime()>=lockDeadline)throw new IllegalStateException("Trace transaction did not release for checkpoint");Thread.sleep(25);
      }
      try{
      var coordinates=manager.getCurrentFor(trace);trace.saveToPackedFile(output.toFile(),monitor);
      Map<String,Object> row=new LinkedHashMap<>();row.put("id",id);row.put("name",trace.getName());row.put("snap",Long.toString(coordinates.getSnap()));
      row.put("modules",trace.getModuleManager().getAllModules().size());row.put("threads",trace.getThreadManager().getAllThreads().size());
      if(coordinates.getThread()!=null)row.put("thread",Long.toString(coordinates.getThread().getKey()));
      var targets=selected.getService(DebuggerTargetService.class);var live=targets==null?null:targets.getTarget(trace);row.put("connected",live!=null&&live.isValid());
      traces.add(row);if(manager.getCurrentTrace()==trace)active=id;
      }finally{trace.unlock();}
    }
    Map<String,Object> result=new LinkedHashMap<>();result.put("traces",traces);if(active!=null)result.put("active",active);
    println("INSIGHT_TRACE_STATE "+new Gson().toJson(result));
  }
}
