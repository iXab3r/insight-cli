// Disposable native fault fixture only. Delay one real DomainFile.save, then delegate.
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.data.DomainObjectAdapter;
import java.lang.reflect.*;
import java.util.concurrent.atomic.AtomicBoolean;
public class SlowSaveFixture extends GhidraScript {
 public void run() throws Exception {
  var options=currentProgram.getOptions("SlowSaveFixture");
  options.setString("marker","saved-once");
  options.setInt("executions",options.getInt("executions",0)+1);
  DomainFile original=currentProgram.getDomainFile();AtomicBoolean once=new AtomicBoolean(true);
  Field field=DomainObjectAdapter.class.getDeclaredField("domainFile");field.setAccessible(true);
  DomainFile delayed=(DomainFile)Proxy.newProxyInstance(DomainFile.class.getClassLoader(),new Class[]{DomainFile.class},(proxy,method,args)->{
   if(method.getName().equals("save")&&once.getAndSet(false)){
    field.set(currentProgram,original);System.err.println("SLOW_SAVE_STARTED");Thread.sleep(36000);
   }
   try{Object result=method.invoke(original,args);if(method.getName().equals("save"))System.err.println("SLOW_SAVE_COMPLETED");return result;}
   catch(InvocationTargetException e){throw e.getCause();}
  });
  field.set(currentProgram,delayed);println("CONTROLLED_MUTATION_COMPLETED");
 }
}
