package db;
import com.xebyte.headless.GhidraServerManager;
import com.google.gson.Gson;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.remote.RepositoryItem;
import ghidra.util.task.TaskMonitor;
import db.buffers.InsightBlockTransfer;
import db.buffers.LocalBufferFile;
import java.io.File;
import java.util.*;
/** Test-only creation of a disposable versioned file and checkout. */
public class InsightAdministrativeFixture {
 public static void main(String[] args){var output=System.out;System.setOut(System.err);
  try{
   if(args.length!=4&&args.length!=5)throw new IllegalArgumentException();
   var canonical=Class.forName("InsightServerAdministration").getDeclaredMethod("canonicalPath",RepositoryItem.class);canonical.setAccessible(true);
   for(String parent:List.of("/","/nested")){
    var item=new RepositoryItem(parent,"program","owned",RepositoryItem.DATABASE,"Program",1,0,null);
    String expected=parent.equals("/")?"/program":"/nested/program";
    if(!expected.equals(canonical.invoke(null,item)))throw new IllegalStateException("SDK repository path did not remain canonical");
   }
   Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
   var manager=new GhidraServerManager();manager.connect();var repo=manager.server().getRepository(args[0]);repo.connect();
   if(args[1].equals("release")){
    if(args.length!=5)throw new IllegalArgumentException();long checkout=Long.parseLong(args[4]);
    if(repo.getCheckout("/",args[2],checkout)==null)throw new IllegalStateException("Owned fixture checkout disappeared");
    repo.terminateCheckout("/",args[2],checkout,false);
    if(repo.getCheckout("/",args[2],checkout)!=null)throw new IllegalStateException("Owned fixture checkout remains");
    output.println("{\"state\":\"released\"}");repo.disconnect();manager.server().disconnect();System.exit(0);
   }
   if(args[1].equals("create")) {
    var snapshot=PackedDatabase.getPackedDatabase(new File(args[3]),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
    var remote=repo.createDatabase("/",args[2],snapshot.getBufferSize(),UUID.randomUUID().toString(),"Program","Owned administration fixture");
    InsightBlockTransfer.copy((LocalBufferFile)snapshot.getBufferMgr().getSourceFile(),remote);
    long initialCheckout=remote.getCheckinID();remote.close();remote.dispose();snapshot.close();
    if(repo.getCheckout("/",args[2],initialCheckout)!=null)repo.terminateCheckout("/",args[2],initialCheckout,false);
   }
   var checkout=repo.checkout("/",args[2],CheckoutType.NORMAL,"owned-administration-fixture");
   if(checkout==null)throw new IllegalStateException("Fixture checkout missing");
   output.println(new Gson().toJson(Map.of("path","/"+args[2],"checkoutId",Long.toString(checkout.getCheckoutId()))));
   repo.disconnect();manager.server().disconnect();System.exit(0);
  }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"owned_fixture_failed\"}");System.exit(1);}
 }
}
