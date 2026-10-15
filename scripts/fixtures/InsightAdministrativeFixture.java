package db;
import com.xebyte.headless.GhidraServerManager;
import com.google.gson.Gson;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.framework.store.CheckoutType;
import ghidra.util.task.TaskMonitor;
import db.buffers.InsightBlockTransfer;
import db.buffers.LocalBufferFile;
import java.io.File;
import java.util.*;
/** Test-only creation of a disposable versioned file and checkout. */
public class InsightAdministrativeFixture {
 public static void main(String[] args){var output=System.out;System.setOut(System.err);
  try{
   if(args.length!=4)throw new IllegalArgumentException();
   Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
   var manager=new GhidraServerManager();manager.connect();var repo=manager.server().getRepository(args[0]);repo.connect();
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
