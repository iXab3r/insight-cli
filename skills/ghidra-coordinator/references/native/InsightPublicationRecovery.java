package db;

import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import db.buffers.InsightBlockTransfer;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

/** Verify an immutable exact version; release only the receipt-identified owned checkout. */
class InsightPublicationRecovery {
  public static void main(String[] args) {
    var output=System.out;System.setOut(System.err);
    try {
      if(args.length!=7)throw new IllegalArgumentException();
      String repo=args[0],path=args[1],marker=args[4],sha=args[6];int expected=Integer.parseInt(args[3]);
      if(!path.startsWith("/")||path.indexOf('/',1)>=0||!marker.matches("insight merge q_[a-f0-9-]{36}"))throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      var reader=new GhidraServerManager();reader.connect();var repository=reader.server().getRepository(repo);repository.connect();
      var user=repository.getUser();if(user==null||!user.isReadOnly()||!user.getName().equals(System.getenv("GHIDRA_SERVER_USER")))throw new SecurityException();
      String folder="/",name=path.substring(1);
      var history=repository.getVersions(folder,name);var matches=Arrays.stream(history).filter(item->marker.equals(item.getComment())).toList();
      if(matches.size()!=1||matches.getFirst().getVersion()!=expected+1){output.println("{\"state\":\"unknown\"}");System.exit(0);}
      int actual=matches.getFirst().getVersion();
      DBHandle snapshot=PackedDatabase.getPackedDatabase(Path.of(args[2]).toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
      DBHandle observed=new DBHandle(repository.openDatabase(folder,name,actual,-1));
      try {
        if(snapshot.getDatabaseId()!=observed.getDatabaseId()||!InsightBlockTransfer.fingerprint(snapshot.getBufferMgr().getSourceFile()).equals(
            InsightBlockTransfer.fingerprint(observed.getBufferMgr().getSourceFile())))throw new IllegalStateException("Exact published buffers differ");
        Object consumer=new Object();ProgramDB program=new ProgramDB(observed,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
        try{if(!sha.equals(program.getExecutableSHA256()))throw new SecurityException("Published source identity changed");}
        finally{program.release(consumer);}
      }finally{snapshot.close();observed.close();}
      repository.disconnect();reader.server().disconnect();
      JsonObject intent=JsonParser.parseString(Files.readString(Path.of(args[5]))).getAsJsonObject();
      if(!repo.equals(intent.get("repository").getAsString())||!path.equals(intent.get("path").getAsString())||
          !marker.equals(intent.get("marker").getAsString())||intent.get("baseline").getAsInt()!=expected)throw new SecurityException();
      long checkout=intent.get("checkoutId").getAsLong();
      var writer=new GhidraServerManager(System.getenv("GHIDRA_SERVER_HOST"),Integer.parseInt(System.getenv("GHIDRA_SERVER_PORT")),
        System.getenv("INSIGHT_PUBLISHER_USER"),System.getenv("INSIGHT_PUBLISHER_PASSWORD"));
      writer.connect();var owned=writer.server().getRepository(repo);owned.connect();
      var authority=owned.getUser();if(authority==null||!authority.hasWritePermission()||!authority.getName().equals(System.getenv("INSIGHT_PUBLISHER_USER")))throw new SecurityException();
      var held=Arrays.stream(owned.getCheckouts(folder,name)).filter(item->item.getCheckoutId()==checkout).toList();
      if(held.size()>1)throw new IllegalStateException();
      if(!held.isEmpty()) {
        var item=held.getFirst();
        if(!authority.getName().equals(item.getUser())||item.getCheckoutVersion()!=expected||owned.isCheckinActive(folder,name))
          throw new IllegalStateException("Owned checkout cannot be safely released yet");
        owned.terminateCheckout(folder,name,checkout,false);
      }
      if(Arrays.stream(owned.getCheckouts(folder,name)).anyMatch(item->item.getCheckoutId()==checkout))throw new IllegalStateException();
      owned.disconnect();writer.server().disconnect();
      output.println(new Gson().toJson(Map.of("state","verified","version",actual,"snapshotBuffersVerified",true,"ownedCheckoutReleased",true)));
      System.exit(0);
    }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"state\":\"unknown\"}");System.exit(0);}
  }
}
