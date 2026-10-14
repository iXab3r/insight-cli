package db;

import com.google.gson.Gson;
import com.xebyte.headless.GhidraServerManager;
import db.buffers.ManagedBufferFile;
import db.buffers.LocalBufferFile;
import db.buffers.InsightBlockTransfer;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Disposable-fixture proof of a complete saved DB transfer, not a shipped facade command.
 * Package db grants access to the pinned DBHandle saved source buffers without reflection.
 * The caller owns this repository and must journal intent before invoking this helper. */
class InsightSnapshotPublisher {
  static void receipt(Path file, Map<String,Object> state) throws Exception {
    Path temporary = file.resolveSibling(file.getFileName() + ".new");
    try (FileOutputStream stream = new FileOutputStream(temporary.toFile())) {
      stream.write(new Gson().toJson(state).getBytes(java.nio.charset.StandardCharsets.UTF_8));
      stream.getFD().sync();
    }
    Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
  }
  public static void main(String[] args) {
    PrintStream output = System.out;
    System.setOut(System.err);
    Map<String,Object> state = new LinkedHashMap<>();
    try {
      if (args.length != 6) throw new IllegalArgumentException("Expected six fixture arguments");
      String repositoryName=args[0], path=args[1], marker=args[4];
      int expected=Integer.parseInt(args[3]); Path journal=Path.of(args[5]);
      if (!path.startsWith("/") || path.indexOf('/',1)>=0 || !marker.startsWith("insight-proof-")) throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(), new HeadlessGhidraApplicationConfiguration());
      GhidraServerManager manager=new GhidraServerManager(); manager.connect();
      var repository=manager.server().getRepository(repositoryName); repository.connect();
      var user=repository.getUser();
      if (user==null || !user.hasWritePermission() || !user.getName().equals(System.getenv("GHIDRA_SERVER_USER"))) throw new SecurityException();
      String folder="/", name=path.substring(1);
      if (repository.getItem(folder,name).getVersion()!=expected) {
        output.println("{\"state\":\"conflict\",\"applied\":0}"); System.exit(2);
      }
      long databaseId;
      var checkout=repository.checkout(folder,name,CheckoutType.EXCLUSIVE,journal.getParent().toString());
      if (checkout==null) throw new IllegalStateException("Exclusive checkout denied");
      state.put("checkoutId",checkout.getCheckoutId()); state.put("baseline",expected); state.put("phase","checkout"); receipt(journal,state);
      if (checkout.getCheckoutVersion()!=expected || repository.getItem(folder,name).getVersion()!=expected) throw new IllegalStateException("Baseline changed before exclusive ownership");
      ManagedBufferFile remote=repository.openDatabase(folder,name,checkout.getCheckoutId());
      boolean completed=false;
      try {
        state.put("phase","commit_intent"); receipt(journal,state);
        PackedDatabase packed=PackedDatabase.getPackedDatabase(new File(args[2]),true,TaskMonitor.DUMMY);
        DBHandle snapshot=packed.open(TaskMonitor.DUMMY);
        databaseId=snapshot.getDatabaseId();
        Object snapshotConsumer=new Object();
        ProgramDB snapshotProgram=new ProgramDB(snapshot,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,snapshotConsumer);
        ProgramChangeSet changes=(ProgramChangeSet)snapshotProgram.getChangeSet();
        snapshotProgram.getChangeSet().startTransaction();
        try {
          changes.add(snapshotProgram.getMemory());
          var dataTypes=snapshotProgram.getDataTypeManager().getAllDataTypes();
          while(dataTypes.hasNext()) changes.dataTypeChanged(snapshotProgram.getDataTypeManager().getID(dataTypes.next()));
          var symbols=snapshotProgram.getSymbolTable().getAllSymbols(true);
          while(symbols.hasNext()) changes.symbolChanged(symbols.next().getID());
        } finally { snapshotProgram.getChangeSet().endTransaction(true); }
        ManagedBufferFile save=remote.getSaveFile();
        if (save==null) throw new IllegalStateException("Save buffer denied");
        save.setVersionComment(marker);
        try {
          InsightBlockTransfer.copy((LocalBufferFile)snapshot.getBufferMgr().getSourceFile(),save);
          var changeFile=remote.getSaveChangeDataFile();
          if(changeFile==null) throw new IllegalStateException("Native change-set buffer missing");
          DBHandle changeDb=new DBHandle();
          try {
            snapshotProgram.getChangeSet().write(changeDb,false);
            changeDb.saveAs(changeFile,false,TaskMonitor.DUMMY);
          } finally { changeDb.close(); changeFile.dispose(); }
        } finally { snapshotProgram.release(snapshotConsumer); }
        remote.saveCompleted(true); completed=true;
        save.dispose();
        state.put("phase","committed"); receipt(journal,state);
      } finally {
        remote.dispose();
        if (!completed) state.put("phase","unknown");
      }
      var versions=repository.getVersions(folder,name);
      long matches=Arrays.stream(versions).filter(v->marker.equals(v.getComment())).count();
      int actual=repository.getItem(folder,name).getVersion();
      if (matches!=1 || actual!=expected+1) throw new IllegalStateException("Publication history does not establish outcome");
      DBHandle readback=new DBHandle(repository.openDatabase(folder,name,actual,-1));
      try {
        if (readback.getDatabaseId()!=databaseId) throw new IllegalStateException("Saved snapshot database ID changed");
        Object consumer=new Object();
        ProgramDB program=new ProgramDB(readback,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
        program.release(consumer);
      } finally { readback.close(); }
      repository.terminateCheckout(folder,name,checkout.getCheckoutId(),false);
      if (repository.isCheckinActive(folder,name) || Arrays.stream(repository.getCheckouts(folder,name)).anyMatch(c->c.getCheckoutId()==checkout.getCheckoutId())) throw new IllegalStateException("Owned checkout not released");
      state.put("phase","released"); state.put("version",actual); receipt(journal,state);
      repository.disconnect(); manager.server().disconnect();
      output.println(new Gson().toJson(Map.of("state","published","version",actual,"snapshotDatabaseIdPreserved",true)));
      System.exit(0);
    } catch (Throwable failure) {
      System.err.println(failure.getClass().getName()+": "+failure.getMessage());
      failure.printStackTrace(System.err);
      output.println(new Gson().toJson(Map.of("state","failed","phase",state.getOrDefault("phase","setup"))));
      System.exit(1);
    }
  }
}
