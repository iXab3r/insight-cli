package db;

import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import db.buffers.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;
import insight.InsightInitialJournal;
import java.nio.file.*;
import java.nio.channels.*;
import java.util.*;

/** Prepare under a unique staging name; only promote independently verified complete buffers.
 * No checkout/check-in, overwrite or buffer write exists for the canonical target path. */
class InsightInitialPublication {
    static String text(JsonObject p,String k){return InsightInitialJournal.text(p,k);}
    static void authority(RepositoryAdapter repo,boolean reader)throws Exception{
        var user=repo.getUser();if(user==null||(reader?!user.isReadOnly():!user.hasWritePermission()))throw new SecurityException();
    }
    static void binding(Path root,JsonObject journal,JsonObject saved)throws Exception{
        if(!text(journal,"intentHash").equals(InsightInitialJournal.hash(root.resolve("intent.json")))||!text(journal,"snapshotSha256").equals(text(saved,"snapshotSha256")))throw new SecurityException("Initial publication binding changed");
    }
    static boolean recovered(RepositoryAdapter repo,String name)throws Exception{
        var versions=repo.getVersions("/",name);
        return versions.length==1&&versions[0].getVersion()==1&&versions[0].getCreateTime()==0&&"<Recovered>".equals(versions[0].getComment());
    }
    static void verify(RepositoryAdapter repo,String name,String fileId,Path snapshot,String sha,String marker)throws Exception{
        var item=repo.getItem("/",name);
        if(item==null||!fileId.equals(item.getFileID())||item.getVersion()!=1||repo.isCheckinActive("/",name))throw new IllegalStateException("Initial item is not quiescent at version one");
        var versions=repo.getVersions("/",name);
        if(versions.length!=1||versions[0].getVersion()!=1||!marker.equals(versions[0].getComment())&&!recovered(repo,name))throw new SecurityException("Initial history changed");
        DBHandle expected=PackedDatabase.getPackedDatabase(snapshot.toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
        try{
            DBHandle observed=new DBHandle(repo.openDatabase("/",name,1,-1));
            try{
                if(expected.getDatabaseId()!=observed.getDatabaseId()||!InsightBlockTransfer.fingerprint(expected.getBufferMgr().getSourceFile()).equals(InsightBlockTransfer.fingerprint(observed.getBufferMgr().getSourceFile())))throw new SecurityException("Initial buffers differ");
                Object consumer=new Object();ProgramDB program=new ProgramDB(observed,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
                try{if(!sha.equals(program.getExecutableSHA256()))throw new SecurityException("Initial source changed");}finally{program.release(consumer);}
            }finally{observed.close();}
        }finally{expected.close();}
    }
    static void release(RepositoryAdapter repo,String name,JsonObject j)throws Exception{
        if(!j.has("checkoutId"))return;
        for(var held:repo.getCheckouts("/",name))if(held.getCheckoutId()==j.get("checkoutId").getAsLong()){
            if(!held.getUser().equals(repo.getUser().getName())||held.getCheckoutVersion()>1||repo.isCheckinActive("/",name))throw new SecurityException("Initial checkout remains active or foreign");
            repo.terminateCheckout("/",name,held.getCheckoutId(),false);
        }
    }
    public static void main(String[] args){var out=System.out;System.setOut(System.err);
        try{
            Path root=Path.of(args[0]);String operation=args[1];boolean readOnly=operation.startsWith("verify");JsonObject p=InsightInitialJournal.intent(root);
            try(var channel=FileChannel.open(root.resolve("lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.tryLock()){
                if(lock==null){out.println("{\"state\":\"busy\"}");System.exit(0);}
                JsonObject saved=InsightInitialJournal.prepared(root);Path snapshot=root.resolve(text(saved,"snapshot")),journalPath=root.resolve("publication.json");
                JsonObject j=Files.exists(journalPath)?InsightInitialJournal.read(journalPath):null;
                if(j!=null)binding(root,j,saved);
                Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
                String name=text(p,"target")+".bin",marker="insight target "+text(p,"target"),sha=text(p,"sha256");
                var manager=new GhidraServerManager();manager.connect();var repo=manager.server().getRepository(text(p,"repository"));repo.connect();authority(repo,readOnly);
                if(!repo.getUser().getName().equals(System.getenv("GHIDRA_SERVER_USER")))throw new SecurityException();
                RepositoryAdapter observed=repo;
                if(operation.equals("verify-stage")){
                    if(j==null||!j.has("stage"))throw new SecurityException();
                    verify(observed,text(j,"stage"),text(j,"fileId"),snapshot,sha,marker);
                    JsonObject proof=j.deepCopy();proof.addProperty("verified",true);InsightInitialJournal.write(root.resolve("stage-verified.json"),proof);
                    out.println("{\"state\":\"stage_verified\",\"version\":1,\"snapshotBuffersVerified\":true}");System.exit(0);
                }
                var canonical=observed.getItem("/",name);
                if(canonical!=null){
                    if(j==null)throw new SecurityException("Canonical item has no retained publication intent");
                    String id=j.has("fileId")?text(j,"fileId"):text(p,"id");
                    if(!id.equals(canonical.getFileID()))throw new SecurityException("Foreign canonical initial model");
                    try{verify(observed,name,id,snapshot,sha,marker);}
                    catch(Exception invalid){
                        // Compatibility with an older interrupted direct create: preserve the
                        // proven-owned, uncommitted <Recovered> object under quarantine. No delete.
                        if(readOnly||j.has("stage")||!recovered(observed,name)||repo.isCheckinActive("/",name))throw invalid;
                        release(repo,name,j);repo.moveItem("/","/",name,"__initial_abandoned_"+UUID.randomUUID().toString().replace("-",""));canonical=null;
                        j.addProperty("phase","quarantined");InsightInitialJournal.write(root.resolve("legacy-quarantined.json"),j);
                    }
                    if(canonical!=null&&!readOnly)release(repo,name,j);
                }
                if(canonical==null){
                    if(readOnly){out.println("{\"state\":\"absent\"}");System.exit(0);}
                    if(repo.fileExists("/",name))throw new SecurityException("Canonical path is reserved");
                    if(operation.equals("stage")){
                    boolean staged=false;
                    if(j!=null&&j.has("stage")){
                        String stage=text(j,"stage");if(!stage.matches("__initial_[a-f0-9]{32}"))throw new SecurityException();
                        var item=observed.getItem("/",stage);
                        if(item!=null){
                            if(!item.getFileID().equals(text(j,"fileId")))throw new SecurityException("Foreign staged initial model");
                            try{verify(observed,stage,text(j,"fileId"),snapshot,sha,marker);staged=true;}
                            catch(Exception incomplete){
                                // Interrupted staging is unpublished. Keep its bytes and receipt;
                                // start another uniquely named stage instead of overwriting it.
                                if(!repo.isCheckinActive("/",stage))release(repo,stage,j);
                            }
                        }
                    }
                    if(!staged){
                        int calls=j!=null&&j.has("createCalls")?j.get("createCalls").getAsInt():0;
                        j=new JsonObject();j.addProperty("intentHash",InsightInitialJournal.hash(root.resolve("intent.json")));j.addProperty("snapshotSha256",text(saved,"snapshotSha256"));
                        j.addProperty("stage","__initial_"+UUID.randomUUID().toString().replace("-",""));j.addProperty("fileId",UUID.randomUUID().toString());
                        j.addProperty("pid",ProcessHandle.current().pid());j.addProperty("createCalls",calls+1);j.addProperty("phase","create_intent");
                        Path attempt=root.resolve("create-"+UUID.randomUUID()+".json");InsightInitialJournal.write(attempt,j);InsightInitialJournal.write(journalPath,j);
                        DBHandle expected=PackedDatabase.getPackedDatabase(snapshot.toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
                        try{
                            var remote=repo.createDatabase("/",text(j,"stage"),expected.getBufferSize(),"Program",text(j,"fileId"),root.toString());
                            j.addProperty("checkoutId",remote.getCheckinID());j.addProperty("phase","created");InsightInitialJournal.write(attempt,j);InsightInitialJournal.write(journalPath,j);
                            try{remote.setVersionComment(marker);InsightBlockTransfer.copy((LocalBufferFile)expected.getBufferMgr().getSourceFile(),remote);if(!remote.setReadOnly())throw new IllegalStateException("Stage save not acknowledged");}
                            finally{remote.dispose();}
                        }finally{expected.close();}
                        j.addProperty("phase","staged");InsightInitialJournal.write(attempt,j);InsightInitialJournal.write(journalPath,j);
                    }
                    String stage=text(j,"stage");verify(observed,stage,text(j,"fileId"),snapshot,sha,marker);release(repo,stage,j);
                    if(repo.getCheckouts("/",stage).length!=0)throw new SecurityException("Stage retains foreign checkout");
                        out.println("{\"state\":\"staged\",\"version\":1,\"snapshotBuffersVerified\":true}");System.exit(0);
                    }
                    if(!operation.equals("promote")||j==null)throw new SecurityException();
                    JsonObject proof=InsightInitialJournal.read(root.resolve("stage-verified.json"));binding(root,proof,saved);
                    if(!proof.get("verified").getAsBoolean()||!text(proof,"fileId").equals(text(j,"fileId"))||!text(proof,"stage").equals(text(j,"stage")))throw new SecurityException("Independent stage proof changed");
                    String stage=text(j,"stage");verify(observed,stage,text(j,"fileId"),snapshot,sha,marker);
                    if(repo.getCheckouts("/",stage).length!=0)throw new SecurityException("Stage retains checkout");
                    j.addProperty("phase","promote_intent");InsightInitialJournal.write(journalPath,j);
                    // Ghidra's server move rejects an existing destination; never overwrite it.
                    try{repo.moveItem("/","/",stage,name);}catch(Exception lost){try{verify(observed,name,text(j,"fileId"),snapshot,sha,marker);}catch(Exception unproved){unproved.addSuppressed(lost);throw unproved;}}
                    j.addProperty("phase","committed");InsightInitialJournal.write(journalPath,j);
                    verify(observed,name,text(j,"fileId"),snapshot,sha,marker);
                }
                if(repo.getCheckouts("/",name).length!=0)throw new IllegalStateException("Initial checkout not released");
                repo.disconnect();manager.server().disconnect();out.println(new Gson().toJson(Map.of("state",readOnly?"verified":"published","version",1,"snapshotBuffersVerified",true)));
            }
            System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);out.println("{\"state\":\"failed\"}");System.exit(1);}
    }
}
