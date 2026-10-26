package db;

import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import db.buffers.InsightBlockTransfer;
import db.buffers.LocalBufferFile;
import ghidra.framework.store.local.ItemSerializer;
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

/** Read-only canonical recovery; only local preparation journals may be created here. */
class InsightInitialRecovery {
    static String text(JsonObject p,String key){return InsightInitialJournal.text(p,key);}
    static void stopped(Path root)throws Exception{
        for(String name:List.of("import.json","publication.json"))if(Files.exists(root.resolve(name))){
            var j=InsightInitialJournal.read(root.resolve(name));
            if(j.has("pid")&&ProcessHandle.of(j.get("pid").getAsLong()).map(ProcessHandle::isAlive).orElse(false))
                throw new IllegalStateException("Retained initial worker is live; no takeover");
        }
    }
    static void quiescent(RepositoryAdapter repo,String name,String id,int revision)throws Exception{
        var item=repo.getItem("/",name);
        if(item==null||!id.equals(item.getFileID())||item.getVersion()!=revision||repo.isCheckinActive("/",name)||repo.getCheckouts("/",name).length!=0)
            throw new IllegalStateException("Canonical revision or ownership changed");
        var history=repo.getVersions("/",name);
        if(Arrays.stream(history).noneMatch(v->v.getVersion()==revision)||
            Arrays.stream(history).noneMatch(v->v.getVersion()==1&&("insight target "+name.substring(0,name.length()-4)).equals(v.getComment())))
            throw new SecurityException("Canonical initial provenance is unproved");
    }
    static void buffers(RepositoryAdapter repo,String name,int version,Path path,String sha)throws Exception{
        DBHandle saved=PackedDatabase.getPackedDatabase(path.toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
        DBHandle observed=new DBHandle(repo.openDatabase("/",name,version,-1));
        try{
            if(saved.getDatabaseId()!=observed.getDatabaseId()||!InsightBlockTransfer.fingerprint(saved.getBufferMgr().getSourceFile()).equals(InsightBlockTransfer.fingerprint(observed.getBufferMgr().getSourceFile())))
                throw new SecurityException("Exact canonical buffers differ");
            Object consumer=new Object();ProgramDB program=new ProgramDB(observed,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
            try{if(!sha.equals(program.getExecutableSHA256()))throw new SecurityException("Canonical target changed");}finally{program.release(consumer);}
        }finally{saved.close();observed.close();}
    }
    static void packExact(DBHandle db,Path path,String name)throws Exception{
        // Program.saveToPackedFile / PackedDatabase.packDatabase allocate a fresh DB identity.
        // Preserve the exact committed identity before serializing the same GZF container format.
        Path raw=path.resolveSibling(path.getFileName()+".db");
        LocalBufferFile file=new LocalBufferFile(raw.toFile(),db.getBufferSize());
        try{db.saveAs(file,Long.valueOf(db.getDatabaseId()),false,TaskMonitor.DUMMY);}finally{file.dispose();}
        try(var input=Files.newInputStream(raw)){
            ItemSerializer.outputItem(name,"Program",0,Files.size(raw),input,path.toFile(),TaskMonitor.DUMMY);
        }
        Files.delete(raw);
    }
    static void settings(ProgramDB program,JsonObject p)throws Exception{
        if(!program.getExecutableSHA256().equals(text(p,"sha256")))throw new SecurityException("Canonical source changed");
        JsonObject settings=p.getAsJsonObject("settings");
        if(settings.has("language")&&!program.getLanguageID().toString().equals(text(settings,"language"))||
            settings.has("compilerSpec")&&!program.getCompilerSpec().getCompilerSpecID().toString().equals(text(settings,"compilerSpec"))||
            settings.has("imageBase")&&!program.getImageBase().toString().replaceFirst("^0+(?!$)","").equals(text(settings,"imageBase")))
            throw new SecurityException("Canonical load settings changed");
    }
    public static void main(String[] args){var out=System.out;System.setOut(System.err);
        try{
            Path root=Path.of(args[0]);String fingerprint=args[1],receipt=args[2];
            if(!fingerprint.matches("[a-f0-9]{64}"))throw new SecurityException("Invalid runtime fingerprint");
            JsonObject p=InsightInitialJournal.intent(root);String intentHash=InsightInitialJournal.hash(root.resolve("intent.json"));
            try(var channel=FileChannel.open(root.resolve("lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.tryLock()){
                if(lock==null){out.println("{\"state\":\"busy\"}");System.exit(0);}
                stopped(root);
                try(var children=Files.newDirectoryStream(root,"runtime-*")){for(Path child:children){
                    if(!Files.isDirectory(child,LinkOption.NOFOLLOW_LINKS)||!child.toRealPath().equals(child.toAbsolutePath().normalize()))throw new SecurityException();
                    stopped(child);
                }}
                Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
                var manager=new GhidraServerManager();manager.connect();var repo=manager.server().getRepository(text(p,"repository"));repo.connect();
                var user=repo.getUser();
                if(user==null||!user.isReadOnly()||!user.getName().equals(text(p,"readerUser"))||!user.getName().equals(System.getenv("GHIDRA_SERVER_USER")))throw new SecurityException();
                String name=text(p,"target")+".bin";var item=repo.getItem("/",name);
                if(item==null){
                    if(!receipt.isEmpty()||repo.fileExists("/",name)||Files.exists(root.resolve("publication.json")))throw new SecurityException("Canonical absence or prior publication remains unproved");
                    // All earlier preparations remain retained; none may have a pending publication.
                    try(var children=Files.newDirectoryStream(root,"runtime-*")){for(Path child:children)if(!child.getFileName().toString().equals("runtime-"+fingerprint)&&Files.exists(child.resolve("publication.json")))throw new SecurityException("Earlier runtime publication requires reconciliation");}
                    Path next=root.resolve("runtime-"+fingerprint);Files.createDirectories(next);
                    if(!next.toRealPath().equals(next.toAbsolutePath().normalize()))throw new SecurityException();
                    Path intent=next.resolve("intent.json");
                    JsonObject expected=p.deepCopy();expected.addProperty("runtimeFingerprint",fingerprint);expected.addProperty("recoveryOf",intentHash);
                    if(Files.exists(intent)){
                        JsonObject actual=InsightInitialJournal.intent(next);expected.add("id",actual.get("id"));
                        if(!expected.equals(actual))throw new SecurityException("Runtime recovery intent changed");
                    }else{expected.addProperty("id",UUID.randomUUID().toString());InsightInitialJournal.write(intent,expected);}
                    out.println(new Gson().toJson(Map.of("state","absent","root",next.getFileName().toString())));System.exit(0);
                }
                String id=item.getFileID();int revision=item.getVersion();quiescent(repo,name,id,revision);
                // A lost initial publication is reconciled against its exact R1, never inferred from latest alone.
                List<Path> attempts=new ArrayList<>();attempts.add(root);
                try(var children=Files.newDirectoryStream(root,"runtime-*")){for(Path child:children)attempts.add(child);}
                for(Path attempt:attempts)if(Files.exists(attempt.resolve("publication.json"))){
                    var j=InsightInitialJournal.read(attempt.resolve("publication.json"));var saved=InsightInitialJournal.prepared(attempt);
                    if(!text(j,"intentHash").equals(InsightInitialJournal.hash(attempt.resolve("intent.json")))||!id.equals(j.has("fileId")?text(j,"fileId"):text(InsightInitialJournal.intent(attempt),"id"))||
                        !text(j,"snapshotSha256").equals(text(saved,"snapshotSha256")))throw new SecurityException("Prior publication identity remains unknown");
                    buffers(repo,name,1,attempt.resolve(text(saved,"snapshot")),text(p,"sha256"));
                }
                if(receipt.isEmpty()){
                    String token=UUID.randomUUID().toString(),snapshot="canonical-"+token+".gzf";Path path=root.resolve(snapshot);
                    DBHandle db=new DBHandle(repo.openDatabase("/",name,revision,-1));Object consumer=new Object();
                    try{ProgramDB program=new ProgramDB(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
                        try{settings(program,p);packExact(db,path,name);}finally{program.release(consumer);}
                    }finally{db.close();}
                    InsightInitialJournal.sync(path);quiescent(repo,name,id,revision);
                    JsonObject journal=new JsonObject();journal.addProperty("intentHash",intentHash);journal.addProperty("runtimeFingerprint",fingerprint);
                    journal.addProperty("fileId",id);journal.addProperty("version",revision);journal.addProperty("snapshot",snapshot);journal.addProperty("snapshotSha256",InsightInitialJournal.hash(path));
                    receipt="canonical-"+token+".json";InsightInitialJournal.write(root.resolve(receipt),journal);
                    journal.addProperty("receipt",receipt);journal.addProperty("state","candidate");out.println(journal);System.exit(0);
                }
                if(!receipt.matches("canonical-[a-f0-9-]{36}\\.json"))throw new SecurityException();
                JsonObject proof=InsightInitialJournal.read(root.resolve(receipt));String snapshot=text(proof,"snapshot");
                if(!snapshot.matches("canonical-[a-f0-9-]{36}\\.gzf")||!intentHash.equals(text(proof,"intentHash"))||!fingerprint.equals(text(proof,"runtimeFingerprint"))||
                    !id.equals(text(proof,"fileId"))||revision!=proof.get("version").getAsInt()||!text(proof,"snapshotSha256").equals(InsightInitialJournal.hash(root.resolve(snapshot))))throw new SecurityException("Canonical recovery receipt changed");
                buffers(repo,name,revision,root.resolve(snapshot),text(p,"sha256"));quiescent(repo,name,id,revision);
                proof.addProperty("state","verified");proof.addProperty("snapshotBuffersVerified",true);out.println(proof);
            }
            System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);out.println("{\"state\":\"unknown\"}");System.exit(0);}
    }
}
