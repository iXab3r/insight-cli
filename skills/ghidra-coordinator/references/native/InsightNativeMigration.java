import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import db.InsightNativeFingerprint;
import java.nio.file.*;
import java.nio.channels.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Explicit legacy promotion only. Ordinary opens never enter this writer. */
public final class InsightNativeMigration {
    public static final class Required extends IllegalStateException {public Required(){super("Legacy model requires explicit migration; run ghidra migrate --target <target> --dry-run, then ghidra migrate --target <target>");}}
    static final Object CONSUMER=new Object();static final TaskMonitor MONITOR=TaskMonitor.DUMMY;
    static class Projects extends DefaultProjectManager {Projects(){super();}}
    static String text(JsonObject q,String k){return q.get(k).getAsString();}
    static void require(boolean ok,String message){if(!ok)throw new IllegalStateException(message);}
    public static String programIdentity(Program p)throws Exception {
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        for(String value:List.of(p.getExecutableSHA256(),p.getLanguageID().toString(),p.getCompilerSpec().getCompilerSpecID().toString(),p.getImageBase().toString()))hash.update((value+"\n").getBytes(StandardCharsets.UTF_8));
        byte[] bytes=new byte[1024*1024];
        for(var block:p.getMemory().getBlocks()){
            hash.update((block.getStart()+":"+block.getSize()+":"+block.isInitialized()+"\n").getBytes(StandardCharsets.UTF_8));
            if(block.isInitialized())for(long at=0;at<block.getSize();){int n=(int)Math.min(bytes.length,block.getSize()-at);int read=p.getMemory().getBytes(block.getStart().add(at),bytes,0,n);require(read==n,"Incomplete program memory read");hash.update(bytes,0,n);at+=n;}
        }
        return HexFormat.of().formatHex(hash.digest());
    }
    static void identity(Program p,JsonObject q)throws Exception {
        require(p.getExecutableSHA256().equals(text(q,"sourceSha")),"Migration source SHA256 differs");
        require(programIdentity(p).equals(text(q,"programIdentity")),"Migration program bytes or load identity differ");
    }
    static void quiescent(Path root)throws Exception {
        if(!Files.exists(root))return;
        var channels=new ArrayList<FileChannel>();var locks=new ArrayList<FileLock>();
        try(var paths=Files.walk(root)){
            for(Path path:paths.toList()){
                String name=path.getFileName().toString();
                if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))continue;
                if(name.equals("lock")){
                    var channel=FileChannel.open(path,StandardOpenOption.WRITE);channels.add(channel);
                    var lock=channel.tryLock();require(lock!=null,"Retained initial-model lock is held; no takeover");locks.add(lock);
                }
                if(!List.of("process.json","import.json","publication.json").contains(name))continue;
                JsonObject receipt=JsonParser.parseString(Files.readString(path)).getAsJsonObject();
                if(!receipt.has("pid"))continue;
                boolean stopped=false;Path stop=path.resolveSibling("stopped.json");
                if(name.equals("process.json")&&receipt.has("tokenSecret")&&Files.exists(stop)){
                    var saved=JsonParser.parseString(Files.readString(stop)).getAsJsonObject();
                    stopped=receipt.get("pid").equals(saved.get("pid"))&&receipt.get("tokenSecret").equals(saved.get("tokenSecret"));
                }
                long pid=receipt.get("pid").getAsLong();require(pid>0,"Invalid retained worker PID");
                require(stopped||!ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false),"Retained native worker is live; no takeover");
            }
        }finally{for(var lock:locks)lock.close();for(var channel:channels)channel.close();}
    }
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);Project project=null;GhidraServerManager server=null;
        try {
            JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            if(text(q,"operation").equals("quiescence")){
                quiescent(Path.of(text(q,"nativeRoot")));output.println("{\"state\":\"verified\"}");System.exit(0);
            }
            if(text(q,"operation").equals("snapshot")){
                Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
                var db=ghidra.framework.store.db.PackedDatabase.getPackedDatabase(Path.of(text(q,"snapshot")).toFile(),true,MONITOR).open(MONITOR);
                var p=new ghidra.program.database.ProgramDB(db,ghidra.framework.data.OpenMode.IMMUTABLE,MONITOR,CONSUMER);
                try{output.println(new Gson().toJson(Map.of("state","verified","fingerprint",InsightNativeFingerprint.of(p),"sourceSha",p.getExecutableSHA256(),"programIdentity",programIdentity(p))));}finally{p.release(CONSUMER);}
                System.exit(0);
            }
            Path root=Path.of(text(q,"root")).toRealPath(),ownerPath=root.resolve("migration-owner.json"),journal=root.resolve("native-migration.json");
            require(JsonParser.parseString(Files.readString(ownerPath)).equals(q.get("owner")),"Migration owner changed");
            JsonObject owner=q.getAsJsonObject("owner");String path=text(owner,"path"),name=path.substring(1),marker=text(owner,"marker");
            require(path.equals("/"+text(owner,"target")+".bin")&&marker.matches("insight migration [a-f0-9-]{36}"),"Invalid migration binding");
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            Class.forName("ghidra.program.database.ProgramMultiUserMergeManagerFactory");
            PluggableServiceRegistry.registerPluggableService(ghidra.program.database.ProgramMultiUserMergeManagerFactory.class,new InsightNativeCheckout.Factory());
            server=new GhidraServerManager();server.connect();var repository=server.server().getRepository(text(owner,"repository"));repository.connect();
            require(repository.getUser().hasWritePermission()&&repository.getUser().getName().equals(System.getenv("GHIDRA_SERVER_USER")),"Migration needs publisher authority");
            var item=repository.getItem("/",name);require(item!=null&&item.getFileID().equals(text(owner,"fileId")),"Migration file identity differs");
            JsonObject saved=Files.exists(journal)?JsonParser.parseString(Files.readString(journal)).getAsJsonObject():new JsonObject();
            String phase=saved.has("phase")?text(saved,"phase"):"reserved";
            if(text(q,"operation").equals("run")&&(phase.equals("commit_intent")||phase.equals("checked_in")||phase.equals("released"))){output.println(saved);System.exit(0);}
            Projects manager=new Projects();ProjectLocator locator=new ProjectLocator(root.toString(),"migration");
            project=locator.getMarkerFile().exists()?manager.openProject(locator,false,false):manager.createProject(locator,repository,false);
            var bound=project.getProjectData().getRepository();require(bound!=null&&bound.getName().equals(repository.getName())&&bound.getServerInfo().equals(repository.getServerInfo()),"Migration project repository differs");
            DomainFile file=project.getProjectData().getFile(path);require(file!=null&&file.getFileID().equals(text(owner,"fileId")),"Migration local identity differs");
            if(text(q,"operation").equals("release")){
                require(phase.equals("commit_intent")||phase.equals("checked_in")||phase.equals("released"),"No migration check-in intent");
                require(q.get("fingerprint").equals(saved.get("fingerprint"))&&q.get("version").getAsInt()==owner.get("version").getAsInt()+1,"Migration release proof differs");
                if(file.isCheckedOut()){require(file.getCheckoutStatus().getCheckoutId()==saved.get("checkoutId").getAsLong(),"Migration checkout changed");require(!file.modifiedSinceCheckout(),"Migration private buffers changed after check-in");file.undoCheckout(false);}
                require(Arrays.stream(repository.getCheckouts("/",name)).noneMatch(c->c.getCheckoutId()==saved.get("checkoutId").getAsLong()),"Migration checkout release is unproved");
                saved.addProperty("phase","released");InsightNativeCheckout.write(journal,saved);output.println(saved);
            }else{
                require(text(q,"operation").equals("run"),"Unsupported migration operation");
                require(item.getVersion()==owner.get("version").getAsInt()&&!repository.isCheckinActive("/",name),"Migration shared head changed");
                if(!file.isCheckedOut()){
                    require(phase.equals("reserved"),"Migration checkout disappeared");
                    require(repository.getCheckouts("/",name).length==0,"Migration requires no existing checkouts");
                    Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                    try{identity(p,owner);require(InsightNativeFingerprint.of(p).equals(text(owner,"fingerprint")),"Migration original saved buffers differ");require(p.getOptions("Insight").getString("Publication Engine","").isEmpty(),"Migration requires an unmarked legacy program");}finally{p.release(CONSUMER);}
                    require(file.checkout(false,MONITOR),"Migration checkout denied");
                }
                require(!file.isCheckedOutExclusive(),"Migration requires an ordinary native checkout");
                long checkout=file.getCheckoutStatus().getCheckoutId();
                if(saved.has("checkoutId"))require(checkout==saved.get("checkoutId").getAsLong(),"Migration checkout owner changed");
                String projectPath=file.getCheckoutStatus().getProjectPath();
                require(Arrays.stream(repository.getCheckouts("/",name)).allMatch(c->c.getCheckoutId()==checkout&&projectPath.equals(c.getProjectPath())),"Another checkout prevents migration");
                saved.addProperty("phase","checkout");saved.addProperty("checkoutId",checkout);InsightNativeCheckout.write(journal,saved);
                Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                try{
                    identity(p,owner);var options=p.getOptions("Insight");String engine=options.getString("Publication Engine","");
                    if(engine.isEmpty()){
                        require(InsightNativeFingerprint.of(p).equals(text(owner,"fingerprint")),"Migration checkout buffers changed before conversion");
                        int tx=p.startTransaction("Explicit native migration");boolean ok=false;
                        try{options.setString("Publication Engine","native-checkout-v1");options.setString("Migration Request",marker);ok=true;}finally{p.endTransaction(tx,ok);}
                        p.save("Explicit native migration",MONITOR);
                    }else require(engine.equals("native-checkout-v1")&&options.getString("Migration Request","").equals(marker),"Foreign migration marker");
                    identity(p,owner);saved.addProperty("fingerprint",InsightNativeFingerprint.of(p));
                }finally{p.release(CONSUMER);}
                require(file.getLatestVersion()==owner.get("version").getAsInt(),"Migration head changed before check-in");
                saved.addProperty("phase","commit_intent");InsightNativeCheckout.write(journal,saved);
                InsightNativeCheckout.permitMerge=false;
                file.checkin(new DefaultCheckinHandler(marker,true,false),MONITOR);
                saved.addProperty("phase","checked_in");InsightNativeCheckout.write(journal,saved);output.println(saved);
            }
            project.close();project=null;repository.disconnect();server.disconnect();System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);output.println(new Gson().toJson(Map.of("state","unknown","diagnostic",failure.getClass().getSimpleName(),"reason",Objects.toString(failure.getMessage(),failure.toString()))));}
        finally{if(project!=null)try{project.close();}catch(Throwable ignored){}}
        System.exit(0);
    }
}
