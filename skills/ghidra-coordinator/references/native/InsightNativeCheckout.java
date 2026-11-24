import insight.nativecheckout.InsightSnapshotFields;
import insight.nativecheckout.InsightSnapshotInspect;
import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.data.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import insight.nativecheckout.HeadlessProgramMergeManager;
import db.InsightNativeFingerprint;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.util.*;

/** Service-only native lifecycle. Native checkouts and their native change sets are never synthesized. */
public final class InsightNativeCheckout {
    static final TaskMonitor MONITOR=TaskMonitor.DUMMY;
    static final Object CONSUMER=new Object();
    static boolean permitMerge=true;
    static class Projects extends DefaultProjectManager {Projects(){super();}}
    static final class HeadChanged extends RuntimeException {HeadChanged(){super("Shared head changed before native check-in");}}
    static class Factory extends ghidra.program.database.GhidraProgramMultiUserMergeManagerFactory {
        @Override protected DomainObjectMergeManager doGetMergeManager(DomainObject result,DomainObject mine,DomainObject original,DomainObject latest){
            // Check-in must commit the already journaled candidate. A server race aborts, never silently changes that candidate.
            if(!permitMerge)throw new HeadChanged();
            return new HeadlessProgramMergeManager((Program)result,(Program)mine,(Program)original,(Program)latest,
                ((ProgramDB)latest).getChanges(),((ProgramDB)mine).getChanges());
        }
    }
    static void require(boolean value,String reason){if(!value)throw new IllegalStateException(reason);}
    static String text(JsonObject q,String name){return q.get(name).getAsString();}
    static final Gson GSON=new GsonBuilder().serializeNulls().create();
    static void write(Path path,Object value)throws Exception {
        Path temporary=path.resolveSibling(path.getFileName()+".new-"+UUID.randomUUID());
        try(var channel=FileChannel.open(temporary,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
            var bytes=java.nio.ByteBuffer.wrap(GSON.toJson(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            while(bytes.hasRemaining())channel.write(bytes);channel.force(true);
        }
        Files.move(temporary,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        if(!System.getProperty("os.name").startsWith("Windows"))try(var channel=FileChannel.open(path.getParent(),StandardOpenOption.READ)){channel.force(true);}
    }
    static void source(Program p,JsonObject owner){
        require(p.getExecutableSHA256().equals(text(owner,"sourceSha")),"Native source identity changed");
        if(!p.getOptions("Insight").getString("Publication Engine","").equals("native-checkout-v1"))throw new InsightNativeMigration.Required();
    }
    static Map<String,Object> saved(DomainFile file,JsonObject owner)throws Exception {
        Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
        try{source(p,owner);return Map.of("fingerprint",InsightNativeFingerprint.of(p),"version",file.getVersion(),"fileId",file.getFileID(),
            "language",p.getLanguageID().toString(),"compiler",p.getCompilerSpec().getCompilerSpecID().toString(),"imageBase",p.getImageBase().toString());}
        finally{p.release(CONSUMER);}
    }
    /** Every file with local bytes, at any depth; unmodified server items have none. */
    static void local(DomainFolder folder,Set<String> names){
        for(DomainFile f:folder.getFiles())if(!f.isVersioned()||f.isCheckedOut()||f.isHijacked()||f.canRecover())names.add(f.getPathname().substring(1));
        for(DomainFolder child:folder.getFolders())if(!child.isLinked())local(child,names);
    }
    static boolean released(Path root,JsonObject q)throws Exception {
        Path path=root.resolve("released.json");if(!Files.exists(path))return false;
        var released=JsonParser.parseString(Files.readString(path)).getAsJsonObject();
        return text(released,"state").equals("released")&&released.get("checkoutId").equals(q.get("checkoutId"))&&
            released.get("fingerprint").equals(q.get("fingerprint"))&&released.get("version").equals(q.get("verifiedVersion"));
    }
    static void deleteReleased(Path root,ProjectLocator locator)throws Exception {
        for(Path target:List.of(locator.getProjectDir().toPath(),locator.getMarkerFile().toPath())){
            if(!Files.exists(target,LinkOption.NOFOLLOW_LINKS))continue;
            require(!Files.isSymbolicLink(target)&&target.toRealPath().getParent().equals(root),"Native deletion escaped owned project");
            List<Path> entries;try(var walk=Files.walk(target)){entries=walk.sorted(Comparator.reverseOrder()).toList();}
            for(Path entry:entries){require(entry.toRealPath(LinkOption.NOFOLLOW_LINKS).startsWith(root)&&!Files.readAttributes(entry,java.nio.file.attribute.BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS).isOther(),"Native deletion met a link");Files.deleteIfExists(entry);}
        }
        require(!locator.getMarkerFile().exists()&&!locator.getProjectDir().exists(),"Native project remains");
    }
    static void history(RepositoryAdapter repository,String path,Map<String,Object> out)throws Exception {
        String name=path.substring(1);
        out.put("versions",Arrays.stream(repository.getVersions("/",name)).map(v->Map.of("version",v.getVersion(),"comment",Objects.toString(v.getComment(),""))).toList());
        out.put("checkouts",Arrays.stream(repository.getCheckouts("/",name)).map(c->Map.of("id",c.getCheckoutId(),"version",c.getCheckoutVersion(),"user",c.getUser())).toList());
        out.put("checkinActive",repository.isCheckinActive("/",name));
    }
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);Project project=null;GhidraServerManager server=null;
        Map<String,Object> out=new LinkedHashMap<>();
        try {
            require(args.length==1,"Owned request required");
            JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            Path root=Path.of(text(q,"root")).toRealPath();JsonObject owner=JsonParser.parseString(Files.readString(root.resolve("native-owner.json"))).getAsJsonObject();
            require(owner.equals(q.getAsJsonObject("owner")),"Native owner receipt changed");
            require(text(owner,"protocol").equals("native-checkout-v1")&&text(owner,"path").equals("/"+text(owner,"target")+".bin"),"Malformed native binding");
            String operation=text(q,"operation"),path=text(owner,"path"),name=path.substring(1);
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            Class.forName("ghidra.program.database.ProgramMultiUserMergeManagerFactory");
            PluggableServiceRegistry.registerPluggableService(ghidra.program.database.ProgramMultiUserMergeManagerFactory.class,new Factory());
            server=new GhidraServerManager();server.connect();require(server.isConnected(),"Native repository disconnected");
            RepositoryAdapter repository=server.server().getRepository(text(owner,"repository"));repository.connect();
            require(repository.getUser().hasWritePermission()&&repository.getUser().getName().equals(System.getenv("GHIDRA_SERVER_USER")),"Publisher authority required");
            ProjectLocator locator=new ProjectLocator(root.toString(),"view");Projects manager=new Projects();
            // After a proved release the project is never reopened: an interrupted deletion can leave it unreadable.
            if((operation.equals("release")||operation.equals("drop"))&&released(root,q)){
                require(Arrays.stream(repository.getCheckouts("/",name)).noneMatch(c->c.getCheckoutId()==q.get("checkoutId").getAsLong()),"Owned checkout remains");
                if(operation.equals("drop"))deleteReleased(root,locator);
                repository.disconnect();server.disconnect();output.println("{\"state\":\""+(operation.equals("drop")?"dropped":"released")+"\"}");System.exit(0);
            }
            if(operation.equals("create")&&!locator.getMarkerFile().exists())project=manager.createProject(locator,repository,false);
            else project=manager.openProject(locator,false,false);
            require(locator.getProjectDir().toPath().toRealPath().getParent().equals(root),"Native project moved outside owned storage");
            var bound=project.getProjectData().getRepository();
            require(bound!=null&&bound.isConnected()&&bound.getName().equals(repository.getName())&&bound.getServerInfo().equals(repository.getServerInfo()),"Saved native repository binding changed");
            DomainFile file=project.getProjectData().getFile(path);require(file!=null,"Native file missing");
            if(operation.equals("create")&&!file.isCheckedOut()){
                String projectPath=ghidra.framework.store.ItemCheckoutStatus.getProjectPath(locator.toString(),false);
                require(Arrays.stream(repository.getCheckouts("/",name)).noneMatch(c->projectPath.equals(c.getProjectPath())),"Uncertain checkout creation must be reconciled");
                saved(file,owner);require(file.checkout(false,MONITOR),"Native checkout denied");
            }
            require(!file.isCheckedOutExclusive(),"Ordinary native checkout required");
            if(q.has("fileId"))require(file.getFileID().equals(text(q,"fileId")),"Native file ID changed");
            if(q.has("checkoutId")&&file.isCheckedOut())require(file.getCheckoutStatus().getCheckoutId()==q.get("checkoutId").getAsLong(),"Native checkout owner changed");
            Path operations=root.resolve("operations");Files.createDirectories(operations);
            if(operation.equals("update")||operation.equals("checkin")||operation.equals("discard")){
                String request=text(q,"request");require(request.matches("q_[a-f0-9-]{36}"),"Native request identity required");
                Path journal=operations.resolve(request+"-"+operation+".json");
                if(Files.exists(journal)){
                    JsonObject prior=JsonParser.parseString(Files.readString(journal)).getAsJsonObject();
                    require(prior.getAsJsonObject("request").equals(q),"Native request changed");
                    require(prior.has("result"),"Native outcome is unknown; do not retry");
                    out=new Gson().fromJson(prior.get("result"),LinkedHashMap.class);
                }else{
                    require(file.isCheckedOut(),"Native checkout missing");
                    var before=saved(file,owner);long checkout=file.getCheckoutStatus().getCheckoutId();int base=file.getCheckoutStatus().getCheckoutVersion(),head=file.getLatestVersion();
                    Map<String,Object> intent=new LinkedHashMap<>();intent.put("request",q);intent.put("before",before);intent.put("checkoutId",checkout);intent.put("baseVersion",base);intent.put("headVersion",head);
                    if(operation.equals("discard")){
                        write(journal,intent);
                        boolean dirty=file.modifiedSinceCheckout();file.undoCheckout(dirty);
                        file=project.getProjectData().getFile(path);require(file.checkout(false,MONITOR),"Native checkout after discard was refused");
                        out.put("state","discarded");out.put("retainedKeepFile",dirty?name+".keep":"");
                    }else if(operation.equals("update")){
                        write(journal,intent);
                        try{if(head>base)file.merge(false,MONITOR);
                            require(file.getCheckoutStatus().getCheckoutId()==checkout&&file.getCheckoutStatus().getCheckoutVersion()>=head,"Native Update did not establish the requested ancestry");
                            out.put("state","updated");}
                        catch(HeadlessProgramMergeManager.UnresolvedNativeConflict conflict){
                            require(before.equals(saved(file,owner))&&file.getCheckoutStatus().getCheckoutId()==checkout&&file.getCheckoutStatus().getCheckoutVersion()==base,"Native conflict did not preserve local state");
                            out.put("state","conflict");out.put("conflict",conflict.getMessage());
                        }
                    }else{
                        require(before.get("fingerprint").equals(text(q,"fingerprint")),"Prepared native publication changed");
                        if(head!=base||head!=q.get("expectedVersion").getAsInt()){
                            // A known pre-call head race is not an unknown check-in: none was issued.
                            out.put("state","conflict");out.put("conflict","Shared head changed before native check-in");
                            intent.put("result",out);write(journal,intent);
                        }else if(!file.modifiedSinceCheckout()){
                            intent.put("marker","insight native "+request);write(journal,intent);out.put("state","empty");
                        }else{
                            intent.put("marker","insight native "+request);write(journal,intent);
                            permitMerge=false;
                            try{file.checkin(new DefaultCheckinHandler("insight native "+request,true,false),MONITOR);out.put("state","checked_in");}
                            catch(HeadChanged changed){
                                require(before.equals(saved(file,owner))&&Arrays.stream(repository.getVersions("/",name)).noneMatch(v->("insight native "+request).equals(v.getComment())),"Check-in outcome is unknown");
                                out.put("state","conflict");out.put("conflict",changed.getMessage());
                            }finally{permitMerge=true;}
                        }
                    }
                    out.put("saved",saved(file,owner));out.put("checkoutId",file.getCheckoutStatus().getCheckoutId());out.put("baseVersion",file.getCheckoutStatus().getCheckoutVersion());
                    out.put("modified",file.modifiedSinceCheckout());out.put("nativeMergeInvocations",HeadlessProgramMergeManager.invocations);out.put("nativePhases",HeadlessProgramMergeManager.phases);
                    intent.put("result",out);write(journal,intent);
                }
            }else if(operation.equals("release")){
                Path releaseFile=root.resolve("released.json");
                Map<String,Object> release=new LinkedHashMap<>(Map.of("checkoutId",q.get("checkoutId").getAsLong(),"version",q.get("verifiedVersion").getAsInt(),"fingerprint",text(q,"fingerprint")));
                if(file.isCheckedOut()){
                    require(!file.modifiedSinceCheckout()&&file.getCheckoutStatus().getCheckoutVersion()==q.get("verifiedVersion").getAsInt(),"Unpublished native work must be retained");
                    require(saved(file,owner).get("fingerprint").equals(text(q,"fingerprint")),"Verified native buffers changed");
                    release.put("state","release_intent");write(releaseFile,release);file.undoCheckout(false);
                }else{
                    var prior=JsonParser.parseString(Files.readString(releaseFile)).getAsJsonObject();
                    require(prior.get("checkoutId").equals(q.get("checkoutId"))&&prior.get("version").equals(q.get("verifiedVersion"))&&prior.get("fingerprint").equals(q.get("fingerprint")),"Release intent changed");
                }
                require(Arrays.stream(repository.getCheckouts("/",name)).noneMatch(c->c.getCheckoutId()==q.get("checkoutId").getAsLong()),"Owned checkout remains");
                release.put("state","released");write(releaseFile,release);out.put("state","released");
            }else if(operation.equals("drop")){
                require(false,"Verified release receipt differs");
            }else if(operation.equals("inspect")||operation.equals("fields")||operation.equals("export")){
                require(saved(file,owner).get("fingerprint").equals(text(q,"fingerprint")),"Saved native view changed");
                ProgramDB p=(ProgramDB)file.getDomainObject(CONSUMER,false,false,MONITOR);
                try{
                    if(operation.equals("export")){
                        Path target=Path.of(text(q,"output"));require(target.getParent().toRealPath().startsWith(root)&&!Files.exists(target),"Native export escaped owned storage");
                        p.saveToPackedFile(target.toFile(),MONITOR);require(InsightNativeFingerprint.of(p).equals(text(q,"fingerprint")),"Native export changed saved buffers");
                    }else out.put("value",operation.equals("fields")?InsightSnapshotFields.inspect(p,q.getAsJsonArray("selectors")):InsightSnapshotInspect.inspect(p,q.getAsJsonObject("parameters")));
                }
                finally{p.release(CONSUMER);}
            }else require(operation.equals("create")||operation.equals("status"),"Unknown native operation");
            if(project!=null){
                out.put("saved",saved(file,owner));out.put("modified",file.modifiedSinceCheckout());out.put("fileId",file.getFileID());out.put("checkedOut",file.isCheckedOut());
                out.put("recoverable",file.canRecover());
                var local=new TreeSet<String>();local(project.getProjectData().getRootFolder(),local);out.put("projectFiles",local);
                if(file.isCheckedOut()){out.put("checkoutId",file.getCheckoutStatus().getCheckoutId());out.put("baseVersion",file.getCheckoutStatus().getCheckoutVersion());}
            }
            history(repository,path,out);out.putIfAbsent("state","ready");out.put("guiWindows",java.awt.Window.getWindows().length);
            require(java.awt.Window.getWindows().length==0,"Unexpected GUI window");
            if(project!=null){project.close();project=null;}repository.disconnect();server.disconnect();server=null;
            output.println(GSON.toJson(out));System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);if(project!=null)project.close();if(server!=null)server.disconnect();
            output.println(GSON.toJson(Map.of("state","unknown","diagnostic",failure.getClass().getSimpleName(),"reason",Objects.toString(failure.getMessage(),failure.toString()),"code",failure instanceof InsightNativeMigration.Required?"migration":"unknown")));System.exit(0);}
    }
}
