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
        for(DomainFolder child:folder.getFolders())if(child.isLinked())names.add(child.getPathname().substring(1)+"/");else local(child,names);
    }
    static String authorized(JsonObject q){return text(q,q.has("opened")?"opened":"fingerprint");}
    static boolean sameRelease(JsonObject receipt,JsonObject q){
        if(!Objects.equals(receipt.get("checkoutId"),q.get("checkoutId"))||!Objects.equals(receipt.get("fingerprint"),q.get("fingerprint"))||
            !Objects.equals(receipt.get("version"),q.get("verifiedVersion")))return false;
        // Completed older receipts already ended the checkout. Preserve their deletion-only recovery.
        if(!receipt.has("savedFingerprint")&&!receipt.has("fileId"))return true;
        return Objects.equals(receipt.get("fileId"),q.get("fileId"))&&Objects.equals(receipt.get("savedFingerprint"),new JsonPrimitive(authorized(q)));
    }
    /** A new intent can prove the local file left between server termination and native undo's local deletion. */
    static boolean survivingRelease(JsonObject receipt,JsonObject q,Map<String,Object> saved){
        return receipt.has("fileId")&&receipt.has("savedFingerprint")&&Objects.equals(receipt.get("state"),new JsonPrimitive("release_intent"))&&sameRelease(receipt,q)&&
            Objects.equals(saved.get("fileId"),text(receipt,"fileId"))&&Objects.equals(saved.get("fingerprint"),text(receipt,"savedFingerprint"));
    }
    static boolean backupMatches(JsonObject journal,String name,Map<String,Object> saved){
        JsonObject files=journal.getAsJsonObject("result").getAsJsonObject("disposableBackups");
        if(files==null||!files.has(name))return false;
        JsonElement proof=files.get(name);
        if(proof.isJsonPrimitive()){
            // Older proofs were recorded only for a before-image-equal backup (not saveAs-created Update copies).
            return proof.equals(journal.getAsJsonObject("before").get("fingerprint"))&&saved.get("fingerprint").equals(proof.getAsString());
        }
        if(!proof.isJsonObject())return false;
        JsonObject created=proof.getAsJsonObject();
        boolean newFile=journal.has("backupAbsent")&&(journal.get("backupAbsent").getAsBoolean()||journal.has("backupBeforeFileId")&&!journal.get("backupBeforeFileId").isJsonNull()&&
            !journal.get("backupBeforeFileId").equals(created.get("fileId")));
        return newFile&&journal.has("backupExpected")&&journal.get("backupExpected").getAsBoolean()&&
            created.has("schema")&&created.get("schema").getAsInt()==1&&saved.get("fileId").equals(text(created,"fileId"))&&saved.get("fingerprint").equals(text(created,"fingerprint"));
    }
    /** Only an expected backup newly created by a completed owned native operation, still at its recorded bytes, is disposable. */
    static Map<String,String> backups(Project project,Path operations,JsonObject q,JsonObject owner)throws Exception {
        String name=text(owner,"path").substring(1),keep=name+".keep";Map<String,String> proved=new TreeMap<>();
        DomainFile backup=project.getProjectData().getFile("/"+keep);
        if(backup==null||backup.isVersioned()||backup.canRecover()||backup.isCheckedOut()||backup.isHijacked())return proved;
        try(var paths=Files.list(operations)){
            for(Path path:paths.filter(p->p.getFileName().toString().matches("q_[a-f0-9-]{36}-(update|discard)\\.json")).sorted().toList()){
                JsonObject journal=JsonParser.parseString(Files.readString(path)).getAsJsonObject(),request=journal.getAsJsonObject("request"),result=journal.getAsJsonObject("result");
                if(request==null||result==null||!request.getAsJsonObject("owner").equals(owner)||!Objects.equals(request.get("root"),q.get("root"))||
                    !Objects.equals(request.get("fileId"),q.get("fileId"))||!Objects.equals(result.get("checkoutId"),q.get("checkoutId"))||
                    !path.getFileName().toString().equals(text(request,"request")+"-"+text(request,"operation")+".json")||
                    !(text(request,"operation").equals("update")&&text(result,"state").equals("updated")||text(request,"operation").equals("discard")&&text(result,"state").equals("discarded"))||
                    result.get("baseVersion").getAsInt()>q.get("verifiedVersion").getAsInt())continue;
                Map<String,Object> current=saved(backup,owner);
                if(backupMatches(journal,keep,current))proved.put(keep,current.get("fingerprint").toString());
            }
        }
        return proved;
    }
    static Map<String,String> releaseFiles(Project project,Path operations,JsonObject q,JsonObject owner,boolean localProgram)throws Exception {
        var files=new TreeSet<String>();local(project.getProjectData().getRootFolder(),files);
        Map<String,String> backups=backups(project,operations,q,owner);var allowed=new TreeSet<>(backups.keySet());
        if(localProgram)allowed.add(text(owner,"path").substring(1));
        require(files.equals(allowed),"Unpublished native project files must be retained");return backups;
    }
    static boolean released(Path root,JsonObject q)throws Exception {
        Path path=root.resolve("released.json");if(!Files.exists(path))return false;
        var released=JsonParser.parseString(Files.readString(path)).getAsJsonObject();
        return text(released,"state").equals("released")&&sameRelease(released,q);
    }
    static void deleteReleased(Path root,ProjectLocator locator)throws Exception {
        for(Path target:List.of(locator.getProjectDir().toPath(),locator.getMarkerFile().toPath())){
            if(!Files.exists(target,LinkOption.NOFOLLOW_LINKS))continue;
            require(!Files.isSymbolicLink(target)&&target.toRealPath().getParent().equals(root),"Native deletion escaped owned project");
            // Validate the whole tree first: a Windows junction is a directory whose children live elsewhere.
            List<Path> entries=new ArrayList<>();
            Files.walkFileTree(target,new SimpleFileVisitor<Path>(){
                FileVisitResult visit(Path path,java.nio.file.attribute.BasicFileAttributes at){require(!at.isSymbolicLink()&&!at.isOther(),"Native deletion met a link");entries.add(path);return FileVisitResult.CONTINUE;}
                @Override public FileVisitResult preVisitDirectory(Path path,java.nio.file.attribute.BasicFileAttributes at)throws java.io.IOException{require(path.toRealPath().startsWith(root),"Native deletion escaped owned project");return visit(path,at);}
                @Override public FileVisitResult visitFile(Path path,java.nio.file.attribute.BasicFileAttributes at){return visit(path,at);}
            });
            Collections.reverse(entries);for(Path entry:entries)Files.delete(entry);
        }
        require(!locator.getMarkerFile().exists()&&!locator.getProjectDir().exists(),"Native project remains");
    }
    static void history(RepositoryAdapter repository,String path,Map<String,Object> out)throws Exception {
        String name=path.substring(1);
        out.put("versions",Arrays.stream(repository.getVersions("/",name)).map(v->Map.of("version",v.getVersion(),"comment",Objects.toString(v.getComment(),""))).toList());
        out.put("checkouts",Arrays.stream(repository.getCheckouts("/",name)).map(c->Map.of("id",c.getCheckoutId(),"version",c.getCheckoutVersion(),"user",c.getUser())).toList());
        out.put("checkinActive",repository.isCheckinActive("/",name));
    }
    /** Ends exactly one server checkout whose own project no longer exists; its private work cannot be recovered. */
    static Map<String,Object> abandon(RepositoryAdapter repository,JsonObject q,JsonObject owner)throws Exception {
        Path root=Path.of(text(q,"root"));String name=text(owner,"path").substring(1);long id=q.get("checkoutId").getAsLong();
        require(root.isAbsolute()&&!Files.exists(root,LinkOption.NOFOLLOW_LINKS),"Native project still exists");
        require(root.getParent().getFileName().toString().equals(text(owner,"context")),"Malformed native binding");
        var item=repository.getItem("/",name);require(item!=null&&item.getFileID().equals(text(q,"fileId")),"Native file ID changed");
        require(!repository.isCheckinActive("/",name),"A native check-in is active");
        String owned="/"+text(owner,"context")+"/"+root.getFileName()+"/view";boolean present=false;
        // Everything is proved before the only effect.
        for(var checkout:repository.getCheckouts("/",name)){
            boolean project=Objects.toString(checkout.getProjectPath(),"").replace('\\','/').endsWith(owned);
            require(project==(checkout.getCheckoutId()==id),"Server checkout belongs to another project");
            if(!project)continue;
            require(checkout.getUser().equals(System.getenv("GHIDRA_SERVER_USER"))&&checkout.getCheckoutType()==ghidra.framework.store.CheckoutType.NORMAL&&
                checkout.getCheckoutVersion()==q.get("baseVersion").getAsInt(),"Server checkout differs from its receipt");
            present=true;
        }
        if(q.get("check").getAsBoolean())return Map.of("state","endable");
        require(!Files.exists(root,LinkOption.NOFOLLOW_LINKS),"Native project still exists");
        if(present)repository.terminateCheckout("/",name,id,false);
        for(var checkout:repository.getCheckouts("/",name))require(checkout.getCheckoutId()!=id,"Owned checkout remains");
        return Map.of("state","abandoned","terminated",present);
    }
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);Project project=null;GhidraServerManager server=null;
        Map<String,Object> out=new LinkedHashMap<>();
        try {
            require(args.length==1,"Owned request required");
            JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            boolean abandoning=text(q,"operation").equals("abandon");
            Path root=abandoning?Path.of(text(q,"root")):Path.of(text(q,"root")).toRealPath();
            JsonObject owner=abandoning?q.getAsJsonObject("owner"):JsonParser.parseString(Files.readString(root.resolve("native-owner.json"))).getAsJsonObject();
            require(owner.equals(q.getAsJsonObject("owner")),"Native owner receipt changed");
            require(text(owner,"protocol").equals("native-checkout-v1")&&text(owner,"path").equals("/"+text(owner,"target")+".bin"),"Malformed native binding");
            String operation=text(q,"operation"),path=text(owner,"path"),name=path.substring(1);
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            Class.forName("ghidra.program.database.ProgramMultiUserMergeManagerFactory");
            PluggableServiceRegistry.registerPluggableService(ghidra.program.database.ProgramMultiUserMergeManagerFactory.class,new Factory());
            server=new GhidraServerManager();server.connect();require(server.isConnected(),"Native repository disconnected");
            RepositoryAdapter repository=server.server().getRepository(text(owner,"repository"));repository.connect();
            require(repository.getUser().hasWritePermission()&&repository.getUser().getName().equals(System.getenv("GHIDRA_SERVER_USER")),"Publisher authority required");
            if(abandoning){
                out.putAll(abandon(repository,q,owner));repository.disconnect();server.disconnect();output.println(GSON.toJson(out));System.exit(0);
            }
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
                    DomainFile priorKeep=project.getProjectData().getFile(path+".keep");boolean keepAbsent=priorKeep==null;
                    String priorKeepId=keepAbsent?null:priorKeep.getFileID();
                    boolean backupExpected=file.modifiedSinceCheckout()&&(operation.equals("discard")||operation.equals("update")&&head>base);
                    intent.put("backupAbsent",keepAbsent);intent.put("backupBeforeFileId",priorKeepId);intent.put("backupExpected",backupExpected);
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
                    if(backupExpected&&(out.get("state").equals("discarded")||out.get("state").equals("updated"))){
                        DomainFile keep=project.getProjectData().getFile(path+".keep");
                        // Ghidra's dirty Update uses createFile/saveAs, assigning the copy a new DB ID inside the fingerprinted bytes.
                        if(keep!=null&&(keepAbsent||priorKeepId!=null&&!priorKeepId.equals(keep.getFileID()))&&!keep.isVersioned()&&!keep.canRecover()&&!keep.isCheckedOut()&&!keep.isHijacked())try{
                            var actual=saved(keep,owner);out.put("disposableBackups",Map.of(name+".keep",Map.of("schema",1,"fileId",actual.get("fileId"),"fingerprint",actual.get("fingerprint"))));
                        }
                        catch(Exception unproved){/* An unreadable backup remains private; it cannot invalidate native completion. */}
                    }
                    intent.put("result",out);write(journal,intent);
                }
            }else if(operation.equals("release")){
                Path releaseFile=root.resolve("released.json");
                Map<String,Object> release=new LinkedHashMap<>(Map.of("checkoutId",q.get("checkoutId").getAsLong(),"version",q.get("verifiedVersion").getAsInt(),"fingerprint",text(q,"fingerprint"),
                    "fileId",text(q,"fileId"),"savedFingerprint",authorized(q)));
                if(file.isCheckedOut()){
                    require(!q.has("opened")||q.has("openedVerified")&&q.get("openedVerified").getAsBoolean(),"Pristine-open proof is unverified; private work must be retained");
                    require(file.getCheckoutStatus().getCheckoutVersion()==q.get("verifiedVersion").getAsInt()&&!file.canRecover(),"Unpublished native work must be retained");
                    Object local=saved(file,owner).get("fingerprint");
                    // Ghidra's own rewrite on open marks a checkout modified; only bytes the coordinator proved to hold no work may carry it.
                    require(local.equals(authorized(q)),"Verified native buffers changed");
                    require(q.has("opened")||!file.modifiedSinceCheckout(),"Unpublished native work must be retained");
                    release.put("disposableBackups",releaseFiles(project,operations,q,owner,true));
                    release.put("state","release_intent");write(releaseFile,release);file.undoCheckout(false);
                }else{
                    var prior=JsonParser.parseString(Files.readString(releaseFile)).getAsJsonObject();
                    require(text(prior,"state").equals("release_intent")&&sameRelease(prior,q),"Release intent changed");
                    boolean surviving=file.isHijacked();
                    if(surviving)require(!file.canRecover()&&survivingRelease(prior,q,saved(file,owner)),"Unproved surviving native file must be retained");
                    release.put("disposableBackups",releaseFiles(project,operations,q,owner,surviving));
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
