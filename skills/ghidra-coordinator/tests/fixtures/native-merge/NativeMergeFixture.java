import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.task.TaskMonitor;
import insight.prototype.HeadlessProgramMergeManager;
import java.nio.file.*;
import java.io.ByteArrayInputStream;
import java.util.*;

/** Only accepts requests bearing this proof's freshly generated ownership marker. */
public class NativeMergeFixture {
    static final TaskMonitor MONITOR=TaskMonitor.DUMMY;
    static final Object CONSUMER=new Object();
    static class Projects extends DefaultProjectManager { Projects(){super();} }
    static class HeadlessFactory extends ghidra.program.database.GhidraProgramMultiUserMergeManagerFactory {
        @Override protected ghidra.framework.data.DomainObjectMergeManager doGetMergeManager(
                DomainObject result,DomainObject mine,DomainObject original,DomainObject latest) {
            return new HeadlessProgramMergeManager((Program)result,(Program)mine,(Program)original,
                (Program)latest,((ProgramDB)latest).getChanges(),((ProgramDB)mine).getChanges());
        }
    }
    static void require(boolean value,String reason){if(!value)throw new IllegalStateException(reason);}
    static Address address(Program p,long value){return p.getAddressFactory().getDefaultAddressSpace().getAddress(value);}
    static Map<String,Object> inspect(Program p){
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<3;i++){
            Function f=p.getFunctionManager().getFunctionAt(address(p,0x1000+0x20*i));
            result.put("function"+i,Map.of("name",f.getName(),"returnType",f.getReturnType().getName(),
                "parameters",Arrays.stream(f.getParameters()).map(v->Map.of("name",v.getName(),"type",v.getDataType().getName())).toList()));
            Structure type=(Structure)p.getDataTypeManager().getDataType("/Record"+i);
            result.put("type"+i,Map.of("name",type.getName(),"fields",Arrays.stream(type.getComponents()).map(c->Map.of("name",c.getFieldName(),"type",c.getDataType().getName())).toList()));
        }
        result.put("extended",ExtendedMergeCases.inspect(p));
        return result;
    }
    static void edit(Program p,int actor,boolean conflict)throws Exception{
        int tx=p.startTransaction("Owned actor "+actor);
        boolean commit=false;
        try{
            int selected=conflict?0:actor;
            Function f=p.getFunctionManager().getFunctionAt(address(p,0x1000+0x20*selected));
            f.setName(conflict?"conflict_actor_"+actor:"actor_"+actor,SourceType.USER_DEFINED);
            f.setReturnType(actor==1?UnsignedIntegerDataType.dataType:LongLongDataType.dataType,SourceType.USER_DEFINED);
            Structure type=(Structure)p.getDataTypeManager().getDataType("/Record"+selected);
            if(conflict)type.getComponent(0).setFieldName("conflict_"+actor);
            else type.add(IntegerDataType.dataType,"actor_"+actor+"_field",null);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,
                new ParameterImpl("record_"+actor,new PointerDataType(type,p.getDataTypeManager()),p));
            if(!conflict)ExtendedMergeCases.edit(p,actor);
            commit=true;
        }finally{p.endTransaction(tx,commit);}
    }
    static void createBaseline(Project project)throws Exception{
        var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        ProgramDB p=new ProgramDB("fixture",language,language.getDefaultCompilerSpec(),CONSUMER);
        try{
            int tx=p.startTransaction("Owned baseline");
            try{
                byte[] bytes=new byte[0x1000];Arrays.fill(bytes,(byte)0xc3);
                p.getMemory().createInitializedBlock("text",address(p,0x1000),new ByteArrayInputStream(bytes),bytes.length,MONITOR,false).setExecute(true);
                p.getMemory().createInitializedBlock("data",address(p,0x4000),0x1000,(byte)0,MONITOR,false);
                for(int i=0;i<3;i++)p.getMemory().createInitializedBlock("region_"+i,address(p,0x6000+0x100*i),0x80,(byte)0,MONITOR,false);
                for(int i=0;i<3;i++){
                    Address a=address(p,0x1000+0x20*i);
                    p.getFunctionManager().createFunction("baseline_"+i,a,new AddressSet(a,a.add(0xf)),SourceType.USER_DEFINED);
                    StructureDataType type=new StructureDataType("Record"+i,0);
                    type.add(IntegerDataType.dataType,"count",null);
                    p.getDataTypeManager().addDataType(type,DataTypeConflictHandler.DEFAULT_HANDLER);
                    Address obsolete=address(p,0x1800+0x20*i);
                    p.getFunctionManager().createFunction("obsolete_"+i,obsolete,new AddressSet(obsolete,obsolete.add(0xf)),SourceType.USER_DEFINED);
                    for(String name:List.of("Obsolete"+i,"RenameMe"+i)){
                        StructureDataType old=new StructureDataType(name,0);old.add(IntegerDataType.dataType,"old",null);
                        p.getDataTypeManager().addDataType(old,DataTypeConflictHandler.DEFAULT_HANDLER);
                    }
                }
            }finally{p.endTransaction(tx,true);}
            DomainFile f=project.getProjectData().getRootFolder().createFile("fixture",p,MONITOR);
            p.release(CONSUMER);p=null;
            f.addToVersionControl("Owned native merge baseline",false,MONITOR);
        }finally{if(p!=null)p.release(CONSUMER);}
    }
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);
        Project project=null;GhidraServerManager server=null;
        try{
            require(args.length==1,"One owned request required");
            JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            Path root=Path.of(q.get("root").getAsString()).toRealPath();
            JsonObject owner=JsonParser.parseString(Files.readString(root.resolve("owner.json"))).getAsJsonObject();
            require(owner.get("id").equals(q.get("id")),"Proof ownership mismatch");
            String repo=owner.get("repository").getAsString(),operation=q.get("operation").getAsString();
            require(repo.matches("native_merge_[a-f0-9]{32}"),"Disposable repository required");
            require(java.awt.GraphicsEnvironment.isHeadless(),"Headless mode required");
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            Class.forName("ghidra.program.database.ProgramMultiUserMergeManagerFactory");
            PluggableServiceRegistry.registerPluggableService(ghidra.program.database.ProgramMultiUserMergeManagerFactory.class,
                new HeadlessFactory());
            server=new GhidraServerManager();server.connect();require(server.isConnected(),"Owned server connection failed");
            RepositoryAdapter repository;
            if(operation.equals("baseline")) repository=server.server().createRepository(repo);
            else repository=server.server().getRepository(repo);
            repository.connect();
            require(repository.getName().equals(repo),"Unexpected repository");
            String actor=q.has("actor")?q.get("actor").getAsString():"baseline";
            require(actor.matches("baseline|agent[0-2]|joint[0-2]|conflict[01]|[fbmntu]conflict[01]|reader[0-9]+"),"Invalid actor");
            Path projectRoot=root.resolve("projects").resolve(actor);Files.createDirectories(projectRoot);
            ProjectLocator locator=new ProjectLocator(projectRoot.toString(),"work");Projects manager=new Projects();
            boolean create=operation.equals("baseline")||operation.equals("checkout")||operation.equals("read");
            project=create?manager.createProject(locator,repository,false):manager.openProject(locator,false,false);
            Map<String,Object> result=new LinkedHashMap<>();result.put("operation",operation);result.put("actor",actor);
            if(operation.equals("baseline"))createBaseline(project);
            else{
                DomainFile file=project.getProjectData().getFile("/fixture");require(file!=null,"Shared program missing");
                if(operation.equals("checkout")){
                    require(file.checkout(false,MONITOR),"Checkout failed");
                    require(file.isCheckedOut()&&!file.isCheckedOutExclusive(),"Normal independent checkout required");
                    result.put("checkoutId",file.getCheckoutStatus().getCheckoutId());
                    result.put("baseVersion",file.getCheckoutStatus().getCheckoutVersion());
                }else if(operation.equals("edit")||operation.equals("jointedit")||operation.equals("conflictedit")){
                    Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                    try{
                        if(operation.equals("conflictedit"))result.put("before",inspect(p));
                        if(operation.equals("edit"))edit(p,q.get("index").getAsInt(),q.has("conflict")&&q.get("conflict").getAsBoolean());
                        else{int tx=p.startTransaction("Owned extended scenario");boolean commit=false;try{
                            if(operation.equals("jointedit"))ExtendedMergeCases.jointEdit(p,q.get("index").getAsInt());
                            else ExtendedMergeCases.conflictEdit(p,q.get("index").getAsInt(),q.get("kind").getAsString());
                            commit=true;
                        }finally{p.endTransaction(tx,commit);}}
                        p.save("Owned local edit",MONITOR);result.put("local",inspect(p));
                    }
                    finally{p.release(CONSUMER);}
                }else if(operation.equals("checkin")){
                    result.put("baseVersion",file.getCheckoutStatus().getCheckoutVersion());
                    result.put("latestBefore",file.getLatestVersion());
                    file.checkin(new DefaultCheckinHandler("native merge "+actor,false,false),MONITOR);
                    require(!project.getProjectData().getFile("/fixture").isCheckedOut(),"Checkout retained after successful checkin");
                    result.put("nativeMergeInvocations",HeadlessProgramMergeManager.invocations);
                    result.put("nativePhases",HeadlessProgramMergeManager.phases);
                }else if(operation.equals("drop")){
                    require(!file.isCheckedOut(),"A live or unpublished checkout must not be dropped");
                    require(projectRoot.toRealPath().equals(root.resolve("projects").resolve(actor)),"Owned project root moved");
                    for(Path target:List.of(locator.getProjectDir().toPath(),locator.getMarkerFile().toPath()))
                        require(target.toRealPath().startsWith(projectRoot),"Project deletion escaped its owned actor directory");
                    project.close();project=null;
                    require(manager.deleteProject(locator),"Owned project deletion failed");
                    require(!locator.getProjectDir().exists()&&!locator.getMarkerFile().exists(),"Owned project remains");
                    result.put("copyDropped",true);
                }else if(operation.equals("read")||operation.equals("local")){
                    Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                    try{result.put("program",inspect(p));}finally{p.release(CONSUMER);}
                }else throw new IllegalArgumentException("Unknown operation");
            }
            var versions=repository.getVersions("/","fixture");
            result.put("versions",Arrays.stream(versions).map(v->Map.of("version",v.getVersion(),"comment",v.getComment())).toList());
            result.put("checkouts",Arrays.stream(repository.getCheckouts("/","fixture")).map(c->Map.of("id",c.getCheckoutId(),"version",c.getCheckoutVersion())).toList());
            require(java.awt.Window.getWindows().length==0,"Unexpected GUI window");result.put("guiWindows",0);
            if(project!=null){project.close();project=null;}repository.disconnect();server.disconnect();server=null;
            output.println(new Gson().toJson(result));System.exit(0);
        }catch(Throwable error){
            error.printStackTrace(System.err);
            output.println(new Gson().toJson(Map.of("state","failed","error",error.getClass().getName(),"message",String.valueOf(error.getMessage()))));
            if(project!=null)project.close();if(server!=null)server.disconnect();System.exit(1);
        }
    }
}
