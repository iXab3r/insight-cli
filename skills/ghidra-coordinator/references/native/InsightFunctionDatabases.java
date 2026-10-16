import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.base.project.GhidraProject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.*;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.*;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.util.task.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Genuine FID and embedded BSim/H2; no custom hash results are relabeled as database matches. */
class InsightFunctionDatabases {
    static String text(JsonObject p,String key){return p.has(key)?p.get(key).getAsString():"";}
    static void bounded(Program p){if(p.getFunctionManager().getFunctionCount()>1000)throw new IllegalArgumentException("Database workflow accepts at most 1000 functions per input");}
    static void only(FidFile file){for(FidFile candidate:FidFileManager.getInstance().getFidFiles())candidate.setActive(candidate.equals(file));}
    static Map<String,Object> library(LibraryRecord value){return Map.of("name",value.getLibraryFamilyName(),"version",value.getLibraryVersion(),"variant",value.getLibraryVariant(),
        "ghidra",value.getGhidraVersion(),"language",value.getGhidraLanguageID().toString(),"compiler",value.getGhidraCompilerSpecID().toString());}
    static Object fidBuild(JsonObject p,TaskMonitor monitor)throws Exception{
        Path output=Path.of(text(p,"output")),projectRoot=Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")),"fid-source-");Object consumer=new Object();Program program=null;GhidraProject project=null;
        var manager=FidFileManager.getInstance();manager.createNewFidDatabase(output.toFile());var file=manager.addUserFidFile(output.toFile());only(file);
        try(FidDB database=file.getFidDB(true)){
            project=GhidraProject.createProject(projectRoot.toString(),"project",false);var domainFile=project.getProjectData().getRootFolder().createFile("LibraryInput",Path.of(text(p,"snapshot")).toFile(),monitor);
            program=(Program)domainFile.getDomainObject(consumer,true,false,monitor);bounded(program);
            FidService service=new FidService();
            var result=service.createNewLibraryFromPrograms(database,text(p,"library"),text(p,"version"),"insight-snapshot",List.of(domainFile),null,program.getLanguageID(),List.of(),List.of(),monitor);
            database.saveDatabase("Owned snapshot library",monitor);
            return Map.of("state","exported","format","FID","library",library(result.getLibraryRecord()),"included",result.getTotalAdded(),"excluded",result.getTotalExcluded(),"attempted",result.getTotalAttempted(),"source_sha256",program.getExecutableSHA256());
        }finally{if(program!=null)program.release(consumer);if(project!=null)project.close();}
    }
    static Object fidQuery(Program program,JsonObject p,TaskMonitor monitor)throws Exception{
        bounded(program);Path copy=Path.of(System.getProperty("java.io.tmpdir"),"query.fidb");Files.copy(Path.of(text(p,"database")),copy);
        var file=FidFileManager.getInstance().addUserFidFile(copy.toFile());only(file);FidService service=new FidService();
        if(!service.canProcess(program.getLanguage()))throw new IllegalArgumentException("FID does not support this language");
        if(p.has("function")){var address=program.getAddressFactory().getAddress(text(p,"function"));Function function=address==null?null:program.getFunctionManager().getFunctionAt(address);
            if(function==null)throw new IllegalArgumentException("No function starts at the query address");
            if(service.hashFunction(function)==null)return Map.of("engine","ghidra.FidService.processProgram","items",List.of(),"complete",false,"no_match",false,"diagnostic","Function has insufficient native FID hash input");}
        float threshold=p.has("threshold")?p.get("threshold").getAsFloat():service.getDefaultScoreThreshold();int limit=p.has("limit")?p.get("limit").getAsInt():100;
        List<Object> rows=new ArrayList<>();int total=0,queried=0;List<Object> libraries;
        try(FidDB database=file.getFidDB(false)){libraries=database.getAllLibraries().stream().map(value->(Object)library(value)).toList();}
        try(FidQueryService query=service.openFidQueryService(program.getLanguage(),false)){
            for(FidSearchResult result:service.processProgram(program,query,threshold,monitor)){
                if(p.has("function")&&!result.function.getEntryPoint().equals(program.getAddressFactory().getAddress(text(p,"function"))))continue;queried++;
                for(FidMatch match:result.matches){total++;if(rows.size()<limit)rows.add(Map.of("address",result.function.getEntryPoint().toString(),"name",match.getFunctionRecord().getName(),"library",library(match.getLibraryRecord()),
                    "score",match.getOverallScore(),"mode",match.getPrimaryFunctionMatchMode().toString(),"primary_code_units",match.getPrimaryFunctionCodeUnitScore(),"child_code_units",match.getChildFunctionCodeUnitScore(),"parent_code_units",match.getParentFunctionCodeUnitScore()));}
            }
        }
        return Map.of("engine","ghidra.FidService.processProgram","libraries",libraries,"items",rows,"total",total,"complete",rows.size()==total,"no_match",total==0,"functions_with_results",queried,"score_semantics","Native matching code-unit scores, not probabilities.");
    }
    static void check(FunctionDatabase database,Object result)throws Exception{if(result==null)throw new IllegalStateException("Native BSim query failed: "+database.getLastError().category);}
    static Map<String,Object> information(FunctionDatabase database){var info=database.getInfo();return Map.of("name",info.databasename,"layout_version",info.layout_version,"signature_major",info.major,"signature_minor",info.minor,"settings",Integer.toUnsignedString(info.settings),"engine","Ghidra BSim/H2");}
    static GenSignatures signatures(Program program,FunctionDatabase database,TaskMonitor monitor,JsonObject p)throws Exception{
        GenSignatures generator=new GenSignatures(false);boolean ready=false;try{generator.setVectorFactory(database.getLSHVectorFactory());generator.openProgram(program,"OwnedLibraryInput",null,null,null,null);
            if(p.has("function")){var address=program.getAddressFactory().getAddress(text(p,"function"));Function function=address==null?null:program.getFunctionManager().getFunctionAt(address);if(function==null)throw new IllegalArgumentException("No function starts at the query address");generator.scanFunction(function);}
            else generator.scanFunctions(program.getFunctionManager().getFunctions(true),program.getFunctionManager().getFunctionCount(),monitor);ready=true;return generator;
        }finally{if(!ready)generator.dispose();}
    }
    static Object bsim(Program program,JsonObject p,TaskMonitor monitor,boolean build)throws Exception{
        bounded(program);Path file;
        if(build)file=Path.of(text(p,"output"));else{file=Path.of(System.getProperty("java.io.tmpdir"),"query.mv.db");Files.copy(Path.of(text(p,"database")),file);}
        FunctionDatabase database=BSimClientFactory.buildClient(new BSimServerInfo(file.toString()),false);
        try{
            if(build){CreateDatabase request=new CreateDatabase();request.config_template=program.getDefaultPointerSize()==8?"medium_64":"medium_32";request.info=new DatabaseInformation();request.info.databasename=text(p,"library");request.info.owner="insight-cli";request.info.description="Explicit owned program snapshots";request.info.trackcallgraph=false;check(database,database.query(request));}
            if(!database.initialize())throw new IllegalStateException("Native BSim database did not initialize");
            try(var resource=new SignatureResource(signatures(program,database,monitor,p))){GenSignatures generator=resource.value;
                if(build){InsertRequest request=new InsertRequest();request.manage=generator.getDescriptionManager();check(database,database.query(request));return Map.of("state","exported","format","BSim/H2","database",information(database),"source_sha256",program.getExecutableSHA256(),"functions",program.getFunctionManager().getFunctionCount());}
                QueryNearest request=new QueryNearest();request.manage=generator.getDescriptionManager();request.thresh=p.has("similarity")?p.get("similarity").getAsDouble():0.7;request.signifthresh=p.has("significance")?p.get("significance").getAsDouble():0;
                request.max=p.has("limit")?p.get("limit").getAsInt():20;request.vectormax=1000;var response=(ResponseNearest)database.query(request);check(database,response);
                List<Object> rows=new ArrayList<>();int total=0;for(var result:response.result){total+=result.getTotalCount();for(var note:result){var function=note.getFunctionDescription();rows.add(Map.of("query_name",result.getBase().getFunctionName(),"query_address","0x"+Long.toUnsignedString(result.getBase().getAddress(),16),
                        "name",function.getFunctionName(),"address","0x"+Long.toUnsignedString(function.getAddress(),16),"executable_md5",function.getExecutableRecord().getMd5(),"similarity",note.getSimilarity(),"significance",note.getSignificance()));}}
                return Map.of("engine","Ghidra BSim QueryNearest","database",information(database),"items",rows,"total",total,"complete",response.totalfunc>0&&rows.size()==total,"no_match",response.totalfunc>0&&rows.isEmpty(),"queried_functions",response.totalfunc,"score_semantics","Native weighted feature similarity and significance, not probabilities.");
            }
        }finally{database.close();var source=BSimH2FileDBConnectionManager.getDataSourceIfExists(database.getServerInfo());if(source!=null)source.dispose();}
    }
    static class SignatureResource implements AutoCloseable{final GenSignatures value;SignatureResource(GenSignatures value){this.value=value;}public void close(){value.dispose();}}
    static Object run(JsonObject p)throws Exception{
        String operation=text(p,"operation");TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(90,TimeUnit.SECONDS);
        try{
            if(operation.equals("fid-build"))return fidBuild(p,monitor);
            Object consumer=new Object();var db=PackedDatabase.getPackedDatabase(Path.of(text(p,"snapshot")).toFile(),true,monitor).open(monitor);ProgramDB program=new ProgramDB(db,OpenMode.IMMUTABLE,monitor,consumer);
            try{long before=program.getModificationNumber();Object result=switch(operation){case "fid-query"->fidQuery(program,p,monitor);case "bsim-build"->bsim(program,p,monitor,true);case "bsim-query"->bsim(program,p,monitor,false);default->throw new IllegalArgumentException("Unknown native function database operation");};
                if(program.getModificationNumber()!=before)throw new IllegalStateException("Function database query modified the source program");return result;
            }finally{program.release(consumer);}
        }finally{monitor.finished();}
    }
    public static void main(String[] args){var output=System.out;System.setOut(System.err);
        try{Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());JsonObject p=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();Object value=run(p);InsightNativeReceipt.write(p,value);output.println(new GsonBuilder().serializeNulls().create().toJson(Map.of("value",value)));System.exit(0);}
        catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"native_function_database_failed\"}");System.exit(1);}
    }
}
