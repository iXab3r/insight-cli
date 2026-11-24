import insight.nativecheckout.InsightSnapshotFields;
import insight.nativecheckout.InsightSnapshotInspect;
import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;
import db.*;
import java.nio.file.*;
import java.util.*;

/** Independent read authority, immutable exact-version native database; never checks out. */
public final class InsightNativeRead {
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);
        try {
            JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            String repo=q.get("repository").getAsString(),path=q.get("path").getAsString(),sha=q.get("sourceSha").getAsString(),op=q.get("operation").getAsString();
            if(!path.startsWith("/")||path.indexOf('/',1)>=0)throw new SecurityException();String name=path.substring(1);
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            var server=new GhidraServerManager();server.connect();var repository=server.server().getRepository(repo);repository.connect();
            if(!repository.getUser().isReadOnly()||!repository.getUser().getName().equals(System.getenv("GHIDRA_SERVER_USER")))throw new SecurityException();
            var item=repository.getItem("/",name);
            if(item==null&&op.equals("migration-probe")){repository.disconnect();server.disconnect();output.println("{\"state\":\"absent\"}");System.exit(0);}
            if(item==null||repository.isCheckinActive("/",name))throw new IllegalStateException("Native item is absent or busy");
            int version=q.has("version")?q.get("version").getAsInt():item.getVersion();
            if(q.has("fileId")&&!item.getFileID().equals(q.get("fileId").getAsString()))throw new SecurityException("Native item ID changed");
            if(op.equals("verify")){
                var matches=Arrays.stream(repository.getVersions("/",name)).filter(v->q.get("marker").getAsString().equals(v.getComment())).toList();
                if(matches.size()!=1||matches.getFirst().getVersion()!=version)throw new IllegalStateException("Native history marker is unresolved");
            }
            DBHandle db=new DBHandle(repository.openDatabase("/",name,version,-1));Object consumer=new Object();ProgramDB program=null;
            Map<String,Object> result=new LinkedHashMap<>();
            try {
                String fingerprint=InsightNativeFingerprint.of(db);
                program=new ProgramDB(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
                if(!sha.equals(program.getExecutableSHA256()))throw new SecurityException("Native source changed");
                if(!op.equals("migration-probe")&&!program.getOptions("Insight").getString("Publication Engine","").equals("native-checkout-v1"))throw new InsightNativeMigration.Required();
                if(q.has("fingerprint")&&!fingerprint.equals(q.get("fingerprint").getAsString()))throw new SecurityException("Exact native buffers differ");
                result.put("state","verified");result.put("version",version);result.put("fileId",item.getFileID());result.put("fingerprint",fingerprint);
                if(op.equals("migration-probe")){result.put("content",InsightNativeFingerprint.content(db));result.put("engine",program.getOptions("Insight").getString("Publication Engine",""));result.put("programIdentity",InsightNativeMigration.programIdentity(program));var functions=program.getFunctionManager().getFunctions(true);int samples=0;String sample=null;
                    while(functions.hasNext()&&samples++<1000){var f=functions.next();var block=program.getMemory().getBlock(f.getEntryPoint());if(!f.isThunk()&&block!=null&&block.isInitialized()&&block.isExecute()){if(sample==null)sample=f.getEntryPoint().toString();if(program.getReferenceManager().getReferencesTo(f.getEntryPoint()).hasNext()){sample=f.getEntryPoint().toString();break;}}}result.put("sampleFunction",sample);
                    result.put("language",program.getLanguageID().toString());result.put("compiler",program.getCompilerSpec().getCompilerSpecID().toString());result.put("imageBase",program.getImageBase().toString());result.put("versions",Arrays.stream(repository.getVersions("/",name)).map(v->Map.of("version",v.getVersion(),"comment",Objects.toString(v.getComment(),""))).toList());}
                else if(op.equals("inspect"))result.put("value",InsightSnapshotInspect.inspect(program,q.getAsJsonObject("parameters")));
                else if(op.equals("fields"))result.put("fields",InsightSnapshotFields.inspect(program,q.getAsJsonArray("selectors")));
                else if(op.equals("export")){program.saveToPackedFile(Path.of(q.get("output").getAsString()).toFile(),TaskMonitor.DUMMY);result.put("output",q.get("output").getAsString());}
                else if(!Set.of("latest","verify","view").contains(op))throw new IllegalArgumentException();
                result.put("checkouts",Arrays.stream(repository.getCheckouts("/",name)).map(c->Map.of("id",c.getCheckoutId(),"version",c.getCheckoutVersion())).toList());
            }finally{if(program!=null)program.release(consumer);else db.close();}
            var after=repository.getItem("/",name);
            if(after==null||!after.getFileID().equals(item.getFileID())||after.getVersion()<version)throw new SecurityException("Native item changed while reading its exact version");
            repository.disconnect();server.disconnect();output.println(new GsonBuilder().serializeNulls().create().toJson(result));System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);output.println(new Gson().toJson(Map.of("state","unknown","diagnostic",failure.getClass().getSimpleName(),"reason",Objects.toString(failure.getMessage(),failure.toString()),"code",failure instanceof InsightNativeMigration.Required?"migration":"unknown")));System.exit(0);}
    }
}
