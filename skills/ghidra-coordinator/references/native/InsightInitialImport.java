import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import insight.InsightInitialJournal;
import java.nio.file.*;
import java.nio.channels.*;
import java.util.*;

/** No repository connection: incomplete analysis can only leave a private attempt. */
class InsightInitialImport {
    public static void main(String[] args){var out=System.out;System.setOut(System.err);
        try{
            Path root=Path.of(args[0]);JsonObject p=InsightInitialJournal.intent(root);
            try(var channel=FileChannel.open(InsightInitialJournal.lockRoot(root).resolve("lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.tryLock()){
                if(lock==null){out.println("{\"state\":\"busy\"}");System.exit(0);}
                Path journal=root.resolve("import.json");
                if(Files.exists(journal)&&InsightInitialJournal.text(InsightInitialJournal.read(journal),"phase").equals("prepared")){
                    InsightInitialJournal.prepared(root);out.println("{\"state\":\"prepared\"}");System.exit(0);
                }
                if(Files.exists(root.resolve("publication.json")))throw new SecurityException("Publication already started without a prepared snapshot");
                Path input=Path.of(InsightInitialJournal.text(p,"input"));
                if(!InsightInitialJournal.hash(input).equals(InsightInitialJournal.text(p,"sha256")))throw new SecurityException("Input bytes changed");
                JsonObject s=new JsonObject();s.addProperty("intentHash",InsightInitialJournal.hash(root.resolve("intent.json")));
                s.addProperty("phase","importing");s.addProperty("pid",ProcessHandle.current().pid());s.addProperty("snapshot","attempt-"+UUID.randomUUID()+".gzf");
                Path attempt=root.resolve(InsightInitialJournal.text(s,"snapshot")+".json");InsightInitialJournal.write(attempt,s);InsightInitialJournal.write(journal,s);
                try(var progress=new InsightImportProgress(InsightInitialJournal.lockRoot(root),InsightInitialJournal.text(p,"target"),InsightInitialJournal.text(s,"snapshot"))){
                progress.phase("runtime-initialization");
                Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
                JsonObject settings=p.getAsJsonObject("settings"),request=new JsonObject();
                request.addProperty("input",input.toString());request.addProperty("output",root.resolve(InsightInitialJournal.text(s,"snapshot")).toString());
                request.add("auto_analyze",settings.get("autoAnalyze"));
                for(String key:List.of("language","loader"))if(settings.has(key))request.add(key,settings.get(key));
                if(settings.has("compilerSpec"))request.add("compiler_spec",settings.get("compilerSpec"));
                if(settings.has("imageBase"))request.add("image_base",settings.get("imageBase"));
                if(settings.has("loaderOptions"))request.add("options",settings.get("loaderOptions"));
                JsonObject metadata;
                try{metadata=new Gson().toJsonTree(InsightSdkFiles.importProgram(request,progress)).getAsJsonObject();}
                catch(Throwable failure){progress.state(progress.isCancelled()?"cancelled":"failed");throw failure;}
                progress.phase("snapshot-verification");
                Path file=root.resolve(InsightInitialJournal.text(s,"snapshot"));InsightInitialJournal.sync(file);
                s.add("metadata",metadata);s.addProperty("snapshotSha256",InsightInitialJournal.hash(file));s.addProperty("phase","prepared");InsightInitialJournal.write(attempt,s);InsightInitialJournal.write(journal,s);
                InsightInitialJournal.prepared(root);progress.state("prepared");out.println("{\"state\":\"prepared\"}");
                }
            }
            System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);out.println("{\"state\":\"failed\"}");System.exit(1);}
    }
}
