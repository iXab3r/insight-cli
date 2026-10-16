package insight;

import com.google.gson.*;
import java.nio.file.*;
import java.nio.channels.*;
import java.security.MessageDigest;
import java.util.*;

/** Initial-model receipts, shared by private import and conditional create/readback helpers. */
public class InsightInitialJournal {
    public static String text(JsonObject p,String key){return p.get(key).getAsString();}
    public static JsonObject read(Path p)throws Exception{
        if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)>1048576)throw new SecurityException("Invalid initial-model receipt");
        return JsonParser.parseString(Files.readString(p)).getAsJsonObject();
    }
    public static String hash(Path p)throws Exception{
        if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new SecurityException("Invalid initial-model file");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(p)){byte[] b=new byte[65536];for(int n;(n=in.read(b))>=0;)if(n>0)hash.update(b,0,n);}
        return HexFormat.of().formatHex(hash.digest());
    }
    public static void sync(Path p)throws Exception{try(var f=FileChannel.open(p,StandardOpenOption.WRITE)){f.force(true);}}
    public static void write(Path p,JsonObject value)throws Exception{
        Path temp=p.resolveSibling(p.getFileName()+".new-"+UUID.randomUUID());
        Files.writeString(temp,new Gson().toJson(value),StandardOpenOption.CREATE_NEW);sync(temp);
        Files.move(temp,p,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        if(!System.getProperty("os.name").toLowerCase().contains("win"))try(var d=FileChannel.open(p.getParent(),StandardOpenOption.READ)){d.force(true);}
    }
    public static JsonObject intent(Path root)throws Exception{
        if(!root.toRealPath().equals(root.toAbsolutePath().normalize()))throw new SecurityException("Initial-model root moved");
        JsonObject p=read(root.resolve("intent.json"));
        if(p.get("schema").getAsInt()!=1||!text(p,"target").matches("t_[a-f0-9]{32}")||!text(p,"id").matches("[a-f0-9-]{36}")||!text(p,"sha256").matches("[a-f0-9]{64}"))throw new SecurityException("Invalid initial-model identity");
        return p;
    }
    public static JsonObject prepared(Path root)throws Exception{
        JsonObject p=intent(root),s=read(root.resolve("import.json"));
        if(!text(s,"intentHash").equals(hash(root.resolve("intent.json")))||!text(s,"phase").equals("prepared"))throw new SecurityException("Import is not prepared");
        String name=text(s,"snapshot");if(!name.matches("attempt-[a-f0-9-]{36}\\.gzf"))throw new SecurityException();
        Path file=root.resolve(name);if(!text(s,"snapshotSha256").equals(hash(file)))throw new SecurityException("Initial snapshot changed");
        JsonObject v=s.getAsJsonObject("metadata"),settings=p.getAsJsonObject("settings");
        if(!text(v,"sha256").equals(text(p,"sha256"))||v.get("auto_analyzed").getAsBoolean()!=settings.get("autoAnalyze").getAsBoolean())throw new SecurityException();
        for(String key:List.of("language","compilerSpec","imageBase"))if(settings.has(key)){
            String field=key.equals("compilerSpec")?"compiler":key.equals("imageBase")?"base_address":key;
            String got=text(v,field);if(key.equals("imageBase"))got=got.replaceFirst("^0+(?!$)","");
            if(!got.equals(text(settings,key)))throw new SecurityException("Initial load settings changed");
        }
        return s;
    }
}
