import com.google.gson.*;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.util.*;

/** Domain-effect receipt: close/sync native outputs before acknowledging a file/database result. */
class InsightNativeReceipt {
    static void write(JsonObject request,Object value)throws Exception{
        if(!request.has("receipt"))return;
        Map<String,Object> result=new LinkedHashMap<>();result.put("request",request.get("request_id").getAsString());result.put("operation",request.get("operation").getAsString());result.put("value",value);
        if(request.has("output")){
            Path directory=Path.of(request.get("output").getAsString()).getParent();List<Object> files=new ArrayList<>();
            try(var entries=Files.list(directory)){
                for(Path file:entries.sorted().toList()){
                    if(files.size()>=64||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Native output manifest requires at most 64 regular files");
                    long size=Files.size(file);if(size<1||size>4294967296L)throw new IllegalArgumentException("Native output exceeds artifact limits");
                    MessageDigest hash=MessageDigest.getInstance("SHA-256");try(var input=Files.newInputStream(file)){byte[] buffer=new byte[65536];for(int count;(count=input.read(buffer))>=0;)if(count>0)hash.update(buffer,0,count);}
                    try(FileChannel channel=FileChannel.open(file,StandardOpenOption.WRITE)){channel.force(true);}
                    files.add(Map.of("name",file.getFileName().toString(),"size",size,"sha256",HexFormat.of().formatHex(hash.digest())));
                }
            }
            if(files.isEmpty())throw new IllegalStateException("Native output is empty");result.put("files",files);
        }
        Path receipt=Path.of(request.get("receipt").getAsString()),temporary=receipt.resolveSibling("receipt-"+UUID.randomUUID()+".new");
        Files.writeString(temporary,new GsonBuilder().serializeNulls().create().toJson(result),StandardOpenOption.CREATE_NEW);
        try(FileChannel channel=FileChannel.open(temporary,StandardOpenOption.WRITE)){channel.force(true);}
        Files.move(temporary,receipt,StandardCopyOption.ATOMIC_MOVE);
        if(!System.getProperty("os.name").toLowerCase().contains("win"))try(FileChannel channel=FileChannel.open(receipt.getParent(),StandardOpenOption.READ)){channel.force(true);}
    }
}
