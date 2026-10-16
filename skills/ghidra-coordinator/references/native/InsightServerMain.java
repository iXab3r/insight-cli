import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.server.remote.GhidraServer;
import java.net.InetSocketAddress;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Owned loopback server with an authenticated identity probe, not an administration API. */
class InsightServerMain {
  public static void main(String[] args) throws Exception {
    if(args.length!=5) throw new IllegalArgumentException();
    Path root=Path.of(args[0]).toRealPath();
    int port=Integer.parseInt(args[1]), healthPort=Integer.parseInt(args[2]);
    String instance=args[3], keystore=args[4];
    String token=System.getenv("INSIGHT_SERVER_TOKEN"), password=System.getenv("INSIGHT_KEYSTORE_PASSWORD");
    if(token==null || token.length()<32 || password==null || password.length()<32) throw new SecurityException();
    FileChannel channel=FileChannel.open(root.resolveSibling("server.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);
    var lock=channel.tryLock(); if(lock==null) throw new IllegalStateException("Owned server already running");
    System.setProperty("ghidra.keystore",keystore);
    ApplicationKeyManagerFactory.setKeyStorePasswordProvider((path,retry)->password.toCharArray());
    GhidraServer.main(new String[]{"-i","127.0.0.1","-ip","127.0.0.1","-p"+port,"-a0","-e0","-u",root.toString()});
    HttpServer health=HttpServer.create(new InetSocketAddress("127.0.0.1",healthPort),4);
    byte[] authorization=("Bearer "+token).getBytes(StandardCharsets.UTF_8);
    health.createContext("/identity",exchange->{
      String supplied=exchange.getRequestHeaders().getFirst("Authorization");
      if(!exchange.getRequestMethod().equals("GET") || !exchange.getRequestURI().toString().equals("/identity") ||
          supplied==null || !MessageDigest.isEqual(authorization,supplied.getBytes(StandardCharsets.UTF_8))) {
        exchange.sendResponseHeaders(403,-1); exchange.close(); return;
      }
      byte[] response=new Gson().toJson(Map.of("pid",ProcessHandle.current().pid(),"instance",instance,"port",port)).getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type","application/json");
      exchange.sendResponseHeaders(200,response.length); exchange.getResponseBody().write(response); exchange.close();
    });
    health.start();
    Runtime.getRuntime().addShutdownHook(new Thread(()->{
      health.stop(0); try {lock.release();channel.close();} catch(Exception ignored){}
    }));
  }
}
