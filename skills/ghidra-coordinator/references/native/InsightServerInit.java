package ghidra.server;

import com.google.gson.Gson;
import generic.hash.HashUtilities;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.remote.User;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;

/** Initialize only the facade's owned local storage, before any network listener exists. */
class InsightServerInit {
  public static void main(String[] args) {
    var output = System.out; System.setOut(System.err);
    try {
      if(args.length!=4) throw new IllegalArgumentException();
      Path root=Path.of(args[0]).toRealPath();
      String repository=args[1], publisher=args[2], reader=args[3];
      if(publisher.equals(reader) || !repository.startsWith("insight_")) throw new IllegalArgumentException();
      try(var channel=FileChannel.open(root.resolveSibling("server.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);
          var lock=channel.tryLock()) {
        if(lock==null) throw new IllegalStateException("Owned server is already running");
        Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
        RepositoryManager manager=new RepositoryManager(root.toFile(),true,0,false);
        try {
          UserManager users=manager.getUserManager();
          for(String role:List.of("PUBLISHER","READER")) {
            String user=role.equals("PUBLISHER")?publisher:reader;
            String secret=System.getenv("INSIGHT_"+role+"_PASSWORD");
            if(secret==null || secret.length()<32) throw new SecurityException();
            char[] password=secret.toCharArray();
            try {
              if(!users.isValidUser(user)) {
                char[] hash=HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM,password);
                try { users.addUser(user,hash.clone()); users.setPassword(user,hash.clone(),false); }
                finally { Arrays.fill(hash,'\0'); }
              }
              users.authenticateUser(user,password);
            } finally { Arrays.fill(password,'\0'); }
          }
          Repository model=manager.getRepository(publisher,repository);
          if(model==null) {
            model=manager.createRepository(publisher,repository);
            model.setUserList(publisher,new User[]{new User(publisher,User.ADMIN),new User(reader,User.READ_ONLY)},false);
          }
          var permissions=model.getUserList(publisher);
          if(permissions.length!=2 || model.anonymousAccessAllowed() ||
              Arrays.stream(permissions).noneMatch(user->user.getName().equals(reader)&&user.isReadOnly()) ||
              Arrays.stream(permissions).noneMatch(user->user.getName().equals(publisher)&&user.isAdmin()))
            throw new SecurityException("Owned repository authority changed");
        } finally { manager.dispose(); }
      }
      output.println(new Gson().toJson(Map.of("state","ready","repository",repository,"readerReadOnly",true,"publisherAdmin",true)));
      System.exit(0);
    } catch(Throwable failure) {
      failure.printStackTrace(System.err);
      output.println("{\"state\":\"failed\",\"error\":\"owned_server_initialization_failed\"}"); System.exit(1);
    }
  }
}
