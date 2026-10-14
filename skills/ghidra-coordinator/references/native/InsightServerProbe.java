import com.google.gson.Gson;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.util.*;

/** Verify actual repository credentials and permissions, without creating or changing anything. */
class InsightServerProbe {
  public static void main(String[] args) {
    var output=System.out; System.setOut(System.err);
    try {
      if(args.length!=2 || !Set.of("reader","publisher").contains(args[1])) throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      GhidraServerManager manager=new GhidraServerManager(); manager.connect();
      var repository=manager.server().getRepository(args[0]); repository.connect();
      var user=repository.getUser();
      if(user==null || !user.getName().equals(System.getenv("GHIDRA_SERVER_USER")) ||
          (args[1].equals("reader")?!user.isReadOnly():!user.hasWritePermission())) throw new SecurityException();
      int permission=user.getPermissionType();
      repository.disconnect(); manager.server().disconnect();
      output.println(new Gson().toJson(Map.of("repository",args[0],"role",args[1],"permission",permission)));
      System.exit(0);
    } catch(Throwable failure) {
      failure.printStackTrace(System.err);
      output.println("{\"error\":\"repository_authority_not_verified\"}"); System.exit(1);
    }
  }
}
