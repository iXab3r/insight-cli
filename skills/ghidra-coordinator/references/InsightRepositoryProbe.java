import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.User;
import com.xebyte.headless.GhidraServerManager;
import com.google.gson.Gson;
import java.util.*;
import java.io.PrintStream;

/** Fixed read-only probe. No write/checkout/terminate operation exists here. */
class InsightRepositoryProbe {
  public static void main(String[] args) {
    PrintStream output = System.out;
    System.setOut(System.err); // Ghidra diagnostics never share the result protocol.
    try {
      if (args.length != 3 || !Set.of("reader", "publisher").contains(args[2])) throw new IllegalArgumentException();
      Application.initializeApplication(new GhidraApplicationLayout(), new HeadlessGhidraApplicationConfiguration());
      GhidraServerManager manager = new GhidraServerManager();
      manager.connect();
      if (manager.server() == null || !manager.server().isConnected()) throw new IllegalStateException();
      RepositoryAdapter repository = manager.server().getRepository(args[0]);
      repository.connect();
      User user = repository.getUser();
      if (user == null || !user.getName().equals(System.getenv("GHIDRA_SERVER_USER"))) throw new IllegalStateException();
      if (args[2].equals("reader") ? !user.isReadOnly() : !user.hasWritePermission()) throw new SecurityException();
      int split = args[1].lastIndexOf('/');
      String folder = split == 0 ? "/" : args[1].substring(0, split), name = args[1].substring(split + 1);
      var item = repository.getItem(folder, name);
      if(item==null){
        boolean reserved=repository.fileExists(folder,name);
        repository.disconnect();manager.server().disconnect();
        output.println(new Gson().toJson(Map.of("state",reserved?"reserved":"absent","repository",args[0],"path",args[1],"permission",user.getPermissionType())));
        System.exit(0);
      }
      var checkouts = repository.getCheckouts(folder, name);
      var versions = repository.getVersions(folder, name);
      if (item == null || checkouts == null || versions == null || versions.length == 0) throw new IllegalStateException();
      List<Map<String,Object>> history = new ArrayList<>();
      for (var version : versions) history.add(Map.of("version", version.getVersion(), "comment", version.getComment() == null ? "" : version.getComment()));
      List<Long> ids = new ArrayList<>();
      for (var checkout : checkouts) ids.add(checkout.getCheckoutId());
      var result = new LinkedHashMap<String,Object>();
      result.put("repository",repository.getName()); result.put("path",(item.getParentPath().equals("/") ? "/" : item.getParentPath() + "/") + item.getName());
      result.put("version",item.getVersion()); result.put("permission",user.getPermissionType());
      result.put("checkouts",ids); result.put("checkinActive",repository.isCheckinActive(folder,name)); result.put("versions",history);
      repository.disconnect(); manager.server().disconnect();
      output.println(new Gson().toJson(result));
      System.exit(0);
    } catch (Throwable error) {
      output.println("{\"error\":\"authoritative_repository_probe_failed\"}");
      System.exit(1);
    }
  }
}
