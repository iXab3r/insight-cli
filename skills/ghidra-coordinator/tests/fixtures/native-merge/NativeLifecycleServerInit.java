package ghidra.server;

import generic.hash.HashUtilities;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.remote.User;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

/** Fixture bootstrap, before its loopback server starts; no production profile. */
public class NativeLifecycleServerInit {
    public static void main(String[] args) throws Exception {
        var output=System.out;System.setOut(System.err);
        Path root=Path.of(args[0]).toRealPath();
        var owner=JsonParser.parseString(Files.readString(root.resolve("owner.json"))).getAsJsonObject();
        String name=owner.get("repository").getAsString();
        if(!name.matches("native_merge_[a-f0-9]{32}"))throw new SecurityException();
        Path data=root.resolve("server/repositories");
        if(Files.list(data).findAny().isPresent())throw new SecurityException("Fresh server required");
        Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
        RepositoryManager manager=new RepositoryManager(data.toFile(),true,0,false);
        try {
            for(String role:List.of("PUBLISHER","READER")) {
                String secret=System.getenv("PROOF_"+role+"_PASSWORD");
                if(secret==null||secret.length()<48)throw new SecurityException("Fresh credential required");
                char[] password=secret.toCharArray();
                char[] hash=HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM,password);
                try {
                    manager.getUserManager().addUser(role.toLowerCase(Locale.ROOT),hash.clone());
                    manager.getUserManager().setPassword(role.toLowerCase(Locale.ROOT),hash.clone(),false);
                } finally {Arrays.fill(password,'\0');Arrays.fill(hash,'\0');}
            }
            var repo=manager.createRepository("publisher",name);
            repo.setUserList("publisher",new User[]{new User("publisher",User.ADMIN),new User("reader",User.READ_ONLY)},false);
        } finally {manager.dispose();}
        output.println("{\"state\":\"ready\",\"readerReadOnly\":true,\"publisherAdmin\":true}");
        System.exit(0);
    }
}
