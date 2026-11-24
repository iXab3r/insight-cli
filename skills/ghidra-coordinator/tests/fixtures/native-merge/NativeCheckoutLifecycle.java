import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.remote.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.ProgramDB;
import insight.prototype.HeadlessProgramMergeManager;
import java.nio.file.*;
import java.util.*;
import java.net.Authenticator;
import java.awt.Component;
import javax.security.auth.callback.*;

/** Separate JVM per operation; workers open the original native project offline. */
public class NativeCheckoutLifecycle extends NativeMergeFixture {
    static class NoCredentials implements ClientAuthenticator {
        int attempts;
        public Authenticator getAuthenticator(){return new Authenticator(){};}
        public boolean processPasswordCallbacks(String a,String b,String c,boolean d,NameCallback n,
                PasswordCallback p,ChoiceCallback choice,AnonymousCallback anon,String e){attempts++;return false;}
        public boolean promptForReconnect(Component c,String m){return false;}
        public char[] getNewPassword(Component c,String s,String u){return null;}
        public boolean isSSHKeyAvailable(){return false;}
        public boolean processSSHSignatureCallbacks(String s,NameCallback n,SSHSignatureCallback cb){return false;}
        public char[] getKeyStorePassword(String s,boolean b){return null;}
    }
    static Map<String,Object> changes(Program p){
        var c=((ProgramDB)p).getChanges();
        return Map.of("dataTypeChanges",c.getDataTypeChanges(),"dataTypeAdditions",c.getDataTypeAdditions(),
            "symbolChanges",c.getSymbolChanges(),"symbolAdditions",c.getSymbolAdditions(),
            "addresses",c.getAddressSet().toString());
    }
    public static void main(String[] args){
        var output=System.out;System.setOut(System.err);
        Project project=null;RepositoryAdapter repository=null;
        Map<String,Object> result=new LinkedHashMap<>();
        try {
            var q=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            Path root=Path.of(q.get("root").getAsString()).toRealPath();
            var owner=JsonParser.parseString(Files.readString(root.resolve("owner.json"))).getAsJsonObject();
            require(owner.get("id").equals(q.get("id")),"Proof ownership mismatch");
            String repo=owner.get("repository").getAsString(),op=q.get("operation").getAsString();
            String actor=q.get("actor").getAsString(),role=q.get("role").getAsString();
            require(repo.matches("native_merge_[a-f0-9]{32}")&&actor.matches("[a-z][a-z0-9]{0,30}"),"Owned fixture required");
            require(List.of("publisher","reader","worker").contains(role),"Unknown role");
            result.put("operation",op);result.put("actor",actor);result.put("role",role);
            result.put("pid",ProcessHandle.current().pid());
            Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            Class.forName("ghidra.program.database.ProgramMultiUserMergeManagerFactory");
            PluggableServiceRegistry.registerPluggableService(ghidra.program.database.ProgramMultiUserMergeManagerFactory.class,new HeadlessFactory());
            NoCredentials denied=null;
            if(role.equals("worker")) {
                require(System.getenv().keySet().stream().noneMatch(k->k.matches("(?i).*(PASSWORD|TOKEN|SECRET|CREDENTIAL|KEYSTORE).*")),"Worker inherited a secret variable");
                denied=new NoCredentials();ClientUtil.setClientAuthenticator(denied);
                result.put("credentialVariablesAbsent",true);
            } else {
                String password=System.getenv("PROOF_ROLE_PASSWORD");require(password!=null&&password.length()>=48,"Role credential missing");
                ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(role,password));
                var server=ClientUtil.getRepositoryServer("127.0.0.1",q.get("port").getAsInt(),true);
                require(server.isConnected(),"Authorized connection failed");
                repository=server.getRepository(repo);repository.connect();
                require(repository.isConnected()&&repository.getUser().getName().equals(role),"Wrong server authority");
                result.put("serverReadOnly",repository.getUser().isReadOnly());
            }
            Path projectRoot=root.resolve("projects").resolve(actor);Files.createDirectories(projectRoot);
            ProjectLocator locator=new ProjectLocator(projectRoot.toString(),"work");Projects manager=new Projects();
            boolean create=List.of("baseline","checkout","read").contains(op);
            require(!create||!role.equals("worker"),"Worker cannot create or replace a checkout");
            project=create?manager.createProject(locator,repository,false):manager.openProject(locator,false,false);
            result.put("project",locator.getProjectDir().getCanonicalPath());
            var bound=project.getProjectData().getRepository();
            require(bound!=null&&bound.getName().equals(repo),"Saved repository binding lost");
            result.put("repositoryConnected",bound.isConnected());
            if(role.equals("worker")) {
                require(!bound.isConnected(),"Credentialless worker unexpectedly connected");
                result.put("authenticationRefusals",denied.attempts);
            }
            if(op.equals("baseline"))createBaseline(project);
            DomainFile file=project.getProjectData().getFile("/fixture");require(file!=null,"Native file missing");
            result.put("fileId",file.getFileID());
            if(op.equals("checkout")) {
                require(file.checkout(false,MONITOR),"Native checkout rejected");
                require(file.isCheckedOut()&&!file.isCheckedOutExclusive(),"Normal checkout required");
            } else if(op.equals("edit")) {
                require(role.equals("worker")&&file.isCheckedOut(),"Edit requires offline checkout");
                Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                try {edit(p,q.get("index").getAsInt(),q.has("conflict")&&q.get("conflict").getAsBoolean());p.save("Offline worker edit",MONITOR);}
                finally{p.release(CONSUMER);}
            } else if(op.equals("update")) {
                result.put("checkoutBefore",file.getCheckoutStatus().getCheckoutId());
                result.put("baseBefore",file.getCheckoutStatus().getCheckoutVersion());
                result.put("latestBefore",file.getLatestVersion());
                file.merge(false,MONITOR);
            } else if(op.equals("checkin")) {
                result.put("baseBefore",file.getVersion());
                file.checkin(new DefaultCheckinHandler("lifecycle "+actor,false,false),MONITOR);
                require(!file.isCheckedOut(),"Check-in must release checkout");
            } else if(op.equals("releaseclean")) {
                require(file.isCheckedOut()&&!file.modifiedSinceCheckout(),"Only an unchanged checkout may be released");
                file.undoCheckout(false);require(!file.isCheckedOut(),"Native checkout release failed");
            } else if(op.equals("drop")) {
                require(!file.isCheckedOut(),"Live or unpublished checkout must not be dropped");
                require(projectRoot.toRealPath().equals(root.resolve("projects").resolve(actor)),"Owned directory moved");
                for(Path target:List.of(locator.getProjectDir().toPath(),locator.getMarkerFile().toPath()))
                    require(target.toRealPath().startsWith(projectRoot),"Deletion escaped owned project");
                project.close();project=null;require(manager.deleteProject(locator),"Native project deletion failed");
                require(!locator.getProjectDir().exists()&&!locator.getMarkerFile().exists(),"Project remains");
                result.put("copyDropped",true);
            } else require(List.of("baseline","checkout","edit","local","read").contains(op),"Unknown operation");
            if(project!=null) {
                file=project.getProjectData().getFile("/fixture");
                result.put("checkedOut",file.isCheckedOut());result.put("localVersion",file.getVersion());
                if(bound.isConnected()&&file.isCheckedOut()) {
                    result.put("checkoutId",file.getCheckoutStatus().getCheckoutId());
                    result.put("baseVersion",file.getCheckoutStatus().getCheckoutVersion());
                }
                Program p=(Program)file.getDomainObject(CONSUMER,false,false,MONITOR);
                try {result.put("program",inspect(p));result.put("changes",changes(p));}
                finally{p.release(CONSUMER);}
                result.put("projectFiles",Arrays.stream(project.getProjectData().getRootFolder().getFiles()).map(DomainFile::getName).sorted().toList());
            }
            if(repository!=null) {
                result.put("versions",Arrays.stream(repository.getVersions("/","fixture")).map(v->v.getVersion()).toList());
                result.put("checkouts",Arrays.stream(repository.getCheckouts("/","fixture")).map(c->Map.of("id",c.getCheckoutId(),"version",c.getCheckoutVersion())).toList());
            }
            result.put("nativeMergeInvocations",HeadlessProgramMergeManager.invocations);
            result.put("nativePhases",HeadlessProgramMergeManager.phases);
            require(java.awt.Window.getWindows().length==0,"Unexpected GUI");result.put("guiWindows",0);
            if(project!=null){project.close();project=null;}
            if(repository!=null)repository.getServer().disconnect();
            output.println(new Gson().toJson(result));System.exit(0);
        } catch(Throwable error) {
            error.printStackTrace(System.err);result.put("state","failed");result.put("error",error.getClass().getName());
            result.put("message",String.valueOf(error.getMessage()));
            if(project!=null)project.close();if(repository!=null)repository.getServer().disconnect();
            output.println(new Gson().toJson(result));System.exit(1);
        }
    }
}
