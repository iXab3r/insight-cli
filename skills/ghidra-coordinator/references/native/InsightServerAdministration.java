import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import java.nio.file.*;
import java.util.*;

/** Explicit repository administration with server-side authority and independent effect readback. */
class InsightServerAdministration {
  static String string(JsonObject value,String name){return value.has(name)?value.get(name).getAsString():"";}
  static String parent(String path){int i=path.lastIndexOf('/');return i>0?path.substring(0,i):"/";}
  static String leaf(String path){return path.substring(path.lastIndexOf('/')+1);}
  static Map<String,Object> file(RepositoryItem item){return Map.of("name",item.getName(),"path",item.getPathName(),"type",item.getContentType(),"version",item.getVersion());}
  static void admin(RepositoryAdapter repo)throws Exception{if(!repo.getUser().isAdmin())throw new SecurityException("Repository administration requires actual admin permission");}
  static List<RepositoryItem> files(RepositoryAdapter repo,String at)throws Exception{
    List<RepositoryItem> out=new ArrayList<>();RepositoryItem exact=at.equals("/")?null:repo.getItem(parent(at),leaf(at));
    if(exact!=null){out.add(exact);return out;}
    var pending=new ArrayDeque<String>();pending.add(at);int folders=0;
    while(!pending.isEmpty()){if(++folders>10000)throw new IllegalArgumentException("Repository walk exceeds 10000 folders");String folder=pending.remove();
      var items=repo.getItemList(folder);if(items!=null)Collections.addAll(out,items);
      if(out.size()>10000)throw new IllegalArgumentException("Repository walk exceeds 10000 files");
      var children=repo.getSubfolderList(folder);if(children!=null)for(String child:children)pending.add((folder.equals("/")?"":folder)+"/"+child);}
    return out;
  }
  public static void main(String[] args){var output=System.out;System.setOut(System.err);
    try{
      if(args.length!=1)throw new IllegalArgumentException();String encoded=Files.readString(Path.of(args[0]));if(encoded.length()>65536)throw new IllegalArgumentException();
      JsonObject request=JsonParser.parseString(encoded).getAsJsonObject();String operation=string(request,"operation"),name=string(request,"repository"),path=string(request,"path");
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      var manager=new GhidraServerManager();manager.connect();var server=manager.server();if(server==null||!server.isConnected())throw new SecurityException("Server connection missing");
      Map<String,Object> result=new LinkedHashMap<>();
      try{
        if(operation.equals("repositories")){var names=server.getRepositoryNames();result.put("repositories",Arrays.asList(names));result.put("count",names.length);}
        else if(operation.equals("users")){var users=server.getAllUsers();result.put("users",Arrays.stream(users).map(user->Map.of("name",user)).toList());result.put("count",users.length);}
        else if(operation.equals("create_repository")){
          server.createRepository(name).connect();if(!Arrays.asList(server.getRepositoryNames()).contains(name))throw new IllegalStateException("Created repository missing");
          result.put("state","created");result.put("repository",name);
        }else{
          var repo=server.getRepository(name);repo.connect();try{
            result.put("repository",name);
            if(operation.equals("files")){var folders=repo.getSubfolderList(path);var items=repo.getItemList(path);
              result.put("path",path);result.put("folders",folders==null?List.of():Arrays.asList(folders));result.put("files",items==null?List.of():Arrays.stream(items).map(InsightServerAdministration::file).toList());}
            else if(operation.equals("file")){var item=repo.getItem(parent(path),leaf(path));if(item==null)throw new IllegalArgumentException("Repository file missing");result.put("file",file(item));}
            else if(operation.equals("permissions")){result.put("users",Arrays.stream(repo.getUserList()).map(user->Map.of("name",user.getName(),"access",user.getPermissionType())).toList());result.put("anonymous",repo.anonymousAccessAllowed());}
            else if(operation.equals("set_permissions")){
              admin(repo);String user=string(request,"user");int level=request.get("access").getAsInt();if(level<0||level>2)throw new IllegalArgumentException();
              var before=new LinkedHashMap<String,Integer>();for(var item:repo.getUserList())before.put(item.getName(),item.getPermissionType());
              boolean anonymous=repo.anonymousAccessAllowed();before.put(user,level);repo.setUserList(before.entrySet().stream().map(item->new User(item.getKey(),item.getValue())).toArray(User[]::new),anonymous);
              var after=new LinkedHashMap<String,Integer>();for(var item:repo.getUserList())after.put(item.getName(),item.getPermissionType());
              if(!before.equals(after)||repo.anonymousAccessAllowed()!=anonymous)throw new IllegalStateException("Repository ACL readback mismatch");
              result.put("state","applied");result.put("users",after);result.put("anonymous",anonymous);
            }else if(operation.equals("history")){var versions=repo.getVersions(parent(path),leaf(path));
              result.put("path",path);result.put("versions",Arrays.stream(versions).map(version->Map.of("version",version.getVersion(),"user",version.getUser(),"time",version.getCreateTime(),"comment",Objects.toString(version.getComment(),""))).toList());}
            else if(Set.of("checkouts","terminate_checkout","terminate_all_checkouts").contains(operation)){
              boolean changing=!operation.equals("checkouts");if(changing)admin(repo);List<Object> rows=new ArrayList<>();int terminated=0;
              var selected=files(repo,path);
              if(changing)for(var item:selected){String itemPath=item.getPathName();
                if(request.has("protected_repository")&&name.equals(string(request,"protected_repository"))&&itemPath.matches("/t_[a-f0-9-]+\\.bin"))throw new SecurityException("Facade publication checkout is protected");
                if(repo.isCheckinActive(parent(itemPath),leaf(itemPath)))throw new IllegalStateException("File has an active check-in");}
              for(var item:selected){String itemPath=item.getPathName();
                var statuses=repo.getCheckouts(parent(itemPath),leaf(itemPath));if(statuses==null)continue;
                for(var checkout:statuses){String id=Long.toString(checkout.getCheckoutId());
                  if(changing){if(operation.equals("terminate_checkout")&&request.has("checkout_id")&&!id.equals(string(request,"checkout_id")))continue;
                    repo.terminateCheckout(parent(itemPath),leaf(itemPath),checkout.getCheckoutId(),false);
                    if(repo.getCheckout(parent(itemPath),leaf(itemPath),checkout.getCheckoutId())!=null)throw new IllegalStateException("Checkout remains after termination");terminated++;}
                  else rows.add(Map.of("path",itemPath,"id",id,"user",checkout.getUser(),"version",checkout.getCheckoutVersion(),"type",checkout.getCheckoutType().toString()));}
              }
              result.put(changing?"terminated":"checkouts",changing?terminated:rows);result.put("path",path);
            }else throw new IllegalArgumentException("Unsupported server administration operation");
          }finally{repo.disconnect();}
        }
      }finally{server.disconnect();}
      output.println(new GsonBuilder().serializeNulls().create().toJson(result));System.exit(0);
    }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"server_administration_not_verified\"}");System.exit(1);}
  }
}
