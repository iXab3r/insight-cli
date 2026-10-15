import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.*;
import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.archive.ArchiveBridge;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;

/** Operations are confined to a facade-owned project, never a research worker project. */
class InsightProjectFiles {
  static String string(JsonObject p,String key){return p.get(key).getAsString();}
  static String path(JsonObject p,String key){String s=string(p,key);
    if(!s.startsWith("/")||s.contains("\\")||s.contains("//")||Arrays.stream(s.split("/")).anyMatch(x->x.equals(".")||x.equals("..")))throw new IllegalArgumentException();return s;}
  static DomainFolder folder(ProjectData data,String path){DomainFolder f=data.getFolder(path);if(f==null)throw new IllegalArgumentException("Folder not found");return f;}
  static DomainFile file(ProjectData data,String path){DomainFile f=data.getFile(path);if(f==null)throw new IllegalArgumentException("File not found");return f;}
  static Map<String,Object> describe(DomainFile f){return Map.of("name",f.getName(),"path",f.getPathname(),"type",f.getContentType());}
  static String parent(String path){int at=path.lastIndexOf('/');return at==0?"/":path.substring(0,at);}
  static String name(String path){String n=path.substring(path.lastIndexOf('/')+1);if(n.isEmpty()||n.startsWith("."))throw new IllegalArgumentException();return n;}
  public static void main(String[] args){var out=System.out;System.setOut(System.err);GhidraProject project=null;
    try{
      if(args.length!=1)throw new IllegalArgumentException();
      Path requestPath=Path.of(args[0]).toRealPath();String requestJson=Files.readString(requestPath);
      JsonObject p=JsonParser.parseString(requestJson).getAsJsonObject();
      Path root=Path.of(string(p,"root")).toRealPath();
      JsonObject owner=JsonParser.parseString(Files.readString(root.resolve("owner.json"))).getAsJsonObject();
      if(!string(owner,"project").equals(string(p,"project"))||!string(owner,"profile").equals(string(p,"profile")))throw new IllegalArgumentException("Ownership mismatch");
      Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
      String op=string(p,"operation");Map<String,Object> result=new LinkedHashMap<>();result.put("project",string(p,"project"));
      if(op.equals("restore")){
        try(ZipFile zip=new ZipFile(string(p,"input"))){int count=0;long total=0;var entries=zip.entries();
          while(entries.hasMoreElements()){ZipEntry entry=entries.nextElement();String n=entry.getName();Path relative=Path.of(n);
            if(++count>100000||relative.isAbsolute()||n.contains("\\")||Arrays.stream(n.split("/")).anyMatch(x->x.equals(".."))||!root.resolve(relative).normalize().startsWith(root))throw new IllegalArgumentException("Archive entry escapes owned project");
            if(entry.getSize()<0||entry.getSize()>4294967296L||(total+=entry.getSize())>4294967296L)throw new IllegalArgumentException("Archive exceeds restore limit");
          }
        }
        ProjectLocator locator=new ProjectLocator(root.toString(),"project");
        if(locator.getProjectDir().exists()||locator.getMarkerFile().exists())throw new IllegalArgumentException("Destination exists");
        ArchiveBridge.restore(Path.of(string(p,"input")).toFile(),locator,TaskMonitor.DUMMY);
      }
      project=op.equals("create")?GhidraProject.createProject(root.toString(),"project",false):GhidraProject.openProject(root.toString(),"project",false);
      ProjectData data=project.getProjectData();
      if(op.equals("create")||op.equals("restore")||op.equals("open")||op.equals("close"))result.put("state",op.equals("close")?"closed":"ready");
      else if(op.equals("info"))result.put("state","ready");
      else if(op.equals("files")){
        String selected=path(p,"path");DomainFolder f=folder(data,selected);
        List<Map<String,Object>> entries=new ArrayList<>();
        for(DomainFolder child:f.getFolders())entries.add(Map.of("name",child.getName(),"path",child.getPathname(),"type","Folder"));
        for(DomainFile child:f.getFiles())entries.add(describe(child));
        entries.sort(Comparator.comparing(row->row.get("path").toString()));
        int offset=p.get("offset").getAsInt(),limit=p.get("limit").getAsInt();
        result.put("path",selected);result.put("total",entries.size());result.put("offset",offset);result.put("limit",limit);
        result.put("items",entries.subList(Math.min(offset,entries.size()),Math.min(entries.size(),offset+limit)));
      }else if(op.equals("create_folder")){
        String selected=path(p,"path");DomainFolder f=folder(data,parent(selected)).createFolder(name(selected));
        if(data.getFolder(selected)==null)throw new IllegalStateException();result.put("path",f.getPathname());result.put("state","created");
      }else if(op.equals("move_file")||op.equals("move_folder")){
        String source=path(p,"path"),destination=path(p,"destination");DomainFolder to=folder(data,destination);
        if(op.equals("move_file")){DomainFile f=file(data,source);String expected=destination.equals("/")?"/"+f.getName():destination+"/"+f.getName();
          f=f.moveTo(to);if(data.getFile(source)!=null||data.getFile(expected)==null)throw new IllegalStateException();result.put("path",f.getPathname());}
        else{if(source.equals("/"))throw new IllegalArgumentException();DomainFolder f=folder(data,source);if(f.isSameOrAncestor(to))throw new IllegalArgumentException();
          String expected=destination.equals("/")?"/"+f.getName():destination+"/"+f.getName();f=f.moveTo(to);
          if(data.getFolder(source)!=null||data.getFolder(expected)==null)throw new IllegalStateException();result.put("path",f.getPathname());}
        result.put("state","moved");
      }else if(op.equals("delete_file")){
        String selected=path(p,"path");file(data,selected).delete();if(data.getFile(selected)!=null)throw new IllegalStateException();result.put("path",selected);result.put("state","deleted");
      }else if(op.equals("import")){
        String selected=path(p,"path");DomainFile imported=folder(data,parent(selected)).createFile(name(selected),Path.of(string(p,"input")).toFile(),TaskMonitor.DUMMY);
        if(!imported.getPathname().equals(selected)||data.getFile(selected)==null)throw new IllegalStateException();result.put("file",describe(imported));result.put("state","imported");
      }else if(op.equals("archive")){
        Path output=Path.of(string(p,"output"));if(Files.exists(output))throw new IllegalArgumentException("Output exists");
        ArchiveBridge.archive(project.getProject(),output.toFile(),TaskMonitor.DUMMY);
        if(!Files.isRegularFile(output)||Files.size(output)==0)throw new IllegalStateException();result.put("state","archived");result.put("size",Files.size(output));
      }else if(op.equals("delete")){project.setDeleteOnClose(true);project.close();project=null;
        if(Files.exists(root.resolve("project.gpr"))||Files.exists(root.resolve("project.rep")))throw new IllegalStateException();result.put("state","deleted");}
      else throw new IllegalArgumentException("Unknown project operation");
      if(project!=null){project.close();project=null;}
      Path journal=requestPath.getParent().resolve("result.json"),temporary=requestPath.getParent().resolve("result.new");
      String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(requestJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      Files.writeString(temporary,new Gson().toJson(Map.of("schema",1,"request",string(p,"request_id"),"hash",hash,"result",result)),StandardOpenOption.CREATE_NEW);
      try(FileChannel channel=FileChannel.open(temporary,StandardOpenOption.WRITE)){channel.force(true);}
      Files.move(temporary,journal,StandardCopyOption.ATOMIC_MOVE);
      if(!System.getProperty("os.name").toLowerCase().contains("win"))try(FileChannel channel=FileChannel.open(requestPath.getParent(),StandardOpenOption.READ)){channel.force(true);}
      out.println(new Gson().toJson(result));System.exit(0);
    }catch(Throwable failure){if(project!=null)project.close();failure.printStackTrace(System.err);out.println("{\"error\":\"project_operation_failed\"}");System.exit(1);}
  }
}
