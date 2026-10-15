import java.nio.file.*;
import java.util.zip.*;
import java.util.*;

/** Extract only the verified SDK's pure Python wheels into a fresh owned directory. */
class InsightPythonWheels {
  public static void main(String[] args)throws Exception{
    if(args.length!=4)throw new IllegalArgumentException();Path root=Path.of(args[0]).toRealPath();int count=0;long total=0;
    for(int i=1;i<args.length;i++)try(ZipFile zip=new ZipFile(args[i])){
      var entries=zip.entries();while(entries.hasMoreElements()){
        ZipEntry entry=entries.nextElement();String name=entry.getName();Path relative=Path.of(name),output=root.resolve(relative).normalize();
        if(++count>10000||relative.isAbsolute()||name.contains("\\")||Arrays.stream(name.split("/")).anyMatch(x->x.equals(".."))||!output.startsWith(root))throw new IllegalArgumentException();
        if(entry.isDirectory()){Files.createDirectories(output);continue;}
        if(entry.getSize()<0||entry.getSize()>16777216||(total+=entry.getSize())>67108864)throw new IllegalArgumentException();
        Files.createDirectories(output.getParent());try(var in=zip.getInputStream(entry);var out=Files.newOutputStream(output,StandardOpenOption.CREATE_NEW)){
          byte[] buffer=new byte[65536];long actual=0;int length;
          while((length=in.read(buffer))!=-1){actual+=length;if(actual>entry.getSize())throw new IllegalArgumentException();out.write(buffer,0,length);}
          if(actual!=entry.getSize())throw new IllegalArgumentException();
        }
      }
    }
    System.out.println("{\"state\":\"prepared\"}");
  }
}
