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
    // Ghidra 12.1.2's LLDB adapter calls a nonexistent SBProcess.write_memory method.
    // Adapt only the newly extracted owned copy; refuse a different upstream implementation.
    Path methods=root.resolve("ghidralldb/methods.py");String source=Files.readString(methods);
    String original="    proc.write_memory(offset, data)";
    if(source.indexOf(original)<0||source.indexOf(original)!=source.lastIndexOf(original))throw new IllegalArgumentException("Unexpected pinned LLDB memory writer");
    String replacement="    error = lldb.SBError()\n    written = proc.WriteMemory(offset, data, error)\n    if error.Fail() or written != len(data):\n        raise RuntimeError(\"LLDB memory write failed: \" + error.GetCString())";
    source=source.replace(original,replacement);
    String originalStep="    if thread is not None:\n        t = find_thread_by_obj(thread)\n        t.process.SetSelectedThread(t)\n    exec_convert_errors('thread step-out')";
    if(source.indexOf(originalStep)<0||source.indexOf(originalStep)!=source.lastIndexOf(originalStep))throw new IllegalArgumentException("Unexpected pinned LLDB step-out adapter");
    source=source.replace(originalStep,"    if thread is None:\n        raise RuntimeError(\"A concrete live thread is required\")\n    t = find_thread_by_obj(thread)\n    frame = t.GetFrameAtIndex(0)\n    if not frame.IsValid():\n        raise RuntimeError(\"No live native frame\")\n    print(\"Insight step-out native frame: pc=\" + hex(frame.GetPC()))\n    error = lldb.SBError()\n    t.StepOutOfFrame(frame, error)\n    if error.Fail():\n        raise RuntimeError(error.GetCString())");
    Files.writeString(methods,source,StandardOpenOption.TRUNCATE_EXISTING);
    Path client=root.resolve("ghidratrace/client.py");String clientSource=Files.readString(client),call="        name = request.name\n        if not name in self._method_registry._methods:";
    if(clientSource.indexOf(call)<0||clientSource.indexOf(call)!=clientSource.lastIndexOf(call))throw new IllegalArgumentException("Unexpected pinned TraceRmi method dispatcher");
    String logPath="__import__('base64').b64decode('"+Base64.getEncoder().encodeToString(root.resolve("rpc-methods.log").toString().getBytes(java.nio.charset.StandardCharsets.UTF_8))+"').decode('utf-8')";
    clientSource=clientSource.replace(call,"        name = request.name\n        import os as _insight_os\n        _insight_fd = _insight_os.open("+logPath+", _insight_os.O_CREAT | _insight_os.O_APPEND | _insight_os.O_WRONLY, 0o600)\n        try:\n            if _insight_os.fstat(_insight_fd).st_size < 65536:\n                _insight_os.write(_insight_fd, (name[:128] + '\\n').encode('utf-8'))\n        finally:\n            _insight_os.close(_insight_fd)\n        if not name in self._method_registry._methods:");
    Files.writeString(client,clientSource,StandardOpenOption.TRUNCATE_EXISTING);
    System.out.println("{\"state\":\"prepared\",\"lldb_memory_adapter\":\"insight-sbprocess-v1\",\"lldb_step_adapter\":\"insight-explicit-native-frame-v2\"}");
  }
}
