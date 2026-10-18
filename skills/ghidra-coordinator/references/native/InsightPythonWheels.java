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
    String step = """
        if thread is None:
            raise RuntimeError("A concrete live thread is required")
        import json, os, uuid
        t = find_thread_by_obj(thread)
        proc = t.GetProcess()
        if proc.GetState() != lldb.eStateStopped:
            raise RuntimeError("Native target is not stopped")
        frames = util.insight_frames(t)
        caller = frames[1] if len(frames) > 1 else lldb.SBFrame()
        if not caller.IsValid():
            raise RuntimeError("No native caller frame")
        return_pc, return_sp = caller.GetPC(), caller.GetSP()
        if return_pc in (0, lldb.LLDB_INVALID_ADDRESS) or return_sp in (0, lldb.LLDB_INVALID_ADDRESS):
            raise RuntimeError("Native caller location is unavailable")
        root = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(root, "caller-goal.json")
        if os.path.exists(path):
            with open(path) as source: prior = json.load(source)
            observed_path = os.path.join(root, "caller-observation.json")
            observed = {}
            if os.path.exists(observed_path):
                with open(observed_path) as source: observed = json.load(source)
            if prior.get("pid") == proc.GetProcessID() and (observed.get("goal") != prior.get("id") or observed.get("state") != "verified"):
                raise RuntimeError("An unverified caller intent is retained; close and reopen the context")
        target = proc.GetTarget()
        with commands.INSIGHT_BREAKPOINT_LOCK:
            breakpoint = target.BreakpointCreateByAddress(return_pc)
            commands.INSIGHT_TRANSIENT_BREAKPOINTS.add(breakpoint.GetID())
        try:
            if not breakpoint.IsValid():
                raise RuntimeError("Cannot establish caller breakpoint")
            breakpoint.SetThreadID(t.GetThreadID())
            breakpoint.SetCondition("$sp == " + hex(return_sp))
            breakpoint.SetOneShot(True)
            if breakpoint.GetNumLocations() != 1:
                raise RuntimeError("Caller breakpoint location is ambiguous")
            goal = dict(schema=1, id=str(uuid.uuid4()), pid=proc.GetProcessID(), thread=str(t.GetThreadID()), pc=hex(return_pc), sp=hex(return_sp), stop=proc.GetStopID(), executable=target.GetExecutable().fullpath, breakpoint=breakpoint.GetID())
            temporary = path + ".new-" + goal["id"]
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, json.dumps(goal).encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, path)
            error = proc.Continue()
            if error.Fail():
                raise RuntimeError(error.GetCString())
        except Exception:
            target.BreakpointDelete(breakpoint.GetID())
            raise
    """;
    boolean ownedCaller=System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("mac");
    if(ownedCaller)source=source.replace(originalStep,step.stripTrailing());
    Files.writeString(methods,source,StandardOpenOption.TRUNCATE_EXISTING);
    Path client=root.resolve("ghidratrace/client.py");String clientSource=Files.readString(client),call="        name = request.name\n        if not name in self._method_registry._methods:";
    if(clientSource.indexOf(call)<0||clientSource.indexOf(call)!=clientSource.lastIndexOf(call))throw new IllegalArgumentException("Unexpected pinned TraceRmi method dispatcher");
    String logPath="__import__('base64').b64decode('"+Base64.getEncoder().encodeToString(root.resolve("rpc-methods.log").toString().getBytes(java.nio.charset.StandardCharsets.UTF_8))+"').decode('utf-8')";
    clientSource=clientSource.replace(call,"        name = request.name\n        import os as _insight_os\n        _insight_fd = _insight_os.open("+logPath+", _insight_os.O_CREAT | _insight_os.O_APPEND | _insight_os.O_WRONLY, 0o600)\n        try:\n            if _insight_os.fstat(_insight_fd).st_size < 65536:\n                _insight_os.write(_insight_fd, (name[:128] + '\\n').encode('utf-8'))\n        finally:\n            _insight_os.close(_insight_fd)\n        if not name in self._method_registry._methods:");
    Path commands=root.resolve("ghidralldb/commands.py");String commandSource=Files.readString(commands);
    int frameStart=commandSource.indexOf("def put_frames() -> None:"),frameEnd=commandSource.indexOf("@convert_errors\ndef ghidra_trace_put_frames",frameStart);
    if(frameStart<0||frameEnd<frameStart)throw new IllegalArgumentException("Unexpected pinned LLDB frame exporter");
    String frameBlock=commandSource.substring(frameStart,frameEnd),frameIndex="level=f.GetFrameID()";
    int first=frameBlock.indexOf(frameIndex),second=frameBlock.indexOf(frameIndex,first+frameIndex.length());
    if(first<0||second<0||frameBlock.indexOf(frameIndex,second+frameIndex.length())>=0)throw new IllegalArgumentException("Unexpected pinned LLDB frame identity");
    if(ownedCaller){
      if(!frameBlock.contains("mapper.map(proc, f.GetPC())")||!frameBlock.contains("str(f.GetFunctionName())")||!frameBlock.contains("util.get_description(f)"))throw new IllegalArgumentException("Unexpected pinned LLDB frame coordinates");
      frameBlock=frameBlock.replace("for i in range(0, t.GetNumFrames()):", "frames = util.insight_frames(t)\n    for i in range(len(frames)):").replace("f = t.GetFrameAtIndex(i)", "f = frames[i]").replace("mapper.map(proc, f.GetPC())","mapper.map(proc, util.insight_frame_pc(f))").replace("str(f.GetFunctionName())","util.insight_frame_function(f)").replace("util.get_description(f)","util.insight_frame_description(f)");
    }
    commandSource=commandSource.substring(0,frameStart)+frameBlock.replace(frameIndex,"level=i")+commandSource.substring(frameEnd);
    String single="def put_single_breakpoint(b: lldb.SBBreakpoint, proc: lldb.SBProcess) -> None:\n";
    String list="        b = target.GetBreakpointAtIndex(i)\n        keys.append(BREAKPOINT_KEY_PATTERN.format(breaknum=b.GetID()))";
    if(commandSource.indexOf(single)<0||commandSource.indexOf(single)!=commandSource.lastIndexOf(single)||commandSource.indexOf(list)<0||commandSource.indexOf(list)!=commandSource.lastIndexOf(list))throw new IllegalArgumentException("Unexpected pinned LLDB breakpoint exporter");
    commandSource=commandSource.replace(single,"import threading as _insight_threading\nINSIGHT_BREAKPOINT_LOCK = _insight_threading.RLock()\nINSIGHT_TRANSIENT_BREAKPOINTS = set()\n\n"+single+"    with INSIGHT_BREAKPOINT_LOCK:\n        if b.GetID() in INSIGHT_TRANSIENT_BREAKPOINTS:\n            return\n");
    commandSource=commandSource.replace(list,"        b = target.GetBreakpointAtIndex(i)\n        with INSIGHT_BREAKPOINT_LOCK:\n            if b.GetID() in INSIGHT_TRANSIENT_BREAKPOINTS:\n                continue\n        keys.append(BREAKPOINT_KEY_PATTERN.format(breaknum=b.GetID()))");
    String registerFrame="frame.GetFrameID()";
    if(commandSource.split(java.util.regex.Pattern.quote(registerFrame),-1).length!=5)throw new IllegalArgumentException("Unexpected pinned LLDB frame register paths");
    commandSource=commandSource.replace(registerFrame,"util.insight_frame_level(frame)");
    String dynamicRegister="bank.GetChildAtIndex(i, lldb.eDynamicCanRunTarget, True)";
    if(commandSource.split(java.util.regex.Pattern.quote(dynamicRegister),-1).length!=3)throw new IllegalArgumentException("Unexpected pinned LLDB register reader");
    commandSource=commandSource.replace(dynamicRegister,"bank.GetChildAtIndex(i, lldb.eDynamicDontRunTarget, True)");
    Path util=root.resolve("ghidralldb/util.py");String utilSource=Files.readString(util);
    String evaluation="def parse_and_eval(expr: str, signed: bool = False) -> int:\n    if signed is True:\n        return get_eval(expr).GetValueAsSigned()\n    return get_eval(expr).GetValueAsUnsigned()";
    String readOnlyEvaluation="""
    def parse_and_eval(expr: str, signed: bool = False) -> int:
        if not signed and re.fullmatch(r'0[xX][0-9a-fA-F]+|0|[1-9][0-9]*', expr):
            return int(expr, 16 if expr.lower().startswith('0x') else 10)
        register = re.fullmatch(r'[$](pc|sp)([+-](?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*))?', expr)
        if register:
            frame = selected_frame()
            value = frame.FindRegister(register.group(1))
            if not frame.IsValid() or not value.IsValid() or value.GetError().Fail():
                raise ValueError('Stopped native register is unavailable')
            offset = register.group(2) or '0'
            displacement = int(offset, 16 if 'x' in offset.lower() else 10)
            bits = get_target().GetAddressByteSize() * 8
            number = (value.GetValueAsUnsigned() + displacement) & ((1 << bits) - 1)
            return number - (1 << bits) if signed and number >= (1 << (bits - 1)) else number
        if signed is True:
            return get_eval(expr).GetValueAsSigned()
        return get_eval(expr).GetValueAsUnsigned()
    """;
    if(utilSource.indexOf(evaluation)<0||utilSource.indexOf(evaluation)!=utilSource.lastIndexOf(evaluation))throw new IllegalArgumentException("Unexpected pinned LLDB address evaluator");
    utilSource=utilSource.replace(evaluation,readOnlyEvaluation.stripTrailing());
    utilSource+="\n\nINSIGHT_NORMALIZE_PHYSICAL_STACK = "+(ownedCaller?"True":"False")+"\n";
    utilSource+="""

    def insight_frames(thread):
        frames = [thread.GetFrameAtIndex(i) for i in range(thread.GetNumFrames())]
        if not INSIGHT_NORMALIZE_PHYSICAL_STACK or not frames:
            return frames
        head = frames[0]
        pc, sp = head.FindRegister('pc'), head.FindRegister('sp')
        if not pc.IsValid() or not sp.IsValid() or pc.GetError().Fail() or sp.GetError().Fail():
            return frames
        live_pc, live_sp = pc.GetValueAsUnsigned(), sp.GetValueAsUnsigned()
        for index in range(1, min(len(frames), 16)):
            previous, candidate = frames[index - 1], frames[index]
            if previous.IsInlined() or previous.IsArtificial() or previous.GetSP() != live_sp or previous.GetCFA() != live_sp:
                break
            if candidate.GetPC() == live_pc and candidate.GetSP() == live_sp and not candidate.IsInlined() and not candidate.IsArtificial():
                return frames[index:]
        return frames

    def insight_frame_native_index(frame):
        thread = frame.GetThread()
        for index in range(thread.GetNumFrames()):
            if thread.GetFrameAtIndex(index).GetFrameID() == frame.GetFrameID():
                return index
        raise RuntimeError('Native frame is no longer present')

    def insight_frame_for_level(thread, level):
        return thread.GetFrameAtIndex(0) if level == 0 else insight_frames(thread)[level]

    def insight_frame_level(frame):
        thread = frame.GetThread()
        for index, candidate in enumerate(insight_frames(thread)):
            if candidate.GetFrameID() == frame.GetFrameID():
                return index
        frames = insight_frames(thread)
        if frames and insight_frame_native_index(frame) < insight_frame_native_index(frames[0]):
            return 0
        raise RuntimeError('Native frame is no longer in the current stack')
    """;
    utilSource+="""

    def insight_frame_pc(frame):
        if insight_frame_level(frame) != 0 or frame.IsInlined() or frame.IsArtificial():
            return frame.GetPC()
        value = frame.FindRegister('pc')
        if not value.IsValid() or value.GetError().Fail():
            raise RuntimeError('Native frame PC register is unavailable')
        return value.GetValueAsUnsigned()

    def insight_frame_function(frame):
        target = frame.GetThread().GetProcess().GetTarget()
        address = target.ResolveLoadAddress(insight_frame_pc(frame))
        function, symbol = address.GetFunction(), address.GetSymbol()
        return str(function.GetName() if function.IsValid() else symbol.GetName() if symbol.IsValid() else '<unknown>')

    def insight_frame_description(frame):
        return '#%d: %s %s' % (insight_frame_level(frame), hex(insight_frame_pc(frame)), insight_frame_function(frame))

    def insight_thread_description(thread):
        if thread.GetProcess().GetState() != lldb.eStateStopped:
            return get_description(thread)
        frames = insight_frames(thread)
        if not frames:
            return get_description(thread)
        frame = frames[0]
        return 'thread #%d: tid = %s, %s %s, stop reason = %s' % (thread.GetIndexID(), hex(thread.GetThreadID()), hex(insight_frame_pc(frame)), insight_frame_function(frame), thread.GetStopDescription(512))
    """;
    Files.writeString(util,utilSource,StandardOpenOption.TRUNCATE_EXISTING);
    String selectFrame="f.thread.SetSelectedFrame(f.GetFrameID())";
    if(source.split(java.util.regex.Pattern.quote(selectFrame),-1).length!=3)throw new IllegalArgumentException("Unexpected pinned LLDB frame selector");
    source=source.replace(selectFrame,"f.thread.SetSelectedFrame(util.insight_frame_native_index(f))");
    if(ownedCaller){
      String lookup="    return thread.GetFrameAtIndex(level)";
      if(source.indexOf(lookup)<0||source.indexOf(lookup)!=source.lastIndexOf(lookup))throw new IllegalArgumentException("Unexpected pinned LLDB frame lookup");
      source=source.replace(lookup,"    return util.insight_frame_for_level(thread, level)");
      String display="def compute_thread_display(t: lldb.SBThread) -> str:\n    return util.get_description(t)";
      if(commandSource.indexOf(display)<0||commandSource.indexOf(display)!=commandSource.lastIndexOf(display))throw new IllegalArgumentException("Unexpected pinned LLDB thread display");
      commandSource=commandSource.replace(display,"def compute_thread_display(t: lldb.SBThread) -> str:\n    return util.insight_thread_description(t)");
    }
    Files.writeString(methods,source,StandardOpenOption.TRUNCATE_EXISTING);
    Files.writeString(commands,commandSource,StandardOpenOption.TRUNCATE_EXISTING);
    Files.writeString(client,clientSource,StandardOpenOption.TRUNCATE_EXISTING);
    Path architecture=root.resolve("ghidralldb/arch.py");String architectureSource=Files.readString(architecture);
    String registerAliases="""

    class InsightAarch64RegisterMapper(DefaultRegisterMapper):
        def map_name(self, proc, name):
            return {'fp': 'x29', 'lr': 'x30'}.get(name, super().map_name(proc, name))

        def map_name_back(self, proc, name):
            return {'x29': 'fp', 'x30': 'lr'}.get(name, super().map_name_back(proc, name))
    """;
    String mapper="def compute_register_mapper(lang: str) -> DefaultRegisterMapper:\n";
    if(architectureSource.indexOf(mapper)<0||architectureSource.indexOf(mapper)!=architectureSource.lastIndexOf(mapper))throw new IllegalArgumentException("Unexpected pinned LLDB register mapper");
    architectureSource=architectureSource.replace(mapper,mapper+"    if lang.startswith('AARCH64:'):\n        return InsightAarch64RegisterMapper('big' if ':BE:' in lang else 'little')\n")+registerAliases;
    Files.writeString(architecture,architectureSource,StandardOpenOption.TRUNCATE_EXISTING);
    System.out.println("{\"state\":\"prepared\",\"lldb_memory_adapter\":\"insight-sbprocess-v1\",\"lldb_step_adapter\":\"insight-caller-dispatch-v2\"}");
  }
}
