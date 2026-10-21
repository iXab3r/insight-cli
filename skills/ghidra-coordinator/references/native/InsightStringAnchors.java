package com.eyeauras.insight;

import com.xebyte.core.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.model.listing.Program;
import java.math.BigInteger;
import java.util.*;

/** Authenticated precompiled read of an already-open byte-addressed default space. */
public final class InsightStringAnchors {
  // Upstream Response.ok omits null map values. This protocol requires explicit nullable facts.
  private static final Gson JSON=new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
  private final ProgramProvider programs;private final ThreadingStrategy threading;
  public InsightStringAnchors(ProgramProvider programs,ThreadingStrategy threading){this.programs=programs;this.threading=threading;}
  private static BigInteger address(String value){if(value==null||!value.matches("0|[1-9a-f][a-f0-9]{0,15}"))throw new IllegalArgumentException("Expected canonical default-space address");return new BigInteger(value,16);}
  @McpTool(path="/insight/string-anchors/v1",method="GET",description="Bounded literal byte matches with separate NUL-delimited candidate context",access=ToolAccess.READ_ONLY)
  public Response anchors(@Param(value="program",source=ParamSource.QUERY,allowEmpty=false) String path,
      @Param(value="text",source=ParamSource.QUERY,allowEmpty=false) String text,
      @Param(value="encodings",source=ParamSource.QUERY,allowEmpty=false) String encodings,
      @Param(value="scan_from",source=ParamSource.QUERY,allowEmpty=false) String start,
      @Param(value="scan_through",source=ParamSource.QUERY,allowEmpty=false) String end,
      @Param(value="resume_address",source=ParamSource.QUERY,allowEmpty=false) String resume,
      @Param(value="resume_encoding",source=ParamSource.QUERY,allowEmpty=false) String encoding,
      @Param(value="max_string_bytes",source=ParamSource.QUERY,allowEmpty=false) int cap,
      @Param(value="max_bytes",source=ParamSource.QUERY,allowEmpty=false) int bytes,
      @Param(value="max_candidates",source=ParamSource.QUERY,allowEmpty=false) int candidates,
      @Param(value="timeout_seconds",source=ParamSource.QUERY,allowEmpty=false) int seconds,
      @Param(value="limit",source=ParamSource.QUERY,allowEmpty=false) int limit)throws Exception{
    var config=new InsightAnchorScan.Config(text,Arrays.asList(encodings.split(",",-1)),address(start),address(end),address(resume),encoding,cap,bytes,candidates,seconds,limit);
    return threading.executeRead(()->{
      if(programs==null||path==null||!path.startsWith("/")||path.length()>4096)throw new IllegalArgumentException("Explicit open program path required");
      Program program=null;for(Program p:programs.getAllOpenPrograms())if(p!=null&&!p.isClosed()&&p.getDomainFile()!=null&&path.equals(p.getDomainFile().getPathname())){if(program!=null&&program!=p)throw new IllegalStateException("Ambiguous program path");program=p;}
      if(program==null)throw new IllegalArgumentException("Program is not open");
      var space=program.getAddressFactory().getDefaultAddressSpace();if(space.getAddressableUnitSize()!=1)throw new IllegalArgumentException("Only byte-addressed default space is supported");
      if(config.end().bitLength()>space.getSize())throw new IllegalArgumentException("Range outside default address space");
      long modification=program.getModificationNumber();var memory=program.getMemory();List<InsightAnchorScan.Span> raw=new ArrayList<>();
      for(var block:memory.getBlocks())if(block.isInitialized()&&block.getStart().getAddressSpace().equals(space)){
        var lo=new BigInteger(Long.toUnsignedString(block.getStart().getOffset(),16),16).max(config.start());var hi=new BigInteger(Long.toUnsignedString(block.getEnd().getOffset(),16),16).min(config.end());
        if(lo.compareTo(hi)<=0)raw.add(new InsightAnchorScan.Span(lo,hi));
      }
      raw.sort(Comparator.comparing(InsightAnchorScan.Span::start));List<InsightAnchorScan.Span> spans=new ArrayList<>();
      for(var s:raw){if(!spans.isEmpty()&&s.start().equals(spans.getLast().end().add(BigInteger.ONE))){var previous=spans.removeLast();spans.add(new InsightAnchorScan.Span(previous.start(),s.end()));}else spans.add(s);}
      Map<String,Object> value=new LinkedHashMap<>(new InsightAnchorScan(config,spans,(at,out)->memory.getBytes(space.getAddress(at.longValue()),out),System::nanoTime).run());
      if(program.getModificationNumber()!=modification)throw new IllegalStateException("Program changed during string-anchor scan");
      value.put("modification",Long.toString(modification));return Response.text(JSON.toJson(value));
    });
  }
}
