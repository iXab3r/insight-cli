package com.eyeauras.insight;

import com.xebyte.core.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.model.listing.Program;
import java.math.BigInteger;
import java.util.*;

/** Authenticated bounded runtime-region evidence for explicitly selected open programs. */
public final class InsightFunctionBoundaries {
  private static final Gson JSON=new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
  private final ProgramProvider programs;private final ThreadingStrategy threading;
  public InsightFunctionBoundaries(ProgramProvider programs,ThreadingStrategy threading){this.programs=programs;this.threading=threading;}
  @McpTool(path="/insight/function-boundaries/v1",method="GET",description="Compare recorded function membership with current mapped PE32+ AMD64 runtime regions; no semantic reconstruction",access=ToolAccess.READ_ONLY)
  public Response boundaries(@Param(value="program",source=ParamSource.QUERY,allowEmpty=false) String path,
      @Param(value="addresses",source=ParamSource.QUERY,allowEmpty=false) String addresses,
      @Param(value="max_unwind_bytes",source=ParamSource.QUERY,allowEmpty=false) int maximum)throws Exception {
    if(maximum<1||maximum>16777216||addresses==null||addresses.length()>339)throw new IllegalArgumentException("Expected 1–20 addresses and byte budget 1–16777216");
    String[] words=addresses.split(",",-1);if(words.length<1||words.length>20)throw new IllegalArgumentException("Expected 1–20 addresses");
    Set<String> unique=new HashSet<>();for(String word:words)if(!word.matches("0|[1-9a-f][a-f0-9]{0,15}")||!unique.add(word))throw new IllegalArgumentException("Expected distinct canonical addresses");
    return threading.executeRead(()->{
      if(programs==null||path==null||!path.startsWith("/")||path.length()>4096)throw new IllegalArgumentException("Explicit open program path required");
      Program program=null;for(Program p:programs.getAllOpenPrograms())if(p!=null&&!p.isClosed()&&p.getDomainFile()!=null&&path.equals(p.getDomainFile().getPathname())){if(program!=null&&program!=p)throw new IllegalStateException("Ambiguous program path");program=p;}
      if(program==null)throw new IllegalArgumentException("Program is not open");
      var space=program.getAddressFactory().getDefaultAddressSpace();var memory=program.getMemory();var functions=program.getFunctionManager();long modification=program.getModificationNumber();
      long lookupStarted=System.nanoTime();List<InsightPeRanges.Span> spans=new ArrayList<>();
      for(var block:memory.getBlocks())if(block.isInitialized()&&block.getStart().getAddressSpace().equals(space))spans.add(new InsightPeRanges.Span(new BigInteger(Long.toUnsignedString(block.getStart().getOffset(),16),16),new BigInteger(Long.toUnsignedString(block.getEnd().getOffset(),16),16).add(BigInteger.ONE),block.isExecute()));
      InsightPeRanges.Result scan;
      if(space.getSize()!=64||space.getAddressableUnitSize()!=1||!program.getLanguageID().toString().equals("x86:LE:64:default"))scan=new InsightPeRanges.Result(Map.of("state","unavailable","complete",false,"reason","unsupported_language","headersSource","current-mapped-memory","recordCount",0,"recordsValidated",0,"bytesRead",0,"maximumBytes",maximum,"deadlineMilliseconds",5000),List.of());
      else scan=new InsightPeRanges(new BigInteger(Long.toUnsignedString(program.getImageBase().getOffset(),16),16),spans,(at,out)->memory.getBytes(space.getAddress(at.longValue()),out),maximum,System::nanoTime,Arrays.stream(words).map(w->new BigInteger(w,16)).toList(),lookupStarted).run();
      Map<String,Object> items=new LinkedHashMap<>();boolean complete=Boolean.TRUE.equals(scan.lookup().get("complete"));
      for(String word:words){
        BigInteger query=new BigInteger(word,16);Map<String,Object> row=new LinkedHashMap<>();Map<String,Object> database=null;
        if(query.bitLength()<=space.getSize()){
          var at=space.getAddress(query.longValue());var f=functions.getFunctionAt(at);String kind="exact-entry";if(f==null){f=functions.getFunctionContaining(at);kind="recorded-containing";}
          if(f!=null)database=Map.of("entryPoint",Long.toUnsignedString(f.getEntryPoint().getOffset(),16),"kind",kind,"recordedBodyContainsAddress",f.getBody().contains(at));
        }
        row.put("database",database);InsightPeRanges.Range range=null;
        for(var candidate:scan.ranges())if(query.compareTo(candidate.begin())>=0&&query.compareTo(candidate.endExclusive())<0){range=candidate;break;}
        row.put("boundary",range==null?null:range.facts());row.put("status","unresolved");
        if(!complete)row.put("reason","boundary_lookup_"+scan.lookup().get("state"));
        else if(range!=null&&database!=null&&!database.get("entryPoint").equals(range.begin().toString(16)))row.put("reason","boundary_conflict");
        else if(range!=null){
          String entry=range.begin().toString(16);
          if(functions.getFunctionAt(space.getAddress(range.begin().longValue()))==null)row.put("reason","runtime_entry_not_defined");
          else{row.put("status","resolved");row.put("entryPoint",entry);row.put("kind","pe-runtime-range");row.put("recordedBodyContainsAddress",database!=null&&Boolean.TRUE.equals(database.get("recordedBodyContainsAddress")));}
        }else if(database!=null){row.put("status","resolved");row.put("entryPoint",database.get("entryPoint"));row.put("kind",database.get("kind"));row.put("recordedBodyContainsAddress",database.get("recordedBodyContainsAddress"));}
        else row.put("reason","no_runtime_range_or_recorded_function");
        items.put(word,row);
      }
      if(modification!=program.getModificationNumber())throw new IllegalStateException("Program changed during function-boundary lookup");
      return Response.text(JSON.toJson(Map.of("protocol","insight-function-boundaries-v1","modification",Long.toString(modification),"boundaryLookup",scan.lookup(),"items",items)));
    });
  }
}
