package com.eyeauras.insight;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/** Precompiled, authenticated bridge read. Does not open, analyze, transact or save programs. */
public final class InsightResearchView {
  private final ProgramProvider programs;
  private final ThreadingStrategy threading;
  public InsightResearchView(ProgramProvider programs,ThreadingStrategy threading){this.programs=programs;this.threading=threading;}
  private Program openProgram(String path){
    if(programs==null||path==null||!path.startsWith("/")||path.length()>4096)throw new IllegalArgumentException("An explicit open program path is required");
    Program selected=null;
    for(Program p:programs.getAllOpenPrograms())if(p!=null&&!p.isClosed()&&p.getDomainFile()!=null&&path.equals(p.getDomainFile().getPathname())){
      if(selected!=null&&selected!=p)throw new IllegalStateException("Program path is ambiguous");selected=p;
    }
    if(selected==null)throw new IllegalArgumentException("Program is not open");return selected;
  }
  @McpTool(path="/insight/research-view/v1",method="GET",description="Read modification/language/compiler of an already open program",access=ToolAccess.READ_ONLY)
  public Response view(@Param(value="program",source=ParamSource.QUERY,allowEmpty=false) String path)throws Exception {
    return threading.executeRead(()->{
      Program selected=openProgram(path);
      return Response.ok(Map.of("protocol","insight-research-view-v1","modification",Long.toString(selected.getModificationNumber()),"language",selected.getLanguageID().toString(),"compiler",selected.getCompilerSpec().getCompilerSpecID().toString()));
    });
  }
  private static Map<String,Object> miss(String reason){return Map.of("status","not_found","reason",reason);}
  private static Map<String,Object> resolved(Function function,Address at,String kind){
    Map<String,Object> row=new LinkedHashMap<>();row.put("status","resolved");row.put("entryPoint",Long.toUnsignedString(function.getEntryPoint().getOffset(),16));
    row.put("kind",kind);row.put("recordedBodyContainsAddress",function.getBody().contains(at));
    if(!kind.equals("recorded-containing"))row.put("distanceBytes",at.subtract(function.getEntryPoint()));return row;
  }
  @McpTool(path="/insight/function-entries/v1",method="GET",description="Resolve up to 20 addresses using recorded bodies or a bounded preceding-entry candidate; no inferred membership",access=ToolAccess.READ_ONLY)
  public Response entries(@Param(value="program",source=ParamSource.QUERY,allowEmpty=false) String path,
      @Param(value="addresses",source=ParamSource.QUERY,allowEmpty=false) String addresses,
      @Param(value="max_entry_distance",source=ParamSource.QUERY,allowEmpty=false) int maximum)throws Exception {
    if(maximum<1||maximum>65536||addresses==null||addresses.length()>339)throw new IllegalArgumentException("Expected 1–20 addresses and a distance of 1–65536 bytes");
    String[] words=addresses.split(",",-1);if(words.length<1||words.length>20)throw new IllegalArgumentException("Expected 1–20 addresses");
    for(String word:words)if(!word.matches("[a-f0-9]{1,16}"))throw new IllegalArgumentException("Expected canonical default-space hexadecimal addresses");
    return threading.executeRead(()->{
      Program program=openProgram(path);long modification=program.getModificationNumber();var functions=program.getFunctionManager();
      var space=program.getAddressFactory().getDefaultAddressSpace();var memory=program.getMemory();Map<String,Object> items=new LinkedHashMap<>();
      for(String word:words){
        if(items.containsKey(word)||!new BigInteger(word,16).toString(16).equals(word))throw new IllegalArgumentException("Expected distinct canonical addresses");
        if(new BigInteger(word,16).bitLength()>space.getSize()){items.put(word,miss("address_out_of_range"));continue;}
        Address at=space.getAddress(Long.parseUnsignedLong(word,16));
        Function function=functions.getFunctionAt(at);
        if(function!=null){items.put(word,resolved(function,at,"exact-entry"));continue;}
        function=functions.getFunctionContaining(at);
        if(function!=null){items.put(word,resolved(function,at,"recorded-containing"));continue;}
        var block=memory.getBlock(at);
        if(block==null||!block.isInitialized()||!block.isExecute()){items.put(word,miss("address_not_in_initialized_executable_block"));continue;}
        // Address-seeded indexed iterator; consume at most one previous entry, never a full-table scan.
        var previous=functions.getFunctions(at,false);
        if(!previous.hasNext()){items.put(word,miss("no_preceding_entry"));continue;}
        function=previous.next();Address entry=function.getEntryPoint();
        if(!entry.getAddressSpace().equals(space)||entry.compareTo(at)>=0||!block.contains(entry)){items.put(word,miss("entry_outside_block"));continue;}
        if(new BigInteger(word,16).subtract(new BigInteger(Long.toUnsignedString(entry.getOffset(),16),16)).compareTo(BigInteger.valueOf(maximum))>0){items.put(word,miss("entry_distance_exceeded"));continue;}
        items.put(word,resolved(function,at,"preceding-entry-candidate"));
      }
      if(modification!=program.getModificationNumber())throw new IllegalStateException("Program changed during function-entry lookup");
      return Response.ok(Map.of("protocol","insight-function-entries-v1","modification",Long.toString(modification),"items",items));
    });
  }
}
