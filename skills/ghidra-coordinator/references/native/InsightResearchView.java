package com.eyeauras.insight;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;
import java.util.Map;

/** Precompiled, authenticated bridge read. Does not open, analyze, transact or save programs. */
public final class InsightResearchView {
  private final ProgramProvider programs;
  private final ThreadingStrategy threading;
  public InsightResearchView(ProgramProvider programs,ThreadingStrategy threading){this.programs=programs;this.threading=threading;}
  @McpTool(path="/insight/research-view/v1",method="GET",description="Read modification/language/compiler of an already open program",access=ToolAccess.READ_ONLY)
  public Response view(@Param(value="program",source=ParamSource.QUERY,allowEmpty=false) String path)throws Exception {
    if(programs==null||path==null||!path.startsWith("/")||path.length()>4096)throw new IllegalArgumentException("An explicit open program path is required");
    return threading.executeRead(()->{
      Program selected=null;
      for(Program p:programs.getAllOpenPrograms())if(p!=null&&!p.isClosed()&&p.getDomainFile()!=null&&path.equals(p.getDomainFile().getPathname())){
        if(selected!=null&&selected!=p)throw new IllegalStateException("Program path is ambiguous");selected=p;
      }
      if(selected==null)throw new IllegalArgumentException("Program is not open");
      return Response.ok(Map.of("protocol","insight-research-view-v1","modification",Long.toString(selected.getModificationNumber()),"language",selected.getLanguageID().toString(),"compiler",selected.getCompilerSpec().getCompilerSpecID().toString()));
    });
  }
}
