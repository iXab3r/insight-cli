import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public class LongBudgetAnalyzer extends AbstractAnalyzer {
 public LongBudgetAnalyzer(){super("LongBudgetFixture","Controlled long import fixture",AnalyzerType.BYTE_ANALYZER);setDefaultEnablement(true);setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());setSupportsOneTimeAnalysis();}
 public boolean canAnalyze(Program p){return true;}
 public boolean added(Program p,AddressSetView s,TaskMonitor monitor,MessageLog log){
  if(p.getOptions("LongBudgetFixture").getBoolean("completed",false))return true;
  System.err.println("LONG_BUDGET_ANALYSIS_STARTED");
  try{Thread.sleep(610000);}catch(InterruptedException e){throw new RuntimeException(e);}
  p.getOptions("LongBudgetFixture").setBoolean("completed",true);
  System.err.println("LONG_BUDGET_ANALYSIS_COMPLETED");return true;
 }
}


