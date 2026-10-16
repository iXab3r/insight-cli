package ownedp3;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
public class OwnedP3Analyzer extends AbstractAnalyzer {
 public OwnedP3Analyzer(){super("OwnedP3 marker","Disposable acceptance marker",AnalyzerType.BYTE_ANALYZER);setDefaultEnablement(false);}
 public boolean canAnalyze(Program program){return true;}
 public boolean added(Program program,AddressSetView set,TaskMonitor monitor,MessageLog log){for(var f:program.getFunctionManager().getFunctions(true))if(f.getName().equals("first"))program.getListing().setComment(f.getEntryPoint(),CommentType.PRE,"OwnedP3 analyzer ran");return true;}
}
