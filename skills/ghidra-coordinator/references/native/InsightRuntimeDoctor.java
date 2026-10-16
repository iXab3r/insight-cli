import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.decompiler.DecompInterface;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;

/** Disposable native probe: decode and decompile a known function using the selected installation. */
class InsightRuntimeDoctor {
 public static void main(String[] args) {
  var out=System.out;System.setOut(System.err);
  try {
   Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
   var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
   var program=new ProgramDB("runtime-probe",language,language.getDefaultCompilerSpec(),new Object());
   var consumer=new Object();program.addConsumer(consumer);
   int tx=program.startTransaction("probe");
   var start=program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
   program.getMemory().createInitializedBlock(".text",start,new ByteArrayInputStream(new byte[]{(byte)0xb8,42,0,0,0,(byte)0xc3}),6,TaskMonitor.DUMMY,false);
   var api=new FlatProgramAPI(program);api.disassemble(start);var function=api.createFunction(start,"runtime_probe");
   program.endTransaction(tx,true);
   var decompiler=new DecompInterface();
   if(!decompiler.openProgram(program))throw new IllegalStateException("Decompiler did not open program");
   var result=decompiler.decompileFunction(function,30,TaskMonitor.DUMMY);
   if(!result.decompileCompleted()||result.getDecompiledFunction()==null||!result.getDecompiledFunction().getC().contains("0x2a"))throw new IllegalStateException("Native decompile did not produce the expected return value");
   decompiler.dispose();program.release(consumer);
   out.println("{\"state\":\"ready\",\"headless\":true,\"decompiler\":true,\"expectedReturn\":42}");System.exit(0);
  } catch(Throwable failure){failure.printStackTrace(System.err);out.println("{\"state\":\"failed\"}");System.exit(1);}
 }
}
