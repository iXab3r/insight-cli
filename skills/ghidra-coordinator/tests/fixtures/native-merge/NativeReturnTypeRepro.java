import com.google.gson.Gson;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.merge.MergeConstants;
import ghidra.util.task.TaskMonitor;
import insight.prototype.HeadlessProgramMergeManager;
import java.nio.file.*;
import java.util.*;

/** One native function and two independent first-time builtin types. No server or CLI. */
public class NativeReturnTypeRepro {
    static final Object OWNER=new Object();
    static final TaskMonitor MONITOR=TaskMonitor.DUMMY;
    static Address entry(Program p){return p.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);}
    static Function function(Program p){return p.getFunctionManager().getFunctionAt(entry(p));}
    static ProgramDB copy(ProgramDB source,Path path)throws Exception{
        source.getDBHandle().saveAs(path.toFile(),false,MONITOR);
        return new ProgramDB(new DBHandle(path.toFile()),OpenMode.UPDATE,MONITOR,OWNER);
    }
    static Map<String,Object> inspect(ProgramDB p){
        var dtm=p.getDataTypeManager();var f=function(p);var type=f.getReturnType();
        return Map.of("returnType",type.getName(),"typeId",dtm.getID(type),
            "storage",f.getReturn().getVariableStorage().toString(),
            "addedTypes",Arrays.stream(p.getChanges().getDataTypeAdditions()).mapToObj(id->Map.of("id",id,"name",dtm.getDataType(id).getName())).toList(),
            "changedTypes",p.getChanges().getDataTypeChanges());
    }
    static void edit(ProgramDB p,DataType type)throws Exception{
        int tx=p.startTransaction("Only change the native return type");
        try{function(p).setReturnType(type,SourceType.USER_DEFINED);}finally{p.endTransaction(tx,true);}
    }
    public static void main(String[] args)throws Exception{
        var output=System.out;System.setOut(System.err);
        Path root=Path.of(args[0]).toRealPath();
        if(!Files.isRegularFile(root.resolve("owner.json")))throw new IllegalArgumentException("Owned fixture required");
        Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
        var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        List<ProgramDB> programs=new ArrayList<>();
        Map<String,Object> result=new LinkedHashMap<>();
        try{
            ProgramDB baseline=new ProgramDB("one_function",language,language.getDefaultCompilerSpec(),OWNER);programs.add(baseline);
            int tx=baseline.startTransaction("One-function baseline");
            try{
                baseline.getMemory().createInitializedBlock("text",entry(baseline),16,(byte)0xc3,MONITOR,false).setExecute(true);
                baseline.getFunctionManager().createFunction("subject",entry(baseline),new AddressSet(entry(baseline),entry(baseline).add(15)),SourceType.USER_DEFINED);
                function(baseline).setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED);
            }finally{baseline.endTransaction(tx,true);}
            ProgramDB original=copy(baseline,root.resolve("original.db"));programs.add(original);
            result.put("builtinsAbsentFromBaseline",original.getDataTypeManager().getDataType("/float")==null&&original.getDataTypeManager().getDataType("/double")==null);
            ProgramDB latest=copy(original,root.resolve("latest.db"));programs.add(latest);
            ProgramDB mine=copy(original,root.resolve("mine.db"));programs.add(mine);
            edit(latest,FloatDataType.dataType);edit(mine,DoubleDataType.dataType);
            ProgramDB merged=copy(latest,root.resolve("result.db"));programs.add(merged);
            result.put("original",inspect(original));result.put("latest",inspect(latest));result.put("mine",inspect(mine));
            var manager=new HeadlessProgramMergeManager(merged,mine,original,latest,latest.getChanges(),mine.getChanges());
            try{result.put("completed",manager.merge(MONITOR));}
            catch(HeadlessProgramMergeManager.UnresolvedNativeConflict conflict){result.put("conflict",conflict.toString());}
            for(String key:List.of(MergeConstants.RESOLVED_MY_DTS,MergeConstants.RESOLVED_LATEST_DTS)){
                Map<?,?> map=(Map<?,?>)manager.getResolveInformation(key);
                Map<String,String> entries=new LinkedHashMap<>();if(map!=null)map.forEach((id,type)->entries.put(id.toString(),((DataType)type).getName()));
                result.put(key,entries);
            }
            result.put("result",inspect(merged));result.put("mineAfter",inspect(mine));result.put("latestAfter",inspect(latest));
            result.put("guiWindows",java.awt.Window.getWindows().length);
            output.println(new Gson().toJson(result));
        }finally{Collections.reverse(programs);for(var p:programs)p.release(OWNER);}
    }
}
