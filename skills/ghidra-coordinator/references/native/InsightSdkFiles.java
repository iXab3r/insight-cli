import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.util.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.exporter.*;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.*;
import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;

/** File-oriented SDK work runs on immutable snapshots in a retained owned call directory. */
class InsightSdkFiles {
    static String text(JsonObject p,String key){return p.has(key)&&!p.get(key).isJsonNull()?p.get(key).getAsString():"";}
    static Object scalar(Object value){return value instanceof HexLong||value instanceof Long?value.toString():value==null?null:value instanceof Number||value instanceof Boolean||value instanceof String?value:value.toString();}
    static List<Object> options(List<Option> values){List<Object> rows=new ArrayList<>();for(Option value:values){Map<String,Object> row=new LinkedHashMap<>();row.put("name",value.getName());row.put("type",value.getValueClass().getSimpleName());row.put("default",scalar(value.getValue()));rows.add(row);}return rows;}
    static List<Option> configured(List<Option> values,JsonObject p,AddressFactory factory){
        Set<String> known=new HashSet<>();for(Option option:values){known.add(option.getName());if(!p.has(option.getName()))continue;JsonElement input=p.get(option.getName());Class<?> type=option.getValueClass();Object value;
            if(!input.isJsonPrimitive())throw new IllegalArgumentException("Native options require typed primitive values");
            var primitive=input.getAsJsonPrimitive();
            if(type==String.class){if(!primitive.isString())throw new IllegalArgumentException("Native text option requires a string");value=input.getAsString();}
            else if(type==Boolean.class||type==boolean.class){if(!primitive.isBoolean())throw new IllegalArgumentException("Native Boolean option requires a Boolean");value=input.getAsBoolean();}
            else if(type==Integer.class||type==int.class){if(!primitive.isNumber())throw new IllegalArgumentException("Native integer option requires a number");value=input.getAsBigDecimal().intValueExact();}
            else if(type==Long.class||type==long.class){if(!primitive.isNumber())throw new IllegalArgumentException("Native long option requires a number");value=input.getAsBigDecimal().longValueExact();}
            else if(type==HexLong.class){String encoded=input.getAsString();value=new HexLong(encoded.startsWith("0x")?Long.parseUnsignedLong(encoded.substring(2),16):Long.parseLong(encoded));}
            else if(type==Address.class&&factory!=null){value=factory.getAddress(input.getAsString());if(value==null)throw new IllegalArgumentException("Invalid loader/exporter address option");}
            else throw new IllegalArgumentException("Option value class is not supported by the typed file contract");option.setValue(value);}
        if(!known.containsAll(p.keySet()))throw new IllegalArgumentException("Unknown loader/exporter option");return values;
    }
    static JsonObject optionValues(JsonObject p){return p.has("options")?p.getAsJsonObject("options"):new JsonObject();}
    static Object loaders(JsonObject p) throws Exception {
        try(ByteProvider provider=new RandomAccessByteProvider(Path.of(text(p,"input")).toFile())){
            LoaderMap supported=LoaderService.getAllSupportedLoadSpecs(provider);List<Object> rows=new ArrayList<>();
            for(var entry:supported.entrySet()){
                Loader loader=entry.getKey();List<Object> specs=new ArrayList<>();
                for(LoadSpec spec:entry.getValue()){Map<String,Object> row=new LinkedHashMap<>();var lcs=spec.getLanguageCompilerSpec();
                    row.put("language",lcs==null?null:lcs.languageID.toString());row.put("compiler_spec",lcs==null?null:lcs.compilerSpecID.toString());row.put("preferred",spec.isPreferred());row.put("complete",spec.isComplete());
                    row.put("options",options(loader.getDefaultOptions(provider,spec,null,false,false)));specs.add(row);}
                rows.add(Map.of("id",loader.getClass().getName(),"name",loader.getName(),"load_specs",specs));}
            return Map.of("supported",rows,"all_loader_names",LoaderService.getAllLoaderNames());
        }
    }
    static Object importProgram(JsonObject p) throws Exception {
        String selected=text(p,"loader");Object consumer=new Object();Loader loader=null;
        for(Loader candidate:ClassSearcher.getInstances(Loader.class))if(candidate.getClass().getName().equals(selected)||candidate.getClass().getSimpleName().equals(selected)||candidate.getName().equals(selected)){
            if(loader!=null)throw new IllegalArgumentException("Ambiguous installed loader");loader=candidate;}
        if(loader==null)throw new IllegalArgumentException("Unknown installed loader");
        Language language=text(p,"language").isEmpty()?null:DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(text(p,"language")));
        CompilerSpec compiler=language==null?null:text(p,"compiler_spec").isEmpty()?language.getDefaultCompilerSpec():language.getCompilerSpecByID(new CompilerSpecID(text(p,"compiler_spec")));
        try(ByteProvider provider=new RandomAccessByteProvider(Path.of(text(p,"input")).toFile())){
            LoadSpec selectedSpec=null;for(LoadSpec spec:loader.findSupportedLoadSpecs(provider)){
                if(language!=null){selectedSpec=new LoadSpec(loader,spec.getDesiredImageBase(),new LanguageCompilerSpecPair(language.getLanguageID(),compiler.getCompilerSpecID()),true);break;}
                if(spec.isPreferred()&&spec.isComplete()){selectedSpec=spec;break;}}
            if(selectedSpec==null)throw new IllegalArgumentException("Loader needs a complete language/compiler selection");
            Language effectiveLanguage=language;if(effectiveLanguage==null&&selectedSpec.getLanguageCompilerSpec()!=null)effectiveLanguage=DefaultLanguageService.getLanguageService().getLanguage(selectedSpec.getLanguageCompilerSpec().languageID);
            var options=configured(loader.getDefaultOptions(provider,selectedSpec,null,false,false),optionValues(p),effectiveLanguage==null?null:effectiveLanguage.getAddressFactory());
            String error=loader.validateOptions(provider,selectedSpec,options,null);if(error!=null)throw new IllegalArgumentException("Native loader rejected options");
            var settings=new Loader.ImporterSettings(provider,"OwnedInput",null,"/",false,selectedSpec,options,consumer,new MessageLog(),TaskMonitor.DUMMY);
            var result=loader.load(settings);
            if(result==null)throw new IllegalStateException("Native loader did not return a program");
            try {
                if(result.size()!=1||!(result.getPrimaryDomainObject() instanceof Program))throw new IllegalArgumentException("Loader must produce one program per explicit target");
                Program program=(Program)result.getPrimaryDomainObject();
                boolean analyze=p.has("auto_analyze")&&p.get("auto_analyze").getAsBoolean();
                if(analyze){AutoAnalysisManager analysis=AutoAnalysisManager.getAnalysisManager(program);analysis.initializeOptions();analysis.reAnalyzeAll(null);analysis.startAnalysis(TaskMonitor.DUMMY);}
                program.saveToPackedFile(Path.of(text(p,"output")).toFile(),TaskMonitor.DUMMY);
                return Map.of("state","imported","loader",loader.getClass().getName(),"language",program.getLanguageID().toString(),
                    "compiler",program.getCompilerSpec().getCompilerSpecID().toString(),"sha256",program.getExecutableSHA256(),"auto_analyzed",analyze);
            } finally {result.release(consumer);}
        }
    }
    static Object exporters(Program program) throws Exception {
        List<Object> rows=new ArrayList<>();for(Exporter exporter:ClassSearcher.getInstances(Exporter.class)){
            if(!exporter.canExportDomainObject(program))continue;
            rows.add(Map.of("id",exporter.getClass().getName(),"name",exporter.getName(),"extension",Objects.toString(exporter.getDefaultFileExtension(),""),
                "address_restriction",exporter.supportsAddressRestrictedExport(),"options",options(exporter.getOptions(()->program))));}
        return Map.of("items",rows);
    }
    static Object export(Program program,JsonObject p) throws Exception {
        Exporter exporter=null;for(Exporter candidate:ClassSearcher.getInstances(Exporter.class))if(candidate.canExportDomainObject(program)&&(candidate.getName().equals(text(p,"exporter"))||candidate.getClass().getName().equals(text(p,"exporter")))){if(exporter!=null)throw new IllegalArgumentException("Ambiguous exporter");exporter=candidate;}
        if(exporter==null||!exporter.canExportDomainObject(program))throw new IllegalArgumentException("Exporter is not available for this program");
        AddressSet selection=null;if(p.has("ranges")){if(!exporter.supportsAddressRestrictedExport())throw new IllegalArgumentException("Exporter cannot restrict address ranges");selection=new AddressSet();
            for(JsonElement value:p.getAsJsonArray("ranges")){JsonObject range=value.getAsJsonObject();Address start=program.getAddressFactory().getAddress(text(range,"start")),end=program.getAddressFactory().getAddress(text(range,"end"));
                if(start==null||end==null||!start.getAddressSpace().equals(end.getAddressSpace())||start.compareTo(end)>0)throw new IllegalArgumentException("Invalid export range");selection.add(start,end);}
            if(selection.isEmpty()||selection.getNumAddresses()>16777216)throw new IllegalArgumentException("Export selection must be 1–16 MiB");}
        exporter.setOptions(configured(exporter.getOptions(()->program),optionValues(p),program.getAddressFactory()));
        long before=program.getModificationNumber();
        if(!exporter.export(Path.of(text(p,"output")).toFile(),program,selection,TaskMonitor.DUMMY)||before!=program.getModificationNumber())throw new IllegalStateException("Native exporter did not complete a read-only export");
        return Map.of("state","exported","exporter",exporter.getClass().getName(),"format",exporter.getName(),"source_sha256",program.getExecutableSHA256(),"selected",selection!=null);
    }
    static Object archive(Program program,JsonObject p) throws Exception {
        JsonArray names=p.getAsJsonArray("types");if(names==null||names.isEmpty()||names.size()>256)throw new IllegalArgumentException("Choose 1–256 type paths");
        try(FileDataTypeManager archive=FileDataTypeManager.createFileArchive(Path.of(text(p,"output")).toFile(),program.getLanguageID(),program.getCompilerSpec().getCompilerSpecID())){
            int transaction=archive.startTransaction("Export selected types");try{for(JsonElement name:names){DataType type=program.getDataTypeManager().getDataType(name.getAsString());if(type==null)throw new IllegalArgumentException("Type path does not exist");archive.resolve(type,DataTypeConflictHandler.DEFAULT_HANDLER);}}finally{archive.endTransaction(transaction,true);}
            archive.save();List<Object> types=new ArrayList<>();for(JsonElement name:names){DataType original=program.getDataTypeManager().getDataType(name.getAsString()),copied=archive.getDataType(name.getAsString());if(copied==null||!original.isEquivalent(copied))throw new IllegalStateException("Exported type layout differs");types.add(Map.of("path",copied.getPathName(),"size",copied.getLength()));}
            return Map.of("state","exported","format","GDT","archive_id",archive.getUniversalID().toString(),"types",types);
        }
    }
    static Object run(JsonObject p) throws Exception {
        String operation=text(p,"operation");if(operation.equals("loaders"))return loaders(p);if(operation.equals("import"))return importProgram(p);
        Object consumer=new Object();var db=PackedDatabase.getPackedDatabase(Path.of(text(p,"snapshot")).toFile(),true,TaskMonitor.DUMMY).open(TaskMonitor.DUMMY);
        ProgramDB program=new ProgramDB(db,OpenMode.IMMUTABLE,TaskMonitor.DUMMY,consumer);
        try {return switch(operation){case "exporters"->exporters(program);case "export"->export(program,p);case "archive-export"->archive(program,p);default->throw new IllegalArgumentException("Unknown SDK file operation");};}
        finally{program.release(consumer);}
    }
    public static void main(String[] args) {
        var output=System.out;System.setOut(System.err);
        try{Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
            JsonObject request=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();Object value=run(request);InsightNativeReceipt.write(request,value);
            output.println(new GsonBuilder().serializeNulls().create().toJson(Map.of("value",value)));System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"native_sdk_file_failed\"}");System.exit(1);}
    }
}
