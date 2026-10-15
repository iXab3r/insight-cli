package insight;

import com.google.gson.*;
import com.xebyte.core.ServiceUtils;
import ghidra.docking.settings.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;

/** Native GDT/layout/settings workflows, including bitfields rather than C text substitutes. */
public class InsightSdkTypes {
    static String text(JsonObject p,String key){return InsightSdkTools.text(p,key);}
    static DataType type(Program program,String path){DataType value=program.getDataTypeManager().getDataType(path);
        if(value==null)throw new IllegalArgumentException("Explicit type path is absent");return value;}
    static DataType resolve(Program program,DataTypeManager manager,String name)throws Exception{
        DataType source=program.getDataTypeManager().getDataType(name);
        if(source==null)source=ServiceUtils.findDataTypeByNameInAllCategories(program.getDataTypeManager(),name);
        DataType value=source==null?ServiceUtils.resolveDataType(manager,name):manager.resolve(source,DataTypeConflictHandler.DEFAULT_HANDLER);
        if(value==null)throw new IllegalArgumentException("Field type could not be resolved");return value;
    }
    static List<Object> settings(DataType type){List<Object> rows=new ArrayList<>();Settings values=type.getDefaultSettings();
        for(SettingsDefinition definition:type.getSettingsDefinitions()){
            Map<String,Object> row=new LinkedHashMap<>();row.put("name",definition.getName());row.put("definition",definition.getClass().getSimpleName());row.put("explicit",definition.hasValue(values));
            if(definition instanceof EnumSettingsDefinition enumeration){row.put("value",enumeration.getChoice(values));row.put("choices",enumeration.getDisplayChoices(values));}
            else if(definition instanceof StringSettingsDefinition string)row.put("value",string.getValue(values));
            else if(definition instanceof BooleanSettingsDefinition bool)row.put("value",bool.getValue(values));
            else if(definition instanceof NumberSettingsDefinition number)row.put("value",Long.toString(number.getValue(values)));
            else row.put("value",definition.getValueString(values));rows.add(row);}
        return rows;
    }
    public static Object layout(DataType value){
        if(value==null)throw new IllegalArgumentException("Explicit type path is absent");
        Map<String,Object> row=new LinkedHashMap<>();row.put("path",value.getPathName());row.put("size",value.getLength());row.put("alignment",value.getAlignment());row.put("settings",settings(value));
        var source=value.getSourceArchive();row.put("source_archive",source==null?null:Map.of("id",source.getSourceArchiveID().toString(),"name",source.getName(),"type",source.getArchiveType().toString()));
        row.put("universal_id",value.getUniversalID()==null?null:value.getUniversalID().toString());
        if(value instanceof Composite composite){
            row.put("packing",composite.getPackingType().toString());row.put("packing_value",composite.getExplicitPackingValue());row.put("minimum_alignment",composite.getExplicitMinimumAlignment());
            List<Object> fields=new ArrayList<>();int total=composite.getNumDefinedComponents();
            DataTypeComponent[] components=total<=10000?composite.getDefinedComponents():new DataTypeComponent[0];
            for(DataTypeComponent field:components){if(fields.size()>=256)break;
                Map<String,Object> item=new LinkedHashMap<>();item.put("name",field.getFieldName());item.put("type",field.getDataType().getPathName());item.put("offset",field.getOffset());item.put("size",field.getLength());item.put("comment",field.getComment());
                if(field.getDataType() instanceof BitFieldDataType bit){item.put("bit_size",bit.getDeclaredBitSize());item.put("bit_offset",bit.getBitOffset());item.put("base_type",bit.getBaseDataType().getPathName());}fields.add(item);}
            row.put("fields",fields);row.put("fields_total",total);row.put("fields_complete",fields.size()==total);}
        return row;
    }
    static Structure structure(Program program,DataTypeManager manager,JsonObject p)throws Exception{
        String path=text(p,"path");int slash=path.lastIndexOf('/');
        if(slash<0||slash==path.length()-1)throw new IllegalArgumentException("Structure requires an absolute type path");
        Structure structure=new StructureDataType(new CategoryPath(slash==0?"/":path.substring(0,slash)),path.substring(slash+1),0,manager);
        int packing=p.has("packing")?p.get("packing").getAsInt():0;
        if(packing<0)structure.setPackingEnabled(false);else if(packing==0)structure.setToDefaultPacking();else structure.setExplicitPackingValue(packing);
        int alignment=p.has("alignment")?p.get("alignment").getAsInt():0;
        if(alignment<0)structure.setToMachineAligned();else if(alignment==0)structure.setToDefaultAligned();else structure.setExplicitMinimumAlignment(alignment);
        JsonArray fields=p.getAsJsonArray("fields");if(fields==null||fields.isEmpty()||fields.size()>256)throw new IllegalArgumentException("Structure requires 1–256 fields");
        Set<String> names=new HashSet<>();for(JsonElement element:fields){JsonObject field=element.getAsJsonObject();String name=text(field,"name");
            if(name.isEmpty()||!names.add(name))throw new IllegalArgumentException("Field names must be nonempty and unique");
            DataType type=resolve(program,manager,text(field,"type"));String comment=field.has("comment")?text(field,"comment"):null;
            if(field.has("offset")){
                if(structure.isPackingEnabled())throw new IllegalArgumentException("Explicit offsets require disabled packing");int offset=field.get("offset").getAsInt();
                if(offset<0||offset>1048576)throw new IllegalArgumentException("Field offset exceeds layout bound");
                if(field.has("bit_size")){int width=field.has("byte_width")?field.get("byte_width").getAsInt():type.getLength(),bit=field.has("bit_offset")?field.get("bit_offset").getAsInt():0;
                    structure.insertBitFieldAt(offset,width,bit,type,field.get("bit_size").getAsInt(),name,comment);}
                else {if(offset<structure.getLength())throw new IllegalArgumentException("Explicit fields cannot overlap");structure.growStructure(offset-structure.getLength());structure.add(type,name,comment);}
            }else if(field.has("bit_size"))structure.addBitField(type,field.get("bit_size").getAsInt(),name,comment);
            else structure.add(type,name,comment);
        }return structure;
    }
    public static void edit(Program program,String operation,JsonObject p,TaskMonitor monitor)throws Exception{
        switch(operation){
            case "type-structure": {
                var manager=program.getDataTypeManager();DataType existing=manager.getDataType(text(p,"path"));
                if(existing!=null&&(!p.has("replace_placeholder")||!p.get("replace_placeholder").getAsBoolean()||!(existing instanceof Structure s)||s.getNumDefinedComponents()!=0))throw new IllegalArgumentException("Existing type is not an explicitly replaceable empty structure");
                Structure wanted=structure(program,manager,p);manager.addDataType(wanted,existing==null?DataTypeConflictHandler.DEFAULT_HANDLER:DataTypeConflictHandler.REPLACE_HANDLER);break;
            }
            case "type-settings": {
                DataType type=type(program,text(p,"path"));JsonObject changes=p.getAsJsonObject("settings");if(changes==null||changes.size()>32)throw new IllegalArgumentException("Settings require at most 32 definition names");
                Map<String,SettingsDefinition> definitions=new HashMap<>();for(var definition:type.getSettingsDefinitions())definitions.put(definition.getName(),definition);
                for(String name:changes.keySet()){SettingsDefinition definition=definitions.get(name);if(definition==null)throw new IllegalArgumentException("Unknown native setting definition name");JsonElement value=changes.get(name);Settings settings=type.getDefaultSettings();
                    if(value.isJsonNull())definition.clear(settings);
                    else if(definition instanceof EnumSettingsDefinition enumeration){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isNumber())throw new IllegalArgumentException("Native enum setting requires an integer choice");int choice=value.getAsBigDecimal().intValueExact();if(choice<0||choice>=enumeration.getDisplayChoices(settings).length)throw new IllegalArgumentException("Setting choice is outside native enumeration");enumeration.setChoice(settings,choice);}
                    else if(definition instanceof StringSettingsDefinition string){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString())throw new IllegalArgumentException("Native string setting requires text");string.setValue(settings,value.getAsString());}
                    else if(definition instanceof BooleanSettingsDefinition bool){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isBoolean())throw new IllegalArgumentException("Native boolean setting requires a Boolean");bool.setValue(settings,value.getAsBoolean());}
                    else if(definition instanceof NumberSettingsDefinition number){BigInteger n=new BigInteger(value.getAsString());if(n.signum()<0&&!number.allowNegativeValue()||n.compareTo(number.getMaxValue())>0||n.bitLength()>63)throw new IllegalArgumentException("Numeric setting exceeds native bounds");number.setValue(settings,n.longValueExact());}
                    else throw new IllegalArgumentException("Native setting has no supported typed setter");}
                break;
            }
            case "type-archive-import": {
                try(FileDataTypeManager archive=FileDataTypeManager.openFileArchive(Path.of(text(p,"input_path")).toFile(),false)){
                    JsonArray names=p.getAsJsonArray("types");if(names==null||names.isEmpty()||names.size()>256)throw new IllegalArgumentException("Choose 1–256 archive type paths");
                    var manager=program.getDataTypeManager();for(JsonElement name:names){DataType wanted=archive.getDataType(name.getAsString());if(wanted==null)throw new IllegalArgumentException("Archive type path is absent");
                        DataType existing=manager.getDataType(name.getAsString());if(existing!=null&&!existing.isEquivalent(wanted))throw new IllegalArgumentException("Existing type conflicts with the selected archive layout");
                        manager.resolve(wanted,DataTypeConflictHandler.DEFAULT_HANDLER);}
                }break;
            }
            default:throw new IllegalArgumentException("Unknown type workflow");
        }
    }
    public static Object verify(Program program,String operation,JsonObject p,TaskMonitor monitor)throws Exception{
        switch(operation){
            case "type-structure": {
                DataType actual=type(program,text(p,"path"));try(var expected=new StandAloneDataTypeManager("LayoutVerification",program.getDataTypeManager().getDataOrganization())){
                    int transaction=expected.startTransaction("Build expected layout");try{
                        Structure wanted=structure(program,expected,p);InsightSdkTools.require(actual instanceof Structure&&actual.isEquivalent(wanted),"Saved structure fields/packing/bitfields differ");
                        InsightSdkTools.require(actual.getLength()==wanted.getLength()&&actual.getAlignment()==wanted.getAlignment(),"Saved structure size/alignment differs");return layout(actual);
                    }finally{expected.endTransaction(transaction,false);}}
            }
            case "type-settings": {
                DataType actual=type(program,text(p,"path"));JsonObject changes=p.getAsJsonObject("settings");Map<String,SettingsDefinition> definitions=new HashMap<>();for(var definition:actual.getSettingsDefinitions())definitions.put(definition.getName(),definition);
                Settings settings=actual.getDefaultSettings();for(String name:changes.keySet()){SettingsDefinition definition=definitions.get(name);InsightSdkTools.require(definition!=null,"Saved setting definition disappeared");JsonElement expected=changes.get(name);
                    if(expected.isJsonNull())InsightSdkTools.require(!definition.hasValue(settings),"Saved explicit setting remains");
                    else if(definition instanceof EnumSettingsDefinition enumeration)InsightSdkTools.require(enumeration.getChoice(settings)==expected.getAsInt(),"Saved enum setting differs");
                    else if(definition instanceof BooleanSettingsDefinition bool)InsightSdkTools.require(bool.getValue(settings)==expected.getAsBoolean(),"Saved boolean setting differs");
                    else if(definition instanceof StringSettingsDefinition string)InsightSdkTools.require(Objects.equals(string.getValue(settings),expected.getAsString()),"Saved string setting differs");
                    else if(definition instanceof NumberSettingsDefinition number)InsightSdkTools.require(Long.toString(number.getValue(settings)).equals(expected.getAsString()),"Saved number setting differs");
                    else throw new IllegalArgumentException("Unsupported saved setting definition");}
                return layout(actual);
            }
            case "type-archive-import": {
                try(FileDataTypeManager archive=FileDataTypeManager.openFileArchive(Path.of(text(p,"input_path")).toFile(),false)){
                    List<Object> rows=new ArrayList<>();for(JsonElement name:p.getAsJsonArray("types")){DataType wanted=archive.getDataType(name.getAsString()),actual=type(program,name.getAsString());
                        InsightSdkTools.require(wanted!=null&&actual.isEquivalent(wanted),"Saved archive layout differs");
                        InsightSdkTools.require(actual.getSourceArchive()!=null&&actual.getSourceArchive().getSourceArchiveID().equals(archive.getUniversalID()),"Saved archive source identity differs");rows.add(layout(actual));}
                    return Map.of("archive_id",archive.getUniversalID().toString(),"types",rows);
                }
            }
            default:throw new IllegalArgumentException("Unknown saved type workflow");
        }
    }
}
