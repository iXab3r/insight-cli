import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Apply typed documentation without the pinned endpoint's regex parsing/silent skips. */
public class InsightApplyDocumentation extends GhidraScript {
  String value(JsonObject object,String key){return object.has(key)&&!object.get(key).isJsonNull()?object.get(key).getAsString():"";}
  DataType resolve(String name)throws Exception{
    return new FunctionSignatureParser(currentProgram.getDataTypeManager(),null).parse(null,name+" __insight_resolve(void)").getReturnType();
  }
  public void run()throws Exception {
    JsonObject document=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
    var at=toAddr(value(document,"target_address"));if(at==null)throw new IllegalArgumentException("Invalid target address");
    var function=currentProgram.getFunctionManager().getFunctionAt(at);if(function==null)throw new IllegalArgumentException("Function missing");
    int transaction=currentProgram.startTransaction("Apply typed documentation");boolean committed=false;
    try {
      String name=value(document,"function_name"),result=value(document,"return_type"),convention=value(document,"calling_convention"),plate=value(document,"plate_comment");
      if(!name.isEmpty())function.setName(name,SourceType.USER_DEFINED);
      if(!convention.isEmpty())function.setCallingConvention(convention);
      if(!result.isEmpty())function.setReturnType(resolve(result),SourceType.USER_DEFINED);
      if(!plate.isEmpty())function.setComment(plate);
      if(document.has("parameters"))for(JsonElement raw:document.getAsJsonArray("parameters")) {
        JsonObject parameter=raw.getAsJsonObject();int ordinal=parameter.get("ordinal").getAsInt();var params=function.getParameters();
        if(ordinal<0||ordinal>=params.length)throw new IllegalArgumentException("Parameter ordinal missing");
        String requestedName=value(parameter,"name"),requestedType=value(parameter,"type");
        if(!requestedName.isEmpty())params[ordinal].setName(requestedName,SourceType.USER_DEFINED);
        if(!requestedType.isEmpty())params[ordinal].setDataType(resolve(requestedType),SourceType.USER_DEFINED);
      }
      if(document.has("comments"))for(JsonElement raw:document.getAsJsonArray("comments")) {
        JsonObject comment=raw.getAsJsonObject();long offset=comment.get("relative_offset").getAsLong();if(offset<0)throw new IllegalArgumentException("Negative comment offset");
        var address=at.add(offset);var unit=currentProgram.getListing().getCodeUnitAt(address);if(unit==null)throw new IllegalArgumentException("Comment code unit missing");
        for(String kind:new String[]{"eol_comment","pre_comment"})if(comment.has(kind)&&!value(comment,kind).isEmpty())
          unit.setComment(kind.equals("eol_comment")?CodeUnit.EOL_COMMENT:CodeUnit.PRE_COMMENT,value(comment,kind));
      }
      if(document.has("labels"))for(JsonElement raw:document.getAsJsonArray("labels")) {
        JsonObject label=raw.getAsJsonObject();long offset=label.get("relative_offset").getAsLong();if(offset<0)throw new IllegalArgumentException("Negative label offset");
        String labelName=value(label,"name");if(labelName.isEmpty())throw new IllegalArgumentException("Label name missing");
        currentProgram.getSymbolTable().createLabel(at.add(offset),labelName,SourceType.USER_DEFINED);
      }
      committed=true;println("insight-documentation:completed");
    }finally{currentProgram.endTransaction(transaction,committed);}
  }
}
