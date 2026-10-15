import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.*;
import com.google.gson.*;
import java.nio.*;
import java.nio.charset.*;
import java.math.BigInteger;
import java.util.*;

/** Isolated instruction stepping. No writes to Program memory, no external process execution. */
public class InsightEmulation extends GhidraScript {
  JsonObject p;String abi;int bits,maxSteps;long deadline;int totalSteps;final long stackTop=0x7fff0000L,sentinel=0x7ffd0000L,scratch=0x7ffc0000L;
  Map<String,Object> map(Object... pairs){Map<String,Object> out=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;}
  String str(String name,String fallback){return !p.has(name)||p.get(name).isJsonNull()?fallback:p.get(name).getAsString();}
  int number(String name,int fallback,int min,int max){int value=p.has(name)?p.get(name).getAsInt():fallback;if(value<min||value>max)throw new IllegalArgumentException(name+" outside supported range");return value;}
  JsonElement json(String name){if(!p.has(name)||p.get(name).isJsonNull()||p.get(name).isJsonPrimitive()&&p.get(name).getAsString().isEmpty())return JsonNull.INSTANCE;var value=p.get(name);return value.isJsonPrimitive()?JsonParser.parseString(value.getAsString()):value;}
  Address at(String value){var address=currentProgram.getAddressFactory().getAddress(value);if(address==null)throw new IllegalArgumentException("Invalid emulation address");return address;}
  Address absolute(long value){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);}
  Function function(String value)throws Exception{Function found=null;try{found=currentProgram.getFunctionManager().getFunctionAt(at(value));}catch(Exception ignored){}if(found!=null)return found;
    var iter=currentProgram.getFunctionManager().getFunctions(true);int visited=0;while(iter.hasNext()){if(++visited>100000||System.nanoTime()>deadline)throw new IllegalArgumentException("Function lookup budget exceeded; use entry address");var f=iter.next();if(f.getName().equals(value)||f.getName(true).equals(value)){if(found!=null)throw new IllegalArgumentException("Ambiguous function");found=f;}}if(found==null)throw new IllegalArgumentException("Function not found");return found;}
  BigInteger integer(String input){String value=input.trim();return value.startsWith("0x")||value.startsWith("0X")?new BigInteger(value.substring(2),16):new BigInteger(value);}
  String hex(BigInteger value){return "0x"+value.toString(16);}
  void policy(){
    bits=currentProgram.getLanguage().getLanguageDescription().getSize();
    if(!currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86")||currentProgram.getLanguage().isBigEndian()||!List.of(32,64).contains(bits))throw new UnsupportedOperationException("Emulation supports little-endian x86 32/64 only; this language is unsupported");
    String selected=str("abi","auto"),compiler=currentProgram.getCompilerSpec().getCompilerSpecID().toString();
    abi=selected.equals("auto")?(bits==32?"x86-cdecl":List.of("windows","clangwindows").contains(compiler)?"windows-x64":"sysv-x64"):selected;
    if(bits==32&&!abi.equals("x86-cdecl")||bits==64&&!List.of("windows-x64","sysv-x64").contains(abi))throw new UnsupportedOperationException("ABI does not match supported language/width");
    if(selected.equals("auto")&&!List.of("windows","clangwindows","gcc","clang","default").contains(compiler))throw new UnsupportedOperationException("Compiler ABI is unknown; select an explicit supported --abi");
    if(currentProgram.getMemory().intersects(absolute(stackTop-65536),absolute(stackTop+256)))throw new UnsupportedOperationException("Reserved ABI stack overlaps program memory");
    for(long base:new long[]{sentinel,scratch})if(currentProgram.getMemory().intersects(absolute(base),absolute(base+65535)))throw new UnsupportedOperationException("Reserved emulation stack/sentinel/scratch overlaps program memory");
    maxSteps=number("max_steps",10000,1,100000);number("timeout_seconds",5,1,30);
  }
  void registers(EmulatorHelper emu,JsonElement raw){if(raw.isJsonNull())return;if(!raw.isJsonObject())throw new IllegalArgumentException("Registers must be an object");for(var entry:raw.getAsJsonObject().entrySet()){
    Register register=currentProgram.getRegister(entry.getKey());if(register==null||register.getBitLength()>64)throw new IllegalArgumentException("Unknown or unsupported register");
    if(register.getBaseRegister().equals(emu.getPCRegister().getBaseRegister())||register.getBaseRegister().equals(emu.getStackPointerRegister().getBaseRegister()))throw new IllegalArgumentException("PC and SP are owned by the selected emulation ABI");
    BigInteger value=integer(entry.getValue().getAsString());if(value.signum()<0||value.bitLength()>register.getBitLength())throw new IllegalArgumentException("Register value exceeds its unsigned width");emu.writeRegister(register,value);
  }}
  void memory(EmulatorHelper emu,JsonElement raw){if(raw.isJsonNull())return;if(raw.isJsonObject()&&raw.getAsJsonObject().has("regions"))raw=raw.getAsJsonObject().get("regions");if(!raw.isJsonArray()||raw.getAsJsonArray().size()>64)throw new IllegalArgumentException("Memory needs at most 64 regions");int total=0;
    for(var item:raw.getAsJsonArray()){var region=item.getAsJsonObject();byte[] bytes;if(region.has("string"))bytes=region.get("string").getAsString().getBytes(StandardCharsets.UTF_8);else if(region.has("data"))bytes=Base64.getDecoder().decode(region.get("data").getAsString());else if(region.has("hex"))bytes=java.util.HexFormat.of().parseHex(region.get("hex").getAsString().replace(" ",""));else throw new IllegalArgumentException("Memory region needs string, base64 data or hex");if((total+=bytes.length)>65536)throw new IllegalArgumentException("Initial memory exceeds 64 KiB");var dest=at(region.get("address").getAsString());if(dest.getAddressSpace()!=currentProgram.getAddressFactory().getDefaultAddressSpace())throw new IllegalArgumentException("Emulation inputs require default address space");long offset=dest.getOffset();if(offset>=stackTop-65536&&offset<stackTop||offset<=sentinel&&offset+bytes.length>sentinel)throw new IllegalArgumentException("Caller memory overlaps the ABI-owned stack/return sentinel");emu.writeMemory(dest,bytes);}
  }
  boolean scalar(DataType type){while(type instanceof TypeDef alias)type=alias.getBaseDataType();return type instanceof Pointer||type instanceof AbstractIntegerDataType||type instanceof BooleanDataType||type instanceof ghidra.program.model.data.Enum||type instanceof VoidDataType||type.getName().startsWith("undefined");}
  Map<String,Object> runFunction(Function function,JsonElement registers,JsonElement memory,String returns)throws Exception{
    if(!scalar(function.getReturnType()))throw new UnsupportedOperationException("Floating-point/aggregate return lowering is unsupported by the integer-slot ABI helper");
    if(!json("arguments").isJsonNull()){
      if(function.hasVarArgs())throw new UnsupportedOperationException("Variadic argument lowering is unsupported");
      for(var parameter:function.getParameters())if(!scalar(parameter.getDataType()))throw new UnsupportedOperationException("Floating-point/aggregate argument lowering is unsupported");
      if(bits==32&&!List.of("unknown","default","__cdecl").contains(function.getCallingConventionName()))throw new UnsupportedOperationException("Only x86 cdecl integer/pointer argument lowering is supported");
    }
    var emu=new EmulatorHelper(currentProgram);int steps=0;boolean returned=false;String reason="step_limit",error=null;
    try{
      long stack=bits==64?stackTop-8:stackTop-4;emu.writeMemory(absolute(stackTop-65536),new byte[65536+256]);emu.writeRegister(emu.getStackPointerRegister(),stack);emu.writeRegister(bits==64?"RBP":"EBP",stack);
      byte[] returnBytes=bits==64?ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(sentinel).array():ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int)sentinel).array();emu.writeMemory(absolute(stack),returnBytes);
      JsonElement arguments=json("arguments");if(!arguments.isJsonNull()){
        if(!arguments.isJsonArray()||arguments.getAsJsonArray().size()>16)throw new IllegalArgumentException("At most 16 unsigned integer/pointer arguments are supported");
        String[] argumentRegisters=bits==32?new String[0]:abi.equals("windows-x64")?new String[]{"RCX","RDX","R8","R9"}:new String[]{"RDI","RSI","RDX","RCX","R8","R9"};
        int index=0;for(var argument:arguments.getAsJsonArray()){BigInteger value=integer(argument.getAsString());if(value.signum()<0||value.bitLength()>bits)throw new IllegalArgumentException("Argument exceeds pointer width");
          if(index<argumentRegisters.length)emu.writeRegister(argumentRegisters[index],value);else {long location=stack+bits/8+(abi.equals("windows-x64")?32:0)+(long)(index-argumentRegisters.length)*(bits/8);byte[] data=bits==64?ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value.longValue()).array():ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value.intValue()).array();emu.writeMemory(absolute(location),data);}index++;}
      }
      registers(emu,registers);memory(emu,memory);emu.writeRegister(emu.getPCRegister(),function.getEntryPoint().getOffset());
      while(steps<maxSteps){monitor.checkCancelled();if(System.nanoTime()>deadline){reason="timeout";break;}if(totalSteps>=200000){reason="batch_step_limit";break;}if(emu.getExecutionAddress().equals(absolute(sentinel))){returned=true;reason="return";break;}
        if(!emu.step(monitor)){reason="emulator_error";error=Objects.toString(emu.getLastError(),"Emulator stopped");break;}steps++;totalSteps++;
      }
      if(!returned&&emu.getExecutionAddress().equals(absolute(sentinel))){returned=true;reason="return";}
      Map<String,Object> values=new LinkedHashMap<>();List<String> requested=returns.isEmpty()?(bits==64?List.of("RAX","RBX","RCX","RDX","RSI","RDI","R8","R9","RSP","RIP"):List.of("EAX","EBX","ECX","EDX","ESI","EDI","ESP","EIP")):Arrays.asList(returns.split(","));
      if(requested.size()>32)throw new IllegalArgumentException("At most 32 output registers");for(String name:requested){var register=currentProgram.getRegister(name.trim());if(register==null||register.getBitLength()>64)throw new IllegalArgumentException("Unknown or oversized output register");values.put(register.getName(),hex(emu.readRegister(register)));}
      List<Object> observed=new ArrayList<>();var reads=json("read_memory_after");int totalRead=0;if(!reads.isJsonNull()){if(!reads.isJsonArray()||reads.getAsJsonArray().size()>64)throw new IllegalArgumentException("Readback needs at most 64 regions");for(var raw:reads.getAsJsonArray()){var r=raw.getAsJsonObject();int size=r.get("length").getAsInt();if(size<0||(totalRead+=size)>65536)throw new IllegalArgumentException("Readback exceeds 64 KiB");var address=at(r.get("address").getAsString());observed.add(map("address",address.toString(),"length",size,"hex",java.util.HexFormat.of().formatHex(emu.readMemory(address,size))));}}
      return map("success",true,"completed",returned,"hit_return",returned,"steps_executed",steps,"stop_reason",reason,"error",error,"registers",values,"memory_after",observed,"abi",abi,"language",currentProgram.getLanguageID().toString(),"stack_pointer",hex(BigInteger.valueOf(stack)),"pointer_bytes",bits/8,"step_unit","instruction","limitations",List.of("Isolated computation only; imports, OS services, syscalls and arbitrary ABI variants are unsupported.","Budget exhaustion is not a completed execution; inspect completed and stop_reason."));
    }finally{emu.dispose();}
  }
  Object execute(String operation)throws Exception{
    policy();if(operation.equals("/emulate_function"))return runFunction(function(str("function","")),json("registers"),json("memory"),str("return_registers",""));
    var function=function(str("hash_function_address",""));var candidates=json("candidates");if(!candidates.isJsonArray()||candidates.getAsJsonArray().size()>256)throw new IllegalArgumentException("Hash emulation supports at most 256 candidates per bounded call");
    String output=str("result_register","EAX"),input=str("string_register","");Register resultRegister=currentProgram.getRegister(output);if(resultRegister==null||resultRegister.getBitLength()>64)throw new IllegalArgumentException("Invalid result register");BigInteger wanted=integer(str("target_hash","")).and(BigInteger.ONE.shiftLeft(resultRegister.getBitLength()).subtract(BigInteger.ONE));
    List<Object> matches=new ArrayList<>(),outcomes=new ArrayList<>();int tested=0;boolean complete=true;String best=null;
    for(var candidate:candidates.getAsJsonArray()){
      if(System.nanoTime()>deadline||totalSteps>=200000){complete=false;break;}String text=candidate.getAsString();byte[] bytes=(text+"\0").getBytes(p.has("wide_string")&&p.get("wide_string").getAsBoolean()?StandardCharsets.UTF_16LE:StandardCharsets.US_ASCII);if(bytes.length>65536)throw new IllegalArgumentException("Candidate exceeds scratch buffer");
      JsonObject regs=json("initial_registers").isJsonNull()?new JsonObject():json("initial_registers").getAsJsonObject().deepCopy();regs.addProperty(input,"0x"+Long.toHexString(scratch));JsonObject region=new JsonObject();region.addProperty("address","0x"+Long.toHexString(scratch));region.addProperty("data",Base64.getEncoder().encodeToString(bytes));JsonArray memory=new JsonArray();memory.add(region);
      JsonElement original=p.get("arguments");JsonArray arguments=new JsonArray();arguments.add("0x"+Long.toHexString(scratch));p.add("arguments",arguments);
      Map<String,Object> result;try{result=runFunction(function,regs,memory,output);}finally{if(original==null)p.remove("arguments");else p.add("arguments",original);}tested++;boolean ended=(boolean)result.get("completed");outcomes.add(map("candidate",text,"completed",ended,"stop_reason",result.get("stop_reason"),"steps_executed",result.get("steps_executed")));if(!ended){complete=false;continue;}
      String value=(String)((Map<?,?>)result.get("registers")).get(resultRegister.getName());if(integer(value).equals(wanted)){matches.add(map("candidate",text,"hash",value));if(best==null)best=text;}
    }
    return map("tested",tested,"total_candidates",candidates.getAsJsonArray().size(),"complete",complete,"truncated",tested<candidates.getAsJsonArray().size(),"resolved",!matches.isEmpty(),"matches",matches,"best_match",best,"outcomes",outcomes,"abi",abi,"steps_executed",totalSteps,"algorithm","isolated-exact-register-comparison-v1");
  }
  public void run()throws Exception{
    var request=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();p=request.getAsJsonObject("parameters");deadline=System.nanoTime()+number("timeout_seconds",5,1,30)*1000000000L;Map<String,Object> result;
    try{result=map("value",execute(request.get("operation").getAsString()));}catch(Exception error){result=map("error",map("code",error instanceof UnsupportedOperationException?"unsupported":error instanceof IllegalArgumentException?"invalid":"partial","message",Objects.toString(error.getMessage(),"Emulation failed")));}
    println("INSIGHT_QUERY:"+new GsonBuilder().serializeNulls().create().toJson(result));
  }
}
