import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;

/** Facade-owned read operations. Budgets cover visited inputs, not just returned rows. */
public class InsightResearchQueries extends GhidraScript {
  StandAloneDataTypeManager temporaryTypes; int temporaryTransaction;
  TimeoutTaskMonitor boundedMonitor;
  JsonObject p; int visited=0,maxScan,limit,offset; long deadline; boolean stopped=false;
  String str(String key,String fallback){return !p.has(key)||p.get(key).isJsonNull()?fallback:p.get(key).getAsString();}
  int number(String key,int fallback,int min,int max){int value=p.has(key)?p.get(key).getAsInt():fallback;if(value<min||value>max)throw new IllegalArgumentException(key+" outside supported range");return value;}
  boolean bool(String key,boolean fallback){return p.has(key)?p.get(key).getAsBoolean():fallback;}
  boolean visit()throws Exception{monitor.checkCancelled();if(visited>=maxScan||System.nanoTime()>deadline){stopped=true;return false;}visited++;return true;}
  Map<String,Object> map(Object... values){Map<String,Object> out=new LinkedHashMap<>();for(int i=0;i<values.length;i+=2)out.put((String)values[i],values[i+1]);return out;}
  Map<String,Object> scan(){return map("visited",visited,"maximum",maxScan,"complete",!stopped,"reason",stopped?"budget":"exhausted","timeout_seconds",number("timeout_seconds",5,1,30));}
  class PagedRows extends ArrayList<Object> {
    int total=0;
    public boolean add(Object row){int index=total++;return index>=offset&&size()<limit?super.add(row):true;}
  }
  Map<String,Object> page(String key,List<?> rows){if(rows instanceof PagedRows paged)return map(key,rows,"count",rows.size(),"total",paged.total,"total_known",!stopped,"offset",offset,"limit",limit,"truncated",stopped||offset+rows.size()<paged.total,"scan",scan());int from=Math.min(offset,rows.size()),to=Math.min(from+limit,rows.size());return map(key,rows.subList(from,to),"count",to-from,"total",rows.size(),"total_known",!stopped,"offset",offset,"limit",limit,"truncated",stopped||to<rows.size(),"scan",scan());}
  Address address(String value){Address at=currentProgram.getAddressFactory().getAddress(value);if(at==null)throw new IllegalArgumentException("Invalid or absent address space");return at;}
  Function function(String value)throws Exception{
    Function result=null;try{result=currentProgram.getFunctionManager().getFunctionAt(address(value));}catch(IllegalArgumentException ignored){}
    if(result!=null)return result;
    var iter=currentProgram.getFunctionManager().getFunctions(true);
    while(iter.hasNext()){if(!visit())throw new IllegalArgumentException("Function-name lookup exceeded budget; use an entry address");var f=iter.next();if(f.getName().equals(value)||f.getName(true).equals(value)){if(result!=null)throw new IllegalArgumentException("Ambiguous function; use address");result=f;}}
    if(result==null)throw new IllegalArgumentException("Function not found");return result;
  }
  DataTypeManager initTemporary(){temporaryTypes=new StandAloneDataTypeManager("insight-read-only-types",currentProgram.getDataTypeManager().getDataOrganization());temporaryTransaction=temporaryTypes.startTransaction("Temporary parsing");return temporaryTypes;}
  FunctionSignatureParser parser(String declaration)throws Exception{
    if(temporaryTypes==null){temporaryTypes=new StandAloneDataTypeManager("insight-read-only-types",currentProgram.getDataTypeManager().getDataOrganization());temporaryTransaction=temporaryTypes.startTransaction("Temporary parsing");}
    var iter=currentProgram.getDataTypeManager().getAllDataTypes();while(iter.hasNext()){
      if(!visit())throw new IllegalArgumentException("Type parsing input budget exceeded");var t=iter.next();
      if(declaration.contains(t.getName())){temporaryTypes.resolve(t,DataTypeConflictHandler.DEFAULT_HANDLER);if(temporaryTypes.getDataTypeCount(true)>10000)throw new IllegalArgumentException("Temporary type dependency graph exceeds 10000 types");}
    }
    return new FunctionSignatureParser(temporaryTypes,null);
  }
  Map<String,Object> type(DataType type){return map("name",type.getName(),"path",type.getPathName(),"size",type.getLength(),"alignment",type.getAlignment(),"builtin",type instanceof BuiltInDataType,"category",type.getCategoryPath().getPath(),"kind",type instanceof Structure?"struct":type instanceof Union?"union":type instanceof ghidra.program.model.data.Enum?"enum":type instanceof Pointer?"pointer":type instanceof Array?"array":type instanceof TypeDef?"typedef":type instanceof FunctionDefinition?"function":"primitive","source",type.getDataTypeManager() instanceof BuiltInDataTypeManager?"builtin":type.getDataTypeManager()==temporaryTypes?"temporary-resolved":"program","source_archive",type.getSourceArchive()==null?null:type.getSourceArchive().getName());}
  DataType resolve(String value)throws Exception{
    var manager=currentProgram.getDataTypeManager();DataType result=null;
    var iter=manager.getAllDataTypes();while(iter.hasNext()){if(!visit())throw new IllegalArgumentException("Type resolution exceeded budget; narrow its category path");var t=iter.next();if(t.getPathName().equals(value))return t;if(t.getName().equals(value)){if(result!=null)throw new IllegalArgumentException("Ambiguous type; use category path");result=t;}}
    if(result!=null)return result;
    return parser(value).parse(null,value+" __insight_type(void)").getReturnType();
  }
  Object validateType()throws Exception{
    String name=str("type_name","");List<Object> diagnostics=new ArrayList<>(),warnings=new ArrayList<>();DataType resolved=null;
    try{resolved=resolve(name);if(resolved.getLength()<=0)warnings.add("Type has no fixed positive length");String at=str("address","");if(!at.isEmpty()&&resolved.getAlignment()>1&&Long.remainderUnsigned(address(at).getUnsignedOffset(),resolved.getAlignment())!=0)warnings.add("Address is not aligned for this type");}
    catch(Exception error){diagnostics.add(map("severity","error","code","unresolved_type","message",Objects.toString(error.getMessage(),"Type cannot be resolved")));}
    return map("type_name",name,"valid",resolved!=null,"resolved",resolved==null?null:type(resolved),"warnings",warnings,"diagnostics",diagnostics,"semantics",map("kind","resolution","parser","Ghidra FunctionSignatureParser","persisted_changes",false));
  }
  Object validatePrototype()throws Exception{
    var f=function(str("function",""));String declaration=str("prototype","");int paren=declaration.indexOf('(');
    var inline=Pattern.compile("\\b(__cdecl|__stdcall|__thiscall|__fastcall|__vectorcall)\\b").matcher(paren<0?declaration:declaration.substring(0,paren));String embedded="";
    if(inline.find()){embedded=inline.group(1);declaration=(declaration.substring(0,inline.start())+declaration.substring(inline.end())).replaceAll("\\s+"," ").trim();}
    String convention=str("calling_convention","");if(convention.isEmpty())convention=embedded;
    List<Object> diagnostics=new ArrayList<>();Map<String,Object> signature=null;
    try{
      if(!convention.isEmpty()&&!convention.equals("default")&&currentProgram.getCompilerSpec().getCallingConvention(convention)==null)throw new IllegalArgumentException("Calling convention is not supported by this compiler specification");
      var parsed=parser(declaration).parse(f.getSignature(),declaration);
      signature=map("name",parsed.getName(),"return_type",type(parsed.getReturnType()),"parameters",Arrays.stream(parsed.getArguments()).map(a->map("name",Objects.toString(a.getName(),""),"type",type(a.getDataType()))).toList(),"calling_convention",convention.equals("default")?currentProgram.getCompilerSpec().getDefaultCallingConvention().getName():convention.isEmpty()?Objects.toString(f.getCallingConventionName(),"default"):convention);
    }catch(Exception error){diagnostics.add(map("severity","error","code","prototype_parse","message",Objects.toString(error.getMessage(),"Prototype cannot be parsed")));}
    return map("valid",signature!=null,"signature",signature,"diagnostics",diagnostics,"parser","Ghidra FunctionSignatureParser","persisted_changes",false);
  }
  Object types(boolean validInventory)throws Exception{
    List<Object> rows=new PagedRows();Set<String> categories=new LinkedHashSet<>(),paths=new HashSet<>();
    String pattern=str("pattern","").toLowerCase(Locale.ROOT),category=str("category","").toLowerCase(Locale.ROOT),kind=str("kind","").trim().toLowerCase(Locale.ROOT);if(validInventory&&category.equals("all"))category="";
    if(!validInventory&&bool("categories",false)){
      List<Object> result=new PagedRows();Deque<Category> work=new ArrayDeque<>();work.add(currentProgram.getDataTypeManager().getRootCategory());
      while(!work.isEmpty()){if(!visit())break;var current=work.removeFirst();String path=current.getCategoryPath().getPath();if(path.toLowerCase(Locale.ROOT).contains(pattern))result.add(path);work.addAll(Arrays.asList(current.getCategories()));}
      return page("categories",result);
    }
    var iter=currentProgram.getDataTypeManager().getAllDataTypes();
    while(iter.hasNext()){if(!visit())break;var t=iter.next();var row=type(t);String path=t.getPathName();if(!path.toLowerCase(Locale.ROOT).contains(pattern)||!t.getCategoryPath().getPath().toLowerCase(Locale.ROOT).contains(category)||!kind.isEmpty()&&!kind.equals(row.get("kind")))continue;paths.add(path);rows.add(row);categories.add(t.getCategoryPath().getPath());}
    // Common builtin names are advertised only after actual resolution in this program.
    if(validInventory&&!stopped&&category.isEmpty())for(String name:List.of("void","byte","char","short","int","long","longlong","float","double","pointer","bool","undefined1","undefined2","undefined4","undefined8","uchar","ushort","uint","ulong","ulonglong")){
      if(!visit())break;try{var t=new FunctionSignatureParser(temporaryTypes==null?initTemporary():temporaryTypes,null).parse(null,name+" __insight_type(void)").getReturnType();if(paths.add(t.getPathName()))rows.add(type(t));}catch(Exception ignored){}
    }
    if(!validInventory&&bool("categories",false))return page("categories",new ArrayList<>(categories));
    var out=page(validInventory?"types":"data_types",rows);out.put("scope","program-and-resolvable-builtins");if(validInventory){out.put("builtin_types",rows.stream().filter(r->Boolean.TRUE.equals(((Map<?,?>)r).get("builtin"))).map(r->((Map<?,?>)r).get("name")).toList());out.put("windows_types",List.of());out.put("suggestions_are_inventory",false);}return out;
  }
  boolean dataAddress(Address at,boolean all){var block=currentProgram.getMemory().getBlock(at);if(block==null)return false;var listing=currentProgram.getListing();if(listing.getInstructionAt(at)!=null||currentProgram.getFunctionManager().getFunctionContaining(at)!=null)return false;return all||!block.isExecute();}
  Map<String,Object> global(Address at,Symbol symbol){var data=currentProgram.getListing().getDefinedDataAt(at);String name=symbol==null?"DAT_"+at.toString(false):symbol.getName();boolean named=symbol!=null&&!name.matches("(?i)(DAT_|PTR_|LAB_|FUN_|UNK_|undefined).*?");boolean typed=data!=null&&!data.getDataType().getName().startsWith("undefined");
    return map("address",at.toString(),"name",name,"type",data==null?"undefined":data.getDataType().getName(),"type_path",data==null?null:data.getDataType().getPathName(),"size",data==null?1:data.getLength(),"xrefs",currentProgram.getReferenceManager().getReferenceCountTo(at),"named",named,"typed",typed,"symbol_source",symbol==null?"none":symbol.getSource().toString(),"namespace",symbol==null?"Global":symbol.getParentNamespace().getName(true));}
  Object globals()throws Exception{
    List<Object> rows=new PagedRows();Set<Address> seen=new HashSet<>();boolean all=bool("include_all_sections",false);String filter=str("filter","all"),typeFilter=str("type_filter","all"),needle=str("name_substring","").toLowerCase(Locale.ROOT);int minimum=number("min_xrefs",1,0,1000000);
    if(!List.of("all","defined","undefined").contains(filter)||!List.of("all","defined","undefined").contains(typeFilter))throw new IllegalArgumentException("Global filter must be all, defined or undefined");
    var symbols=currentProgram.getSymbolTable().getSymbols(currentProgram.getGlobalNamespace());
    while(symbols.hasNext()){if(!visit())break;var symbol=symbols.next();if(symbol.getSymbolType()==SymbolType.FUNCTION||!dataAddress(symbol.getAddress(),all))continue;var row=global(symbol.getAddress(),symbol);if(globalMatch(row,filter,typeFilter,needle,minimum)){rows.add(row);seen.add(symbol.getAddress());}}
    if(!stopped&&!filter.equals("defined")&&!typeFilter.equals("defined")){
      var refs=currentProgram.getReferenceManager().getReferenceDestinationIterator(currentProgram.getMinAddress(),true);
      while(refs.hasNext()){if(!visit())break;var at=refs.next();if(seen.contains(at)||currentProgram.getSymbolTable().getPrimarySymbol(at)!=null||!dataAddress(at,all))continue;var row=global(at,null);if(globalMatch(row,filter,typeFilter,needle,minimum)){rows.add(row);seen.add(at);}}
    }
    return page("globals",rows);
  }
  boolean globalMatch(Map<String,Object> row,String filter,String types,String needle,int minimum){boolean named=(boolean)row.get("named"),typed=(boolean)row.get("typed");return (!filter.equals("defined")||named)&&(!filter.equals("undefined")||!named)&&(!types.equals("defined")||typed)&&(!types.equals("undefined")||!typed)&&(named||(int)row.get("xrefs")>=minimum)&&(needle.isEmpty()||row.toString().toLowerCase(Locale.ROOT).contains(needle));}
  Object entries()throws Exception{
    List<Object> confirmed=new ArrayList<>(),candidates=new ArrayList<>();Set<Address> emitted=new HashSet<>();var it=currentProgram.getSymbolTable().getAllSymbols(true);
    while(it.hasNext()){if(!visit())break;var s=it.next();if(s.isExternalEntryPoint()){if(confirmed.size()>=limit){stopped=true;break;}confirmed.add(map("address",s.getAddress().toString(),"name",s.getName(),"kind","external_entry","confirmed",true,"provenance","ghidra.symbol.external-entry-point"));emitted.add(s.getAddress());}
      else if(candidates.size()<limit&&List.of("main","_main","start","_start","WinMain","_WinMain","DllMain","_DllMain","entry","_entry").contains(s.getName()))candidates.add(map("address",s.getAddress().toString(),"name",s.getName(),"kind","named_candidate","confirmed",false,"provenance","conventional-name"));}
    candidates.add(map("address",currentProgram.getImageBase().toString(),"name","image_base","kind","image_base_candidate","confirmed",false,"provenance","program.image-base"));
    return map("entry_points",confirmed,"count",confirmed.size(),"candidates",candidates,"scan",scan(),"truncated",stopped,"semantics",map("kind","metadata","limitation","External-entry designation is Ghidra metadata, not proof of OS startup behavior; candidates are not confirmed entries."));
  }
  Object navigation()throws Exception{
    final int cap=128;int functions=0,oneByte=0,entryInstructions=0,instructions=0,references=0,data=0,strings=0;long bodyBytes=0;
    var fs=currentProgram.getFunctionManager().getFunctions(true);
    while(fs.hasNext()&&functions<cap){if(!visit())break;var f=fs.next();functions++;long size=f.getBody().getNumAddresses();bodyBytes+=size;if(size==1)oneByte++;if(currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null)entryInstructions++;}
    boolean functionsComplete=!fs.hasNext();
    var is=currentProgram.getListing().getInstructions(true);
    while(is.hasNext()&&instructions<cap){if(!visit())break;is.next();instructions++;}boolean instructionsComplete=!is.hasNext();
    var rs=currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress());
    while(rs.hasNext()&&references<cap){if(!visit())break;rs.next();references++;}boolean referencesComplete=!rs.hasNext();
    var ds=currentProgram.getListing().getDefinedData(true);
    while(ds.hasNext()&&data<cap){if(!visit())break;var d=ds.next();data++;if(d.hasStringValue())strings++;}boolean dataComplete=!ds.hasNext();
    boolean complete=functionsComplete&&instructionsComplete&&referencesComplete&&dataComplete;
    String assessment=functions>0&&oneByte*5>=functions*4&&(functions-entryInstructions)*5>=functions*4?"sparse-metadata":functions==0&&instructions==0?"no-code-observed":"observed-metadata";
    return map("functions",map("sampled",functions,"oneByteBodies",oneByte,"bodyBytes",bodyBytes,"entriesWithInstructions",entryInstructions,"complete",functionsComplete),
      "instructions",map("sampled",instructions,"complete",instructionsComplete),"references",map("sampled",references,"complete",referencesComplete),
      "definedData",map("sampled",data,"strings",strings,"complete",dataComplete),
      "scan",map("visited",visited,"maximum",maxScan,"sampleLimitPerCategory",cap,"complete",complete,"reason",complete?"exhausted":stopped?"budget":"sample_limit"),
      "assessment",assessment,"assessmentAlgorithm","one-byte-and-missing-entry-instruction-ratio-at-least-0.8-v1",
      "recommendations",assessment.equals("sparse-metadata")||assessment.equals("no-code-observed")?List.of("Treat missing stored xrefs, strings and function containment as unknown. For known function entries try functions inspect --fields decompiled_code,callees; refresh stale/failed output with functions force-decompile --function <entry>.","For executable bytes without a function entry use functions decode. These reads do not repair Listing instructions or stored xrefs.","Find undefined literals with analysis search-byte-patterns and its next_address continuation; strings search visits defined data only.","Consider an explicit bounded analysis/disassembly Update only when needed; this diagnostic does not run analyzers."):List.of("Use observed metadata for navigation; verify individual bodies and references for the question under study."),
      "coverage","At most 128 inputs per category, in address order, sharing max-scan and a five-second deadline. References are stored DB references; strings count only sampled defined data. Observations and heuristics do not prove analysis or semantic completeness.");
  }
  Object strings(boolean search)throws Exception{
    List<Object> rows=new PagedRows();String needle=str(search?"search_term":"filter","");Pattern regex=search?safeRegex(needle):null;String encoding=str("encoding","");int min=number("min_length",search?4:0,0,65536);var iter=currentProgram.getListing().getDefinedData(true);
    while(iter.hasNext()){if(!visit())break;var d=iter.next();if(!d.hasStringValue())continue;if(d.getLength()>65536){stopped=true;break;}String value=Objects.toString(d.getValue(),"");if(value.length()>8192){stopped=true;break;}String enc=d.getDataType().getName().toLowerCase(Locale.ROOT).contains("unicode")?"unicode":"ascii";
      if(value.length()<min||!encoding.isEmpty()&&!encoding.equalsIgnoreCase(enc)||search&&!regex.matcher(value).find()||!search&&!needle.isEmpty()&&!value.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT)))continue;
      rows.add(map("address",d.getAddress().toString(),"value",value.length()>8192?value.substring(0,8192):value,"value_truncated",value.length()>8192,"length",value.length(),"encoding",enc));}
    return page(search?"matches":"strings",rows);
  }
  Pattern safeRegex(String expression){
    // Preserve literal/escaped search and the common .* wildcard without nested repetition/backtracking.
    if(expression.length()>512||expression.replaceAll("\\\\.", "").matches(".*[(){}|+?].*")||expression.matches(".*\\\\[1-9].*")||expression.replaceAll("\\\\.", "").replace(".*","").contains("*"))throw new IllegalArgumentException("Search regex supports literals, escapes, anchors, character classes and .*; nested/branching quantifiers are unsupported");
    if(expression.split(Pattern.quote(".*"),-1).length>2)throw new IllegalArgumentException("At most one .* search wildcard is supported");
    return Pattern.compile(expression,Pattern.CASE_INSENSITIVE);
  }
  Object instructions()throws Exception{
    List<Object> rows=new PagedRows();String f=str("function","");var it=f.isEmpty()?currentProgram.getListing().getInstructions(true):currentProgram.getListing().getInstructions(function(f).getBody(),true);String mnemonic=str("mnemonic","").toLowerCase(Locale.ROOT),operand=str("operand_pattern","");Pattern pattern=operand.isEmpty()?null:safeRegex(operand);
    while(it.hasNext()){if(!visit())break;var i=it.next();String display=i.toString();if(!mnemonic.isEmpty()&&!i.getMnemonicString().equalsIgnoreCase(mnemonic)||pattern!=null&&!pattern.matcher(display).find())continue;rows.add(map("address",i.getAddress().toString(),"mnemonic",i.getMnemonicString(),"instruction",display,"length",i.getLength()));}return page("matches",rows);
  }
  Object dead()throws Exception{
    var f=function(str("function_name",""));var model=new BasicBlockModel(currentProgram);var iterator=model.getCodeBlocksContaining(f.getBody(),boundedMonitor);Map<Address,CodeBlock> blocks=new LinkedHashMap<>();
    while(iterator.hasNext()){if(!visit())break;var block=iterator.next();blocks.put(block.getFirstStartAddress(),block);}
    Set<Address> reachable=new HashSet<>();Deque<Address> work=new ArrayDeque<>();CodeBlock first=model.getFirstCodeBlockContaining(f.getEntryPoint(),boundedMonitor);if(first!=null)work.add(first.getFirstStartAddress());boolean unresolved=first==null||!blocks.containsKey(first.getFirstStartAddress());
    while(!work.isEmpty()&&!stopped){var at=work.removeFirst();if(!reachable.add(at))continue;var block=blocks.get(at);if(block==null)continue;var refs=block.getDestinations(boundedMonitor);
      while(refs.hasNext()){if(!visit())break;var ref=refs.next();if(ref.getFlowType().isCall())continue;var dest=ref.getDestinationAddress();if(ref.getFlowType().isComputed())unresolved=true;if(dest!=null&&f.getBody().contains(dest)){var target=model.getFirstCodeBlockContaining(dest,boundedMonitor);if(target!=null)work.add(target.getFirstStartAddress());else unresolved=true;}}
      var last=currentProgram.getListing().getInstructionAt(block.getMaxAddress());if(last==null)last=currentProgram.getListing().getInstructionContaining(block.getMaxAddress());if(last!=null&&last.getFlowType().isComputed()&&last.getFlowType().isJump())unresolved=true;
    }
    List<Object> findings=new PagedRows();if(!stopped&&!unresolved)for(var entry:blocks.entrySet())if(!reachable.contains(entry.getKey()))findings.add(map("address",entry.getKey().toString(),"end",entry.getValue().getMaxAddress().toString(),"size",entry.getValue().getNumAddresses(),"kind","unreachable-in-static-cfg"));
    var out=page("findings",findings);out.put("function_name",f.getName());out.put("address",f.getEntryPoint().toString());out.put("algorithm","static-basic-block-reachability-v1");out.put("complete",!stopped&&!unresolved);out.put("unresolved_flow",unresolved);out.put("blocks",blocks.size());out.put("reachable_blocks",reachable.size());out.put("limitations",List.of("Static CFG only; indirect unresolved flow suppresses unreachable conclusions.","Only instructions in the selected function body are classified; not a proof about runtime execution."));return out;
  }
  byte[] hex(String value){return java.util.HexFormat.of().parseHex(value.replace(" ",""));}
  Object bytes(boolean crypto)throws Exception{
    Map<String,byte[]> signatures=new LinkedHashMap<>();String database="insight-constant-tables-v1";
    if(crypto){
      signatures.put("AES-SBOX",hex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16".replace(" ","")));
      signatures.put("SHA256-IV-BE",hex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"));
      signatures.put("SHA1-IV-BE",hex("67452301efcdab8998badcfe10325476c3d2e1f0"));
      signatures.put("MD5-IV-BE",hex("67452301efcdab8998badcfe10325476"));
      signatures.put("ChaCha-sigma", "expand 32-byte k".getBytes(StandardCharsets.US_ASCII));
      for(String name:List.copyOf(signatures.keySet()))if(name.endsWith("-BE")){byte[] b=signatures.get(name).clone();for(int i=0;i<b.length;i+=4)for(int j=0;j<2;j++){byte t=b[i+j];b[i+j]=b[i+3-j];b[i+3-j]=t;}signatures.put(name.replace("-BE","-LE"),b);}
    }else {String pattern=str("pattern","").replaceAll("\\s","");if(pattern.isEmpty()||pattern.length()%2!=0||pattern.length()>1024)throw new IllegalArgumentException("Pattern must contain 1..512 hex byte pairs");byte[] values=new byte[pattern.length()/2],masks=new byte[values.length];String mask=str("mask","");for(int i=0;i<values.length;i++){String pair=pattern.substring(2*i,2*i+2);if(pair.equals("??")){masks[i]=0;values[i]=0;}else {values[i]=hex(pair)[0];masks[i]=(byte)255;}}if(!mask.isEmpty()){if(mask.length()!=values.length)throw new IllegalArgumentException("Mask length must equal pattern byte count");for(int i=0;i<masks.length;i++){if(mask.charAt(i)=='?')masks[i]=0;else if(mask.charAt(i)!='x'&&mask.charAt(i)!='X')throw new IllegalArgumentException("Mask uses x or ?");}}signatures.put("pattern",values);this.patternMasks=masks;}
    int maxBytes=number("max_bytes",1048576,1,16777216),scanned=0;String from=str("scan_from","");Address start=from.isEmpty()?null:address(from),next=null;List<Object> matches=new PagedRows();boolean done=true;
    var blocks=currentProgram.getMemory().getBlocks();Arrays.sort(blocks,Comparator.comparing(MemoryBlock::getStart));
    int longest=signatures.values().stream().mapToInt(v->v.length).max().orElse(1);
    outer:for(var block:blocks){
      if(!block.isInitialized())continue;Address at=block.getStart();if(start!=null){if(block.getEnd().compareTo(start)<0)continue;if(at.compareTo(start)<0)at=start;}
      if(scanned>=maxBytes||!visit()){next=at;done=false;break;}
      long available=block.getEnd().subtract(at)+1;int count=(int)Math.min(available,maxBytes-scanned);byte[] data=new byte[count];int read=currentProgram.getMemory().getBytes(at,data);if(read!=count)throw new IllegalStateException("Incomplete initialized-memory read");scanned+=read;
      // Stop before a truncated lookahead tail. The continuation resumes at its first unchecked start.
      int positions=count==available?count:Math.max(0,count-longest+1);
      for(int i=0;i<positions;i++){
        if(i%256==0&&!visit()){next=at.add(i);done=false;break outer;}
        List<String> names=new ArrayList<>();int length=0;
        for(var signature:signatures.entrySet()){byte[] pattern=signature.getValue();if(i+pattern.length>data.length)continue;boolean equal=true;for(int j=0;j<pattern.length;j++){if(patternMasks!=null&&patternMasks[j]==0)continue;if(data[i+j]!=pattern[j]){equal=false;break;}}if(equal){names.add(signature.getKey());length=Math.max(length,pattern.length);}}
        if(!names.isEmpty()){matches.add(map("address",at.add(i).toString(),"signature",names.getFirst(),"signatures",names,"length",length,"kind",crypto?"constant-table-match":"byte-pattern-match"));if(((PagedRows)matches).total>=offset+limit){next=at.add(i+1);done=false;break outer;}}
      }
      if(count<available){next=at.add(positions);done=false;break;}
    }
    stopped=!done;var out=page("matches",matches);out.put("complete",done);out.put("scanned_bytes",scanned);out.put("maximum_bytes",maxBytes);out.put("next_address",next==null?null:next.toString());out.put("algorithm",crypto?"exact-constant-table-match":"masked-byte-search");
    if(crypto){out.put("database",map("version",database,"signatures",signatures.entrySet().stream().map(e->map("name",e.getKey(),"length",e.getValue().length)).toList()));out.put("limitations",List.of("An exact constant match is a candidate, not proof that cryptography executes.","Only the versioned signature catalog and the returned scan range were checked; increase the byte budget if a continuation cannot advance."));}return out;
  }

  byte[] patternMasks;
  Object decodeInstructions()throws Exception{
    Address start=address(str("address",""));int maximum=number("max_bytes",64,1,4096),maxInstructions=number("max_instructions",16,1,256);
    String language=currentProgram.getLanguageID().toString();
    // Other processors may require mode propagation or delay-slot handling. Fail explicitly
    // until those semantics have their own native acceptance; never fall back to an Update API.
    if(!currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86"))throw new UnsupportedOperationException("Read-only decode currently supports x86 languages only; language/context unavailable: "+language);
    MemoryBlock block=currentProgram.getMemory().getBlock(start);
    if(block==null||!block.isInitialized()||!block.isExecute())throw new IllegalArgumentException("Decode requires initialized executable memory");
    int available=(int)Math.min(maximum,block.getEnd().subtract(start)+1);byte[] input=new byte[available];
    if(currentProgram.getMemory().getBytes(start,input)!=available)throw new IllegalStateException("Incomplete executable memory read");
    var decoder=new ghidra.app.util.PseudoDisassembler(currentProgram);List<Object> rows=new ArrayList<>();int consumed=0;String reason="byte_limit";
    while(consumed<input.length&&rows.size()<maxInstructions){
      boundedMonitor.checkCancelled();Address at=start.addNoWrap(consumed);ghidra.app.util.PseudoInstruction instruction;
      try{instruction=decoder.disassemble(at,Arrays.copyOfRange(input,consumed,input.length));}
      catch(ghidra.program.model.lang.InsufficientBytesException error){reason="truncated_instruction";break;}
      catch(ghidra.program.model.lang.UnknownInstructionException error){reason="undecodable";break;}
      catch(ghidra.program.model.lang.UnknownContextException error){reason="context_unavailable";break;}
      if(instruction==null){reason="undecodable";break;}
      int length=instruction.getLength();if(length<1||length>input.length-consumed){reason="truncated_instruction";break;}
      List<String> operands=new ArrayList<>();for(int i=0;i<instruction.getNumOperands();i++)operands.add(instruction.getDefaultOperandRepresentation(i));
      var flow=instruction.getFlowType();List<String> targets=new ArrayList<>();
      if(!flow.isComputed())for(Address target:instruction.getFlows())if(target!=null&&!target.equals(Address.NO_ADDRESS))targets.add(target.toString());
      rows.add(map("address",at.toString(),"bytes",HexFormat.of().formatHex(Arrays.copyOfRange(input,consumed,consumed+length)),"length",length,"mnemonic",instruction.getMnemonicString(),"operands",operands,"direct_targets",targets,"flow",flow.toString(),"computed_flow",flow.isComputed()));
      consumed+=length;
      if(flow.isTerminal()){reason="terminal_flow";break;}
      if(flow.isJump()&&!flow.isConditional()){reason="control_flow";break;}
    }
    if(consumed<input.length&&rows.size()==maxInstructions&&reason.equals("byte_limit"))reason="instruction_limit";
    if(consumed==input.length&&available<maximum&&reason.equals("byte_limit"))reason="executable_block_end";
    return map("address",start.toString(),"language",language,"compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),"input_bytes",HexFormat.of().formatHex(input),"input_sha256",HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(input)),"maximum_bytes",maximum,"maximum_instructions",maxInstructions,"instructions",rows,"consumed_bytes",consumed,"stop_reason",reason,"truncated",List.of("byte_limit","instruction_limit","truncated_instruction","executable_block_end").contains(reason),"semantics","Linear pseudo instructions in the selected program context; direct targets are computed from bytes, not function membership or stored xrefs.");
  }
  Object execute(String operation)throws Exception{return switch(operation){case "/navigation_diagnostic"->navigation();case "/research_view"->map("modification",Long.toString(currentProgram.getModificationNumber()),"language",currentProgram.getLanguageID().toString(),"compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString());case "/decode_instructions"->decodeInstructions();case "/find_dead_code"->dead();case "/detect_crypto_constants"->bytes(true);case "/search_byte_patterns"->bytes(false);case "/get_valid_data_types"->types(true);case "/find_data_types"->types(false);case "/validate_data_type"->validateType();case "/validate_function_prototype"->validatePrototype();case "/get_entry_points"->entries();case "/list_globals"->globals();case "/list_strings"->strings(false);case "/search_strings"->strings(true);case "/search_instructions"->instructions();default->throw new IllegalArgumentException("Unknown native query");};}
  public void run()throws Exception{
    var request=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();p=request.getAsJsonObject("parameters");maxScan=number("max_scan",100000,1,200000);limit=number("limit",100,1,1000);offset=number("offset",0,0,2000000);deadline=System.nanoTime()+number("timeout_seconds",5,1,30)*1000000000L;
    boundedMonitor=TimeoutTaskMonitor.timeoutIn(number("timeout_seconds",5,1,30),TimeUnit.SECONDS,monitor);
    Map<String,Object> result;long modification=currentProgram.getModificationNumber();try{
      Object value=execute(request.get("operation").getAsString());
      if(currentProgram.getModificationNumber()!=modification)throw new IllegalStateException("Read-only query changed the program modification counter");
      if(value instanceof Map<?,?>)((Map<String,Object>)value).put("read_only",map("modification_unchanged",true,"modification",Long.toString(modification)));result=map("value",value);
    }catch(Exception error){result=map("error",map("code",error instanceof UnsupportedOperationException?"unsupported":error instanceof IllegalArgumentException?"invalid":"partial","message",Objects.toString(error.getMessage(),"Native query failed")));}
    finally{boundedMonitor.finished();if(temporaryTypes!=null){temporaryTypes.endTransaction(temporaryTransaction,false);temporaryTypes.close();}}

    println("INSIGHT_QUERY:"+new GsonBuilder().serializeNulls().create().toJson(result));
  }
}
