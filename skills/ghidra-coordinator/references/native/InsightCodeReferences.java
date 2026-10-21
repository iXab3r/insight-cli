import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded candidate discovery only. Never creates instructions, functions or references. */
public class InsightCodeReferences extends GhidraScript {
  static final String ALGORITHM="x86-64-code-reference-candidates-v1";
  static final List<String> FORMS=List.of("call-rel32","lea-rip","mov-rip","call-rip-slot");
  JsonObject p; long deadline,started; int bytesRead,tested,visited,maxBytes,maxCandidates,limit;
  String reason="exhausted"; Address next; Set<Address> targets=new HashSet<>(); List<String> forms=new ArrayList<>();
  List<Object> matches=new ArrayList<>();
  Map<String,Object> map(Object... pairs){Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)m.put((String)pairs[i],pairs[i+1]);return m;}
  int number(String k,int d,int min,int max){int v=p.has(k)?p.get(k).getAsInt():d;if(v<min||v>max)throw new IllegalArgumentException(k+" outside supported bounds");return v;}
  Address address(String s){if(!s.matches("[a-fA-F0-9]{1,16}"))throw new IllegalArgumentException("Default-space 64-bit hexadecimal address required");return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(s,16));}
  String hex(Address a){return Long.toUnsignedString(a.getOffset(),16);}
  boolean expired()throws Exception{monitor.checkCancelled();return System.nanoTime()>=deadline;}
  record Encoding(String form,int length,int operand,int bits,int delta,String role){}
  Encoding encoding(byte[] b,int start){
    int i=start,rex=0;boolean word=false;
    while(i<b.length&&i-start<15){int v=b[i]&255;if(v==0x66||v==0x26||v==0x2e||v==0x36||v==0x3e){word|=v==0x66;rex=0;i++;}else if(v>=0x40&&v<=0x4f){rex=v;i++;}else break;}
    if(i>=b.length)return null;int op=b[i]&255,length,disp,operand,bits;String form,role;
    if(op==0xe8){form="call-rel32";role="direct-call-target";length=i-start+5;disp=i+1;operand=0;bits=64;}
    else{
      if(i+1>=b.length)return null;int m=b[i+1]&255;if((m&0xc7)!=5)return null;
      if(op==0x8d){form="lea-rip";operand=1;}
      else if(op==0x88||op==0x89||op==0x8a||op==0x8b){form="mov-rip";operand=op==0x88||op==0x89?0:1;}
      else if(op==0xff&&((m>>3)&7)==2){form="call-rip-slot";operand=0;}
      else return null;
      role=form.equals("call-rip-slot")?"pointer-slot":"effective-address";
      length=i-start+6;disp=i+2;bits=form.equals("call-rip-slot")?64:op==0x88||op==0x8a?8:(rex&8)!=0?64:word?16:32;
    }
    if(length>15||start+length>b.length)return null;
    int delta=(b[disp]&255)|((b[disp+1]&255)<<8)|((b[disp+2]&255)<<16)|(b[disp+3]<<24);
    return new Encoding(form,length,operand,bits,delta,role);
  }
  boolean compatible(PseudoInstruction i,Encoding e,Address target){
    if(i==null||i.getLength()!=e.length)return false;
    if(e.form.equals("call-rel32"))return i.getMnemonicString().equalsIgnoreCase("CALL")&&i.getFlowType().isCall()&&!i.getFlowType().isComputed()&&Arrays.asList(i.getFlows()).contains(target);
    if(e.form.equals("call-rip-slot"))return i.getMnemonicString().equalsIgnoreCase("CALL")&&i.getFlowType().isCall()&&i.getFlowType().isComputed();
    if(!i.getMnemonicString().equalsIgnoreCase(e.form.equals("lea-rip")?"LEA":"MOV"))return false;
    var register=i.getRegister(e.operand==0?1:0);return register!=null&&register.getBitLength()==e.bits;
  }
  String boundary(Address at,PseudoInstruction decoded,byte[] bytes)throws Exception{
    var listing=currentProgram.getListing();var stored=listing.getInstructionContaining(at);
    if(stored==null){var after=listing.getInstructionAfter(at);return after!=null&&after.getAddress().compareTo(at.addNoWrap(bytes.length-1))<=0?"listing-conflict":"unconfirmed";}
    if(!stored.getAddress().equals(at)||stored.getLength()!=decoded.getLength()||!Arrays.equals(stored.getBytes(),bytes)||!stored.getMnemonicString().equals(decoded.getMnemonicString())||stored.getNumOperands()!=decoded.getNumOperands())return "listing-conflict";
    for(int i=0;i<stored.getNumOperands();i++)if(!stored.getDefaultOperandRepresentation(i).equals(decoded.getDefaultOperandRepresentation(i)))return "listing-conflict";
    return "listing-confirmed";
  }
  Object scan()throws Exception{
    if(!currentProgram.getLanguageID().toString().startsWith("x86:LE:64:")||currentProgram.getAddressFactory().getDefaultAddressSpace().getSize()!=64)throw new UnsupportedOperationException("Code references V1 requires x86-64 little-endian default memory space");
    var mode=currentProgram.getRegister("longMode");if(mode==null)throw new UnsupportedOperationException("64-bit decode mode is unavailable");
    Address from=address(p.get("scan_from").getAsString()),through=address(p.get("scan_through").getAsString());if(from.compareTo(through)>0)throw new IllegalArgumentException("Inverted scan range");
    var ts=p.getAsJsonArray("targets");if(ts.size()<1||ts.size()>64)throw new IllegalArgumentException("Select 1..64 targets");for(var t:ts)if(!targets.add(address(t.getAsString())))throw new IllegalArgumentException("Duplicate target");
    var fs=p.getAsJsonArray("forms");for(String f:FORMS)for(var v:fs)if(f.equals(v.getAsString()))forms.add(f);if(forms.isEmpty()||new HashSet<>(forms).size()!=fs.size()||forms.size()!=fs.size())throw new IllegalArgumentException("Unsupported or duplicate form");
    maxBytes=number("max_bytes",4194304,15,16777216);maxCandidates=number("max_candidates",200000,1,1000000);limit=number("limit",100,1,1000);
    started=System.nanoTime();deadline=started+number("timeout_seconds",5,1,30)*1000000000L;
    List<Address[]> runs=new ArrayList<>();var blocks=currentProgram.getMemory().getBlocks();Arrays.sort(blocks,Comparator.comparing(MemoryBlock::getStart));
    for(var block:blocks){
      if(expired()){reason="timeout";next=from;return result(from,through);}
      if(!block.isInitialized()||!block.isExecute()||!block.getStart().getAddressSpace().equals(from.getAddressSpace())||block.getEnd().compareTo(from)<0||block.getStart().compareTo(through)>0)continue;
      Address a=block.getStart().compareTo(from)<0?from:block.getStart(),z=block.getEnd().compareTo(through)>0?through:block.getEnd();
      if(!runs.isEmpty()&&a.equals(runs.getLast()[1].next()))runs.getLast()[1]=z;
      else runs.add(new Address[]{a,z});
    }
    var decoder=new PseudoDisassembler(currentProgram);
    outer:for(int runIndex=0;runIndex<runs.size();runIndex++){
      var run=runs.get(runIndex);Address at=run[0];
      while(at.compareTo(run[1])<=0){
        next=at;
        if(expired()){reason="timeout";break outer;}
        int remaining=maxBytes-bytesRead;long available=run[1].subtract(at)+1;
        if(remaining<Math.min(15,available)){reason="byte_limit";break outer;}
        int count=(int)Math.min(Math.min(65550,available),remaining);byte[] data=new byte[count];
        if(currentProgram.getMemory().getBytes(at,data)!=count)throw new IllegalStateException("Incomplete initialized executable memory read");bytesRead+=count;
        int positions=count==available?count:count-14;
        for(int i=0;i<positions;i++){
          Address here=at.addNoWrap(i);next=here;
          if(expired()){reason="timeout";break outer;}
          Encoding e=encoding(data,i);
          if(e!=null&&forms.contains(e.form)){
            if(visited==maxCandidates){reason="candidate_limit";break outer;}
            var modeValue=currentProgram.getProgramContext().getValue(mode,here,false);
            if(modeValue==null||!modeValue.equals(java.math.BigInteger.ONE))throw new UnsupportedOperationException("Candidate encountered outside known 64-bit decode mode");
            visited++;
            Address target=here.addWrap(e.length+(long)e.delta);
            if(targets.contains(target)){
              PseudoInstruction instruction=null;
              try{instruction=decoder.disassemble(here,Arrays.copyOfRange(data,i,Math.min(data.length,i+15)));}
              catch(ghidra.program.model.lang.InsufficientBytesException|ghidra.program.model.lang.UnknownInstructionException ignored){}
              catch(ghidra.program.model.lang.UnknownContextException error){throw new UnsupportedOperationException("Native decoder context unavailable");}
              if(compatible(instruction,e,target)){
                byte[] bytes=Arrays.copyOfRange(data,i,i+e.length);String display=instruction.toString();
                matches.add(map("from",hex(here),"to",hex(target),"form",e.form,"bytes",HexFormat.of().formatHex(bytes),"length",e.length,"operand_index",e.operand,"operand_bits",e.bits,"target_role",e.role,"validation","decoded","boundary",boundary(here,instruction,bytes),"instruction",display.substring(0,Math.min(512,display.length()))));
              }
            }
          }
          tested++;
          if(here.equals(through)||here.equals(run[1])&&runIndex==runs.size()-1)next=null;
          else next=here.addNoWrap(1);
          if(matches.size()==limit&&next!=null){reason="result_limit";break outer;}
        }
        if(positions==available)break;
        at=at.addNoWrap(positions);
      }
    }
    if(reason.equals("exhausted"))next=null;
    return result(from,through);
  }
  Object result(Address from,Address through){return map("algorithm",ALGORITHM,"language",currentProgram.getLanguageID().toString(),"forms",forms,"matches",matches,
    "scan",map("from",hex(from),"through",hex(through),"next_start",next==null?null:hex(next),"complete",reason.equals("exhausted"),"reason",reason,"bytes_read",bytesRead,"tested_starts",tested,"visited_candidates",visited,"elapsed_ms",(System.nanoTime()-started)/1000000.0),
    "coverage","Every byte start in initialized executable default-space memory, in address order; adjacent eligible blocks merge. Instructions fit entirely within the requested range. Overlapping decodes are separate candidates.",
    "limitations",List.of("Decoded byte candidates do not prove instruction boundaries, execution or callgraph membership.","Indirect CALL targets identify pointer slots; pointees are never followed.","Only explicit V1 encodings; 67, FS/GS, LOCK/REP, SIMD and immediate MOV encodings are excluded at that start. A later start inside their bytes may still be a candidate."));}
  public void run()throws Exception{
    Map<String,Object> output;long modification=currentProgram.getModificationNumber();
    try{
      var request=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
      if(!request.get("operation").getAsString().equals("/code_references"))throw new IllegalArgumentException("Unknown code-reference operation");p=request.getAsJsonObject("parameters");
      var value=(Map<String,Object>)scan();if(currentProgram.getModificationNumber()!=modification)throw new IllegalStateException("Read-only scan changed program modification counter");
      value.put("read_only",map("modification_unchanged",true,"modification",Long.toString(modification)));output=map("value",value);
    }catch(Exception error){output=map("error",map("code",error instanceof UnsupportedOperationException?"unsupported":error instanceof IllegalArgumentException?"invalid":"partial","message",Objects.toString(error.getMessage(),"Native code-reference scan failed")));}
    println("INSIGHT_QUERY:"+new GsonBuilder().serializeNulls().create().toJson(output));
  }
}
