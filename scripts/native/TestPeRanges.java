import com.eyeauras.insight.InsightPeRanges;
import java.math.BigInteger;
import java.util.*;
import java.util.function.LongSupplier;

/** Synthetic current memory oracle, no filesystem/program source fallback. */
public class TestPeRanges {
 static BigInteger B=new BigInteger("180000000",16);static int checks;
 static void check(boolean x,String why){checks++;if(!x)throw new AssertionError(why);}
 static class M implements InsightPeRanges.Bytes {
  byte[] data=new byte[0x8000];int read;List<InsightPeRanges.Span> spans=new ArrayList<>();
  M(){spans.add(new InsightPeRanges.Span(B,B.add(BigInteger.valueOf(data.length)),true));u16(0,0x5a4d);u32(60,0x80);u32(0x80,0x4550);u16(0x84,0x8664);u16(0x94,240);u16(0x98,0x20b);u32(0x98+56,data.length);u32(0x98+60,0x400);u32(0x98+108,16);u32(0x98+136,0x3000);u32(0x98+140,24);record(0,0x1000,0x1020,0x2000);record(1,0x1020,0x1040,0x2000);}
  void u16(int n,int x){data[n]=(byte)x;data[n+1]=(byte)(x>>8);}
  void u32(int n,long x){for(int i=0;i<4;i++)data[n+i]=(byte)(x>>(8*i));}
  void record(int i,long a,long b,long u){u32(0x3000+i*12,a);u32(0x3004+i*12,b);u32(0x3008+i*12,u);}
  public int read(BigInteger at,byte[] out){int n=at.subtract(B).intValueExact();System.arraycopy(data,n,out,0,out.length);read+=out.length;return out.length;}
 }
 static InsightPeRanges.Result run(M m,int max,LongSupplier clock,BigInteger base,String...selectors)throws Exception {
  var r=new InsightPeRanges(base,m.spans,m,max,clock,Arrays.stream(selectors).map(x->B.add(new BigInteger(x,16))).toList()).run();check(r.lookup().get("bytesRead").equals(m.read),"exact physical accounting");return r;
 }
 static InsightPeRanges.Result run(M m,String...selectors)throws Exception{return run(m,4194304,System::nanoTime,B,selectors);}
 static void bad(M m,String state,String reason)throws Exception {var r=run(m,"1008");check(r.lookup().get("state").equals(state),"state "+r.lookup());check(r.lookup().get("reason").equals(reason),"reason "+r.lookup());check(r.ranges().isEmpty(),"No candidate leaked before full validation");}
 public static void main(String[] args)throws Exception {
  var m=new M();var r=run(m,"1000","101f","1020","1040","1200");check(r.lookup().get("complete").equals(true),"complete full table");check(r.ranges().size()==2,"half open adjacent and leaf misses");check(r.ranges().get(1).begin().equals(B.add(BigInteger.valueOf(0x1020))),"adjacent start");check(r.lookup().get("recordsValidated").equals(2),"whole table count");check(r.lookup().get("bytesRead").equals(232),"headers208 + table24");
  m=new M();m.record(1,0x1010,0x1040,0x2000);bad(m,"malformed","unordered_or_overlapping_ranges");
  m=new M();m.record(1,0x1000,0x1020,0x2000);bad(m,"malformed","unordered_or_overlapping_ranges");
  m=new M();m.record(1,0x800,0x900,0x2000);bad(m,"malformed","unordered_or_overlapping_ranges");
  m=new M();m.record(1,0x1040,0x1040,0x2000);bad(m,"malformed","invalid_runtime_range");
  m=new M();m.record(1,0x1040,0x9000,0x2000);bad(m,"malformed","invalid_runtime_range");
  m=new M();m.record(1,0x1040,0x1080,0x2001);bad(m,"malformed","invalid_unwind_rva");
  m=new M();m.u32(0x98+140,23);bad(m,"malformed","invalid_exception_directory");
  m=new M();m.u32(0x98+136,0);bad(m,"malformed","invalid_exception_directory");
  m=new M();m.u32(0x98+136,0xfffffff0L);bad(m,"malformed","invalid_exception_directory");
  m=new M();m.u32(60,0x10);bad(m,"malformed","invalid_pe_offset");
  m=new M();m.u16(0x94,112);m.u32(0x98+108,0);r=run(m,"1008");check(r.lookup().get("state").equals("absent"),"short optional header with no directory supported");
  m=new M();m.u16(0x84,0x14c);bad(m,"unavailable","unsupported_machine");
  m=new M();m.u16(0x98,0x10b);bad(m,"unavailable","unsupported_optional_header");
  m=new M();m.spans.clear();bad(m,"unavailable","headers_not_mapped");
  m=new M();m.spans=List.of(new InsightPeRanges.Span(B,B.add(BigInteger.valueOf(0x3000)),true));bad(m,"unavailable","table_not_mapped");
  m=new M();m.spans=List.of(new InsightPeRanges.Span(B,B.add(BigInteger.valueOf(0x1010)),true),new InsightPeRanges.Span(B.add(BigInteger.valueOf(0x1011)),B.add(BigInteger.valueOf(0x8000)),true));bad(m,"unavailable","runtime_range_not_initialized_executable");
  m=new M();m.spans=List.of(new InsightPeRanges.Span(B,B.add(BigInteger.valueOf(0x1000)),false),new InsightPeRanges.Span(B.add(BigInteger.valueOf(0x1000)),B.add(BigInteger.valueOf(0x1020)),true),new InsightPeRanges.Span(B.add(BigInteger.valueOf(0x1020)),B.add(BigInteger.valueOf(0x8000)),false));bad(m,"unavailable","runtime_range_not_initialized_executable");
  m=new M();m.spans=List.of(new InsightPeRanges.Span(B,B.add(BigInteger.valueOf(0x1010)),true),new InsightPeRanges.Span(B.add(BigInteger.valueOf(0x1010)),B.add(BigInteger.valueOf(0x8000)),true));check(run(m,"1008").lookup().get("complete").equals(true),"adjacent eligible blocks accepted");
  m=new M();m.u32(0x98+136,0);m.u32(0x98+140,0);r=run(m,"1008");check(r.lookup().get("state").equals("absent")&&Boolean.TRUE.equals(r.lookup().get("complete")),"validated missing directory");
  m=new M();r=run(m,1,System::nanoTime,B,"1008");check(r.lookup().get("reason").equals("byte_limit")&&r.ranges().isEmpty(),"tiny cap yields unknown");
  m=new M();r=run(m,220,System::nanoTime,B,"1008");check(r.lookup().get("reason").equals("byte_limit")&&r.lookup().get("recordsValidated").equals(0),"no partial table candidates");
  m=new M();long[] t={0};r=run(m,4194304,()->(t[0]+=1_000_000_000),B,"1008");check(r.lookup().get("reason").equals("timeout")&&!Boolean.TRUE.equals(r.lookup().get("complete")),"cooperative deadline explicit");
  m=new M(){@Override public int read(BigInteger at,byte[] out){int got=super.read(at,out);read--;return got-1;}};bad(m,"unavailable","short_read");
  m=new M();r=run(m,4194304,System::nanoTime,new BigInteger("fffffffffffff000",16),"1008");check(r.lookup().get("state").equals("unavailable"),"out of space mapped header unavailable");
  BigInteger old=B;B=BigInteger.ONE.shiftLeft(64).subtract(BigInteger.valueOf(0x8000));m=new M();m.record(1,0x1020,0x8000,0x2000);r=run(m,"7fff");check(r.ranges().getFirst().endExclusive().equals(BigInteger.ONE.shiftLeft(64)),"U64 exclusive endpoint accepted");B=old;
  B=new BigInteger("7ff600000000",16);m=new M();r=run(m,"1008");check(r.ranges().getFirst().begin().equals(B.add(BigInteger.valueOf(0x1000))),"rebased current program base");B=old;
  System.out.println("PE runtime range core PASS; assertions="+checks);
 }
}
