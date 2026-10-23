package com.eyeauras.insight;

import java.math.BigInteger;
import java.util.*;
import java.util.function.LongSupplier;

/** Current mapped PE32+/AMD64 runtime regions, never semantic function reconstruction. */
public final class InsightPeRanges {
  public record Span(BigInteger begin,BigInteger endExclusive,boolean execute) {}
  public interface Bytes { int read(BigInteger at,byte[] out)throws Exception; }
  public record Range(BigInteger begin,BigInteger endExclusive,BigInteger recordAddress) {
    public Map<String,Object> facts(){return Map.of("source","pe-exception-directory","begin",begin.toString(16),"endExclusive",endExclusive.toString(16),"tableRecordAddress",recordAddress.toString(16),"semanticMembership","not-established","instructionBoundary","not-checked","unwindInfo","not-parsed");}
  }
  public record Result(Map<String,Object> lookup,List<Range> ranges) {}
  private static final BigInteger U64=BigInteger.ONE.shiftLeft(64);
  private final List<BigInteger> addresses;
  private final BigInteger base;private final List<Span> spans;private final Bytes memory;private final LongSupplier clock;private final int maximum;private final long start;
  private int bytesRead=0,recordsValidated=0;private long recordCount=0;
  private static final class Stop extends Exception {final String state,reason;Stop(String s,String r){state=s;reason=r;}}
  public InsightPeRanges(BigInteger base,List<Span> spans,Bytes memory,int maximum,LongSupplier clock,List<BigInteger> addresses){
    this(base,spans,memory,maximum,clock,addresses,clock.getAsLong());
  }
  public InsightPeRanges(BigInteger base,List<Span> spans,Bytes memory,int maximum,LongSupplier clock,List<BigInteger> addresses,long started){
    if(base.signum()<0||base.compareTo(U64)>=0||maximum<1||maximum>16777216)throw new IllegalArgumentException("Invalid PE lookup bounds");
    if(addresses.size()>20)throw new IllegalArgumentException("At most 20 addresses");this.addresses=List.copyOf(addresses);
    start=started;this.base=base;this.spans=spans.stream().sorted(Comparator.comparing(Span::begin)).toList();this.memory=memory;this.maximum=maximum;this.clock=clock;
  }
  private void tick()throws Stop {if(clock.getAsLong()-start>=5_000_000_000L)throw new Stop("incomplete","timeout");}
  private boolean mapped(BigInteger at,long length,boolean execute)throws Stop {
    BigInteger end=at.add(BigInteger.valueOf(length));if(length<1||at.signum()<0||end.compareTo(U64)>0)return false;
    BigInteger cursor=at;
    for(Span s:spans){tick();if(s.endExclusive.compareTo(cursor)<=0)continue;if(s.begin.compareTo(cursor)>0)return false;if(execute&&!s.execute)return false;cursor=s.endExclusive.min(end);if(cursor.equals(end))return true;}
    return false;
  }
  private byte[] read(BigInteger at,int length,String missing)throws Exception {
    tick();if(length>maximum-bytesRead)throw new Stop("incomplete","byte_limit");
    if(!mapped(at,length,false))throw new Stop("unavailable",missing);
    byte[] out=new byte[length];int got;
    try{got=memory.read(at,out);}catch(Exception e){throw new Stop("unavailable","memory_read_failed");}
    // A failed/short read never establishes absence. Charge every reported physical byte.
    if(got<0||got>length)throw new IllegalStateException("Invalid native byte count");bytesRead+=got;
    if(got!=length)throw new Stop("unavailable","short_read");tick();return out;
  }
  private static int u16(byte[] a,int i){return (a[i]&255)|((a[i+1]&255)<<8);}
  private static long u32(byte[] a,int i){return Integer.toUnsignedLong((a[i]&255)|((a[i+1]&255)<<8)|((a[i+2]&255)<<16)|((a[i+3]&255)<<24));}
  private void valid(boolean condition,String reason)throws Stop {if(!condition)throw new Stop("malformed",reason);}
  private BigInteger rva(long offset,long size)throws Stop {valid(offset>0&&size>0&&offset+size<=0x1_0000_0000L,"invalid_rva");BigInteger at=base.add(BigInteger.valueOf(offset));valid(at.add(BigInteger.valueOf(size)).compareTo(U64)<=0,"address_overflow");return at;}
  public Result run()throws Exception {
    List<Range> ranges=new ArrayList<>();String state="validated",reason="validated";
    try{
      byte[] dos=read(base,64,"headers_not_mapped");valid(u16(dos,0)==0x5a4d,"invalid_dos_signature");long pe=u32(dos,60);valid(pe>=64,"invalid_pe_offset");
      byte[] header=read(base.add(BigInteger.valueOf(pe)),24,"headers_not_mapped");valid(u32(header,0)==0x4550,"invalid_pe_signature");
      if(u16(header,4)!=0x8664)throw new Stop("unavailable","unsupported_machine");
      int optionalSize=u16(header,20);valid(optionalSize>=112,"short_optional_header");
      byte[] optional=read(base.add(BigInteger.valueOf(pe+24)),112,"headers_not_mapped");
      if(u16(optional,0)!=0x20b)throw new Stop("unavailable","unsupported_optional_header");
      long imageSize=u32(optional,56),headerSize=u32(optional,60),directories=u32(optional,108);
      valid(imageSize>0&&headerSize>=pe+24+optionalSize&&headerSize<=imageSize,"invalid_image_headers");
      valid(directories<=(optionalSize-112)/8,"short_optional_header");
      valid(base.add(BigInteger.valueOf(imageSize)).compareTo(U64)<=0,"address_overflow");
      if(!mapped(base,pe+24+optionalSize,false))throw new Stop("unavailable","headers_not_mapped");
      if(directories<4){state="absent";reason="no_exception_directory";}
      else{
        byte[] directory=read(base.add(BigInteger.valueOf(pe+24+136)),8,"headers_not_mapped");
        long table=u32(directory,0),size=u32(directory,4);
        if(table==0&&size==0){state="absent";reason="no_exception_directory";}
        else{
          valid(table>0&&size>0&&size%12==0&&table%4==0&&table+size<=imageSize,"invalid_exception_directory");
          recordCount=size/12;BigInteger tableAt=rva(table,size);long previousEnd=0;
          for(long offset=0;offset<size;){
            tick();int length=(int)Math.min(4092,size-offset);byte[] chunk=read(tableAt.add(BigInteger.valueOf(offset)),length,"table_not_mapped");
            for(int i=0;i<length;i+=12){
              tick();long begin=u32(chunk,i),end=u32(chunk,i+4),unwind=u32(chunk,i+8);
              valid(begin>0&&begin<end&&end<=imageSize,"invalid_runtime_range");
              valid(begin>=previousEnd,"unordered_or_overlapping_ranges");
              valid(unwind>0&&unwind<imageSize&&unwind%4==0,"invalid_unwind_rva");
              BigInteger lo=rva(begin,end-begin);
              if(!mapped(lo,end-begin,true))throw new Stop("unavailable","runtime_range_not_initialized_executable");
              if(!mapped(rva(unwind,1),1,false))throw new Stop("unavailable","unwind_not_mapped");
              BigInteger hi=base.add(BigInteger.valueOf(end));
              if(addresses.stream().anyMatch(at->at.compareTo(lo)>=0&&at.compareTo(hi)<0))ranges.add(new Range(lo,hi,tableAt.add(BigInteger.valueOf(offset+i))));previousEnd=end;recordsValidated++;
            }
            offset+=length;
          }
        }
      }
      tick();
    }catch(Stop e){state=e.state;reason=e.reason;ranges.clear();}
    boolean complete=state.equals("validated")||state.equals("absent");
    return new Result(Map.of("state",state,"complete",complete,"reason",reason,"headersSource","current-mapped-memory","recordCount",recordCount,"recordsValidated",recordsValidated,"bytesRead",bytesRead,"maximumBytes",maximum,"deadlineMilliseconds",5000),List.copyOf(ranges));
  }
}
