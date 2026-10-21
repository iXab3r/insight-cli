package com.eyeauras.insight;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.function.LongSupplier;

/** Pure bounded raw-memory algorithm. No Ghidra, filesystem, process or persistent query state. */
public final class InsightAnchorScan {
  public static final String ALGORITHM="raw-string-anchors-v1";
  public interface Bytes { int read(BigInteger at,byte[] destination)throws Exception; }
  public record Span(BigInteger start,BigInteger end) {}
  public record Config(String text,List<String> encodings,BigInteger start,BigInteger end,
      BigInteger resume,String resumeEncoding,int cap,int maxBytes,int maxCandidates,int seconds,int limit) {
    public Config {
      if(text==null||text.isEmpty()||text.length()>256||text.indexOf(0)>=0)throw new IllegalArgumentException("Expected 1–256 UTF-16 units without NUL");
      for(int i=0;i<text.length();i++)if(Character.isSurrogate(text.charAt(i))){
        if(!Character.isHighSurrogate(text.charAt(i))||i+1>=text.length()||!Character.isLowSurrogate(text.charAt(++i)))throw new IllegalArgumentException("Unpaired surrogate");
      }
      if(!List.of(List.of("ascii"),List.of("utf16le"),List.of("ascii","utf16le")).contains(encodings))throw new IllegalArgumentException("Expected canonical ascii,utf16le encodings");
      if(encodings.contains("ascii")&&text.chars().anyMatch(c->c>127))throw new IllegalArgumentException("Text is not representable in ASCII");
      if(start.signum()<0||end.bitLength()>64||start.compareTo(end)>0||resume.compareTo(start)<0||resume.compareTo(end)>0||!encodings.contains(resumeEncoding))throw new IllegalArgumentException("Invalid range/frontier");
      if(cap<16||cap>8192||(cap&1)!=0||encodings.stream().anyMatch(e->encoded(text,e).length>cap))throw new IllegalArgumentException("Invalid candidate byte cap");
      if(maxBytes<32768||maxBytes>16777216||maxCandidates<1||maxCandidates>100000||seconds<1||seconds>30||limit<1||limit>1000)throw new IllegalArgumentException("Invalid page budgets");
      encodings=List.copyOf(encodings);
    }
  }
  public static byte[] encoded(String text,String encoding){return text.getBytes(encoding.equals("ascii")?StandardCharsets.US_ASCII:StandardCharsets.UTF_16LE);}
  private static final BigInteger ONE=BigInteger.ONE,PAGE=BigInteger.valueOf(4096);
  private static String hex(BigInteger at){return at.toString(16);}
  private static Map<String,Object> frontier(BigInteger at,String encoding){return Map.of("address",hex(at),"encoding",encoding);}
  private static final class Pause extends RuntimeException {final String reason;Pause(String reason){this.reason=reason;}}
  private record Page(BigInteger start,BigInteger end,byte[] bytes) {}
  private record Probe(int bytes,String boundary,BigInteger nul) {}
  private final Config c;private final List<Span> spans;private final Bytes source;private final LongSupplier clock;
  private final long started;private final byte[][] needles;private final LinkedHashMap<BigInteger,Page> cache=new LinkedHashMap<>(16,.75f,true);
  private Page last,positionPage;private int positionIndex,encodingIndex,bytesRead,testedPairs,candidates,estimatedResultBytes=2048;
  private BigInteger position;private final List<Object> matches=new ArrayList<>();
  public InsightAnchorScan(Config config,List<Span> spans,Bytes source,LongSupplier clock){
    c=config;this.spans=List.copyOf(spans);this.source=source;this.clock=clock;started=clock.getAsLong();
    needles=c.encodings.stream().map(e->encoded(c.text,e)).toArray(byte[][]::new);position=c.resume;encodingIndex=c.encodings.indexOf(c.resumeEncoding);
    BigInteger previous=null;
    for(Span s:spans){if(s.start.compareTo(c.start)<0||s.end.compareTo(c.end)>0||s.start.compareTo(s.end)>0||previous!=null&&s.start.compareTo(previous.add(ONE))<=0)throw new IllegalArgumentException("Expected clipped, sorted, merged spans");previous=s.end;}
  }
  private void deadline(){if(clock.getAsLong()-started>=c.seconds*1000000000L)throw new Pause("timeout");}
  private BigInteger at(){return positionPage==null?position:positionPage.start.add(BigInteger.valueOf(positionIndex));}
  private Page page(BigInteger at,Span span)throws Exception{
    if(last!=null&&at.compareTo(last.start)>=0&&at.compareTo(last.end)<=0)return last;
    BigInteger base=at.divide(PAGE).multiply(PAGE),start=base.max(span.start),end=base.add(PAGE).subtract(ONE).min(span.end);
    Page hit=cache.get(start);if(hit!=null)return last=hit;
    deadline();int length=end.subtract(start).intValueExact()+1;
    if(length>c.maxBytes-bytesRead)throw new Pause("byte_limit");
    byte[] data=new byte[length];int read=source.read(start,data);if(read!=length)throw new IllegalStateException("Incomplete initialized-memory read");
    bytesRead+=read;Page value=new Page(start,end,data);cache.put(start,value);if(cache.size()>8)cache.remove(cache.keySet().iterator().next());return last=value;
  }
  private int byteAt(BigInteger at,Span span)throws Exception{Page p=page(at,span);return p.bytes[at.subtract(p.start).intValueExact()]&255;}
  private byte[] copy(BigInteger at,int count,Span span)throws Exception{
    byte[] data=new byte[count];int offset=0;
    while(offset<count){Page p=page(at,span);int index=at.subtract(p.start).intValueExact(),n=Math.min(count-offset,p.bytes.length-index);System.arraycopy(p.bytes,index,data,offset,n);offset+=n;at=at.add(BigInteger.valueOf(n));}
    return data;
  }
  private int unit(BigInteger at,int width,Span span)throws Exception{return width==1?byteAt(at,span):byteAt(at,span)|(byteAt(at.add(ONE),span)<<8);}
  private Probe probe(BigInteger match,int length,int width,Span span,boolean left)throws Exception{
    int count=0,allowance=c.cap-length;BigInteger cursor=left?match.subtract(BigInteger.valueOf(width)):match.add(BigInteger.valueOf(length));
    while(true){
      if((count&127)==0)deadline();
      if(cursor.compareTo(span.start)<0||cursor.add(BigInteger.valueOf(width-1)).compareTo(span.end)>0){
        boolean range=left?cursor.compareTo(c.start)<0:cursor.add(BigInteger.valueOf(width-1)).compareTo(c.end)>0;
        return new Probe(count,range?"range_edge":"memory_edge",null);
      }
      // At the payload cap the next code unit may still be the NUL (not payload).
      if(unit(cursor,width,span)==0)return new Probe(count,"nul",cursor);
      if(count==allowance)return new Probe(count,"string_limit",null);
      count+=width;cursor=left?cursor.subtract(BigInteger.valueOf(width)):cursor.add(BigInteger.valueOf(width));
    }
  }
  private Map<String,Object> candidate(BigInteger match,int index,Span span)throws Exception{
    String encoding=c.encodings.get(index);int width=encoding.equals("ascii")?1:2,length=needles[index].length;
    Probe left=probe(match,length,width,span,true),right=probe(match,length,width,span,false);
    int spare=c.cap-length,l=Math.min(left.bytes,(spare/2/width)*width),r=Math.min(right.bytes,spare-l);
    l+=Math.min(left.bytes-l,spare-l-r);r+=Math.min(right.bytes-r,spare-l-r);
    BigInteger textFrom=match.subtract(BigInteger.valueOf(l));byte[] data=copy(textFrom,l+length+r,span);String text=null;
    try{text=(encoding.equals("ascii")?StandardCharsets.US_ASCII:StandardCharsets.UTF_16LE).newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();}catch(CharacterCodingException ignored){}
    boolean bounded=left.nul!=null&&right.nul!=null;int total=left.bytes+length+right.bytes;
    boolean complete=bounded&&total<=c.cap&&text!=null;
    String reason=complete?"complete":bounded&&total>c.cap||left.boundary.equals("string_limit")||right.boundary.equals("string_limit")?"string_limit":!bounded?"missing_boundary":"invalid_encoding";
    Map<String,Object> literal=new LinkedHashMap<>();literal.put("start",left.nul==null?null:hex(left.nul.add(BigInteger.valueOf(width))));literal.put("terminatorAddress",right.nul==null?null:hex(right.nul));
    literal.put("byteLength",bounded?total:null);literal.put("textFrom",hex(textFrom));literal.put("text",text);literal.put("textBytes",HexFormat.of().formatHex(data));literal.put("textByteLength",data.length);
    literal.put("leftBoundary",left.boundary);literal.put("rightBoundary",right.boundary);literal.put("boundariesComplete",bounded);literal.put("decoding",text==null?"invalid":"valid");literal.put("complete",complete);literal.put("reason",reason);
    Map<String,Object> row=new LinkedHashMap<>();row.put("encoding",encoding);row.put("matchAddress",hex(match));row.put("matchByteLength",length);row.put("matchOffsetBytes",left.nul==null?null:left.bytes);row.put("literalCandidate",literal);return row;
  }
  private boolean match(Page p,int index,int which,Span span)throws Exception{
    byte[] needle=needles[which];if(p.bytes[index]!=needle[0])return false;
    BigInteger at=p.start.add(BigInteger.valueOf(index));if(at.add(BigInteger.valueOf(needle.length-1)).compareTo(span.end)>0)return false;
    if(index+needle.length<=p.bytes.length){for(int i=1;i<needle.length;i++)if(p.bytes[index+i]!=needle[i])return false;return true;}
    for(int i=1;i<needle.length;i++){if((i&63)==0)deadline();if(byteAt(at.add(BigInteger.valueOf(i)),span)!=(needle[i]&255))return false;}return true;
  }
  public Map<String,Object> run()throws Exception{
    String reason="exhausted";boolean complete=true;
    try{
      for(Span span:spans){
        if(span.end.compareTo(c.resume)<0)continue;
        BigInteger current=span.start.max(c.resume);int first=current.equals(c.resume)?c.encodings.indexOf(c.resumeEncoding):0;
        while(current.compareTo(span.end)<=0){
          position=current;positionPage=null;encodingIndex=first;
          // Limits apply only while there remains an eligible unchecked pair.
          if(matches.size()>=c.limit||estimatedResultBytes>=900000)throw new Pause("result_limit");
          if(candidates>=c.maxCandidates)throw new Pause("candidate_limit");
          Page p=page(current,span);positionPage=p;
          for(int i=current.subtract(p.start).intValueExact();i<p.bytes.length;i++){
            positionIndex=i;
            for(int e=first;e<needles.length;e++){
              encodingIndex=e;if((testedPairs&1023)==0)deadline();
              if(matches.size()>=c.limit||estimatedResultBytes>=900000)throw new Pause("result_limit");
              if(candidates>=c.maxCandidates)throw new Pause("candidate_limit");
              if(match(p,i,e,span)){
                candidates++;Map<String,Object> row=candidate(at(),e,span);
                Map<?,?> literal=(Map<?,?>)row.get("literalCandidate");int cost=2048+8*((String)literal.get("textBytes")).length();
                if(estimatedResultBytes+cost>900000)throw new Pause("result_limit");
                matches.add(row);estimatedResultBytes+=cost;
              }
              testedPairs++;
            }
            first=0;
          }
          current=p.end.add(ONE);first=0;
        }
      }
    }catch(Pause pause){complete=false;reason=pause.reason;}
    Map<String,Object> scan=new LinkedHashMap<>();scan.put("from",frontier(c.resume,c.resumeEncoding));scan.put("through",hex(c.end));scan.put("next",complete?null:frontier(at(),c.encodings.get(encodingIndex)));
    scan.put("complete",complete);scan.put("reason",reason);scan.put("bytesRead",bytesRead);scan.put("testedPairs",testedPairs);scan.put("candidates",candidates);scan.put("elapsedMs",Math.max(0,(clock.getAsLong()-started)/1000000.0));
    return Map.of("algorithm",ALGORITHM,"encodings",c.encodings,"matches",matches,"scan",scan);
  }
}
