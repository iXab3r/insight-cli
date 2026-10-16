package db.buffers;

import java.io.IOException;
import java.util.TreeSet;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Pinned native block-stream protocol; avoids RMI serialization of DataBuffer objects. */
public class InsightBlockTransfer {
  /** Exact live DB buffers/parameters; ignores physical headers and unused free allocation. */
  public static String fingerprint(BufferFile file) throws Exception {
    MessageDigest hash=MessageDigest.getInstance("SHA-256");
    String[] parameters=file.getParameterNames();Arrays.sort(parameters);
    for(String name:parameters) {
      byte[] key=name.getBytes(StandardCharsets.UTF_8);
      hash.update(ByteBuffer.allocate(4).putInt(key.length).array());hash.update(key);
      hash.update(ByteBuffer.allocate(4).putInt(file.getParameter(name)).array());
    }
    TreeSet<Integer> free=new TreeSet<>();for(int index:file.getFreeIndexes())free.add(index);
    InputBlockStream stream=file instanceof LocalBufferFile local?local.getInputBlockStream():
      file instanceof BufferFileAdapter remote?remote.getInputBlockStream():null;
    if(stream==null)throw new IOException("Unsupported saved buffer protocol");
    try(InputBlockStream input=stream) {
      BufferFileBlock block;int previous=-1;
      while((block=input.readBlock())!=null) {
        if(block.getIndex()<=previous)throw new IOException("Saved block stream order is inconsistent");previous=block.getIndex();
        if(block.getIndex()==0||free.contains(block.getIndex()-1))continue;
        hash.update(ByteBuffer.allocate(4).putInt(block.getIndex()).array());hash.update(block.getData());
      }
    }
    return HexFormat.of().formatHex(hash.digest());
  }
  public static void copy(LocalBufferFile source, ManagedBufferFile destination) throws Exception {
    if (!(destination instanceof BufferFileAdapter remote)) throw new IOException("Expected remote save buffer");
    try (InputBlockStream input=source.getInputBlockStream()) {
      boolean header=input.includesHeaderBlock();
      int expected=input.getBlockCount()-(header?1:0), written=0;
      try (OutputBlockStream output=remote.getOutputBlockStream(expected)) {
        BufferFileBlock block;
        while((block=input.readBlock())!=null) {
          if(header && block.getIndex()==0) continue;
          output.writeBlock(block); written++;
        }
      }
      if(written!=expected) throw new IOException("Incomplete block transfer");
    }
    destination.clearParameters();
    for(String name:source.getParameterNames()) destination.setParameter(name,source.getParameter(name));
    TreeSet<Integer> free=new TreeSet<>();
    for(int index:source.getFreeIndexes()) free.add(index);
    for(int index=source.getIndexCount();index<destination.getIndexCount();index++) free.add(index);
    destination.setFreeIndexes(free.stream().mapToInt(Integer::intValue).toArray());
  }
}
