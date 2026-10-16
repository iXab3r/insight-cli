package db.buffers;

import java.io.IOException;
import java.util.TreeSet;

/** Pinned native block-stream protocol; avoids RMI serialization of DataBuffer objects. */
public class InsightBlockTransfer {
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
