package db;

import db.buffers.InsightBlockTransfer;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

/** Saved native buffers only; never fabricates or replaces native ancestry/change sets. */
public final class InsightNativeFingerprint {
    public static String of(Program p)throws Exception {
        if(p.isChanged())throw new IllegalStateException("Program has unsaved changes");
        return InsightBlockTransfer.fingerprint(((ProgramDB)p).getDBHandle().getBufferMgr().getSourceFile());
    }
    /**
     * Every saved record except what opening a program writes by itself: the derived Metadata table, rebuilt
     * from options on save, and the GUI's "Should Ask To Analyze" flag. Memory bytes live in chained buffers;
     * callers also require an equal program identity.
     */
    public static String content(DBHandle db)throws Exception {
        var hash=java.security.MessageDigest.getInstance("SHA-256");
        var tables=new java.util.TreeMap<String,Table>();
        for(Table table:db.getTables())if(!table.getName().equals("Metadata"))tables.put(table.getName(),table);
        for(Table table:tables.values()){
            boolean properties=table.getName().equals("Property Table");Schema schema=table.getSchema();
            add(hash,table.getName().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            add(hash,(schema.getVersion()+"|"+schema.getKeyName()+"|"+String.join("|",schema.getFieldNames())).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var records=table.iterator();
            while(records.hasNext()){
                DBRecord record=records.next();
                if(properties&&record.getKeyField() instanceof StringField key&&"Program Information.Should Ask To Analyze".equals(key.getString()))continue;
                add(hash,record.getKeyField().getBinaryData());
                for(int i=0;i<record.getColumnCount();i++){Field field=record.getFieldValue(i);add(hash,field==null||field.isNull()?null:field.getBinaryData());}
            }
            hash.update((byte)2);
        }
        return java.util.HexFormat.of().formatHex(hash.digest());
    }
    private static void add(java.security.MessageDigest hash,byte[] value){
        hash.update((byte)(value==null?0:1));if(value==null)return;
        hash.update(java.nio.ByteBuffer.allocate(4).putInt(value.length).array());hash.update(value);
    }
    public static String of(DBHandle db)throws Exception{return InsightBlockTransfer.fingerprint(db.getBufferMgr().getSourceFile());}
}
