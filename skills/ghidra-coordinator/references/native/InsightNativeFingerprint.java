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
    public static String of(DBHandle db)throws Exception{return InsightBlockTransfer.fingerprint(db.getBufferMgr().getSourceFile());}
}
