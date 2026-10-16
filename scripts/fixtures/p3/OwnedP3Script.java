// @category OwnedP3
import ghidra.app.script.GhidraScript;
public class OwnedP3Script extends GhidraScript {public void run(){for(var f:currentProgram.getFunctionManager().getFunctions(true))if(f.getName().equals("first"))currentProgram.getListing().setComment(f.getEntryPoint(),ghidra.program.model.listing.CommentType.POST,"OwnedP3 script ran");}}
