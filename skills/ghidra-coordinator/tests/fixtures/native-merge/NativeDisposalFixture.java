import com.google.gson.*;
import com.xebyte.headless.GhidraServerManager;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CodeUnit;
import java.nio.file.*;
import java.util.*;

/** Controlled mutations of disposable projects, between native status and final release. */
public final class NativeDisposalFixture {
    static void receiptTests(){
        JsonObject q=JsonParser.parseString("{checkoutId:3,verifiedVersion:1,fileId:'file',fingerprint:'base',opened:'opened'}").getAsJsonObject();
        JsonObject legacy=JsonParser.parseString("{checkoutId:3,version:1,fingerprint:'base'}").getAsJsonObject();
        InsightNativeCheckout.require(InsightNativeCheckout.sameRelease(legacy,q),"Legacy completed release recovery changed");
        JsonObject current=legacy.deepCopy();current.addProperty("fileId","file");current.addProperty("savedFingerprint","opened");
        InsightNativeCheckout.require(InsightNativeCheckout.sameRelease(current,q),"Exact release proof rejected");
        for(String key:List.of("opened","fileId","checkoutId","verifiedVersion","fingerprint")){
            JsonObject changed=q.deepCopy();if(key.equals("checkoutId")||key.equals("verifiedVersion"))changed.addProperty(key,9);else changed.addProperty(key,"other");
            InsightNativeCheckout.require(!InsightNativeCheckout.sameRelease(current,changed),"Release proof accepted changed "+key);
        }
        JsonObject base=q.deepCopy();base.remove("opened");InsightNativeCheckout.require(!InsightNativeCheckout.sameRelease(current,base),"Opened proof fell back to base");
        current.addProperty("savedFingerprint","base");InsightNativeCheckout.require(InsightNativeCheckout.sameRelease(current,base),"Base proof rejected");
        current.remove("fileId");InsightNativeCheckout.require(!InsightNativeCheckout.sameRelease(current,base),"Incomplete new receipt accepted as legacy");
        JsonObject backup=JsonParser.parseString("{before:{fingerprint:'original'},backupAbsent:true,backupExpected:true,result:{disposableBackups:{'program.keep':{schema:1,fileId:'created',fingerprint:'saveAs-bytes'}}}}").getAsJsonObject();
        var actual=Map.<String,Object>of("fileId","created","fingerprint","saveAs-bytes");
        InsightNativeCheckout.require(InsightNativeCheckout.backupMatches(backup,"program.keep",actual),"Dirty Update saveAs backup rejected");
        InsightNativeCheckout.require(!InsightNativeCheckout.backupMatches(backup,"program.keep",Map.of("fileId","replacement","fingerprint","saveAs-bytes")),"Replaced backup accepted");
        InsightNativeCheckout.require(!InsightNativeCheckout.backupMatches(backup,"program.keep",Map.of("fileId","created","fingerprint","changed")),"Changed backup accepted");
        for(String key:List.of("backupAbsent","backupExpected")){
            JsonObject changed=backup.deepCopy();changed.addProperty(key,false);InsightNativeCheckout.require(!InsightNativeCheckout.backupMatches(changed,"program.keep",actual),"Unproved native backup creation accepted");
        }
        JsonObject replaced=backup.deepCopy();replaced.addProperty("backupAbsent",false);replaced.addProperty("backupBeforeFileId","prior-native-copy");
        InsightNativeCheckout.require(InsightNativeCheckout.backupMatches(replaced,"program.keep",actual),"A newly created replacement native backup was rejected");
        replaced.addProperty("backupBeforeFileId","created");InsightNativeCheckout.require(!InsightNativeCheckout.backupMatches(replaced,"program.keep",actual),"An unchanged preexisting backup was accepted as native creation");
        JsonObject legacyBackup=JsonParser.parseString("{before:{fingerprint:'original'},result:{disposableBackups:{'program.keep':'original'}}}").getAsJsonObject();
        InsightNativeCheckout.require(InsightNativeCheckout.backupMatches(legacyBackup,"program.keep",Map.of("fileId","legacy","fingerprint","original")),"Legacy backup proof rejected");
        InsightNativeCheckout.require(!InsightNativeCheckout.backupMatches(legacyBackup,"program.keep",actual),"Legacy proof blessed unrelated saveAs bytes");
        System.out.println("RELEASE_RECEIPTS_VERIFIED");
    }
    public static void main(String[] args)throws Exception {
        if(args[0].equals("receipts")){receiptTests();return;}
        JsonObject q=JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject(),owner=q.getAsJsonObject("owner");
        Path root=Path.of(q.get("root").getAsString()).toRealPath();
        InsightNativeCheckout.require(root.getParent().getFileName().toString().equals(owner.get("context").getAsString()),"Fixture escaped its context");
        Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());
        var server=new GhidraServerManager();server.connect();var repository=server.server().getRepository(owner.get("repository").getAsString());repository.connect();
        var project=new InsightNativeCheckout.Projects().openProject(new ProjectLocator(root.toString(),"view"),false,false);
        String path=owner.get("path").getAsString();DomainFile file=project.getProjectData().getFile(args[0].equals("edit-backup")?path+".keep":path);
        ProgramDB program=(ProgramDB)file.getDomainObject(InsightNativeCheckout.CONSUMER,false,false,InsightNativeCheckout.MONITOR);
        try{
            if(args[0].equals("edit")||args[0].equals("edit-backup")){
                int tx=program.startTransaction("Disposable release-race fixture");
                try{program.getListing().setComment(program.getMinAddress(),CodeUnit.EOL_COMMENT,args[0].equals("edit-backup")?"PRIVATE_BACKUP_AFTER_STATUS":"PRIVATE_AFTER_STATUS");}finally{program.endTransaction(tx,true);}
                program.save("Disposable release-race fixture",InsightNativeCheckout.MONITOR);
            }else{
                var data=project.getProjectData().getRootFolder();
                var extra=new ProgramDB("private",program.getLanguage(),program.getCompilerSpec(),InsightNativeCheckout.CONSUMER);
                try{
                    if(args[0].equals("nested"))data.createFolder("private").createFile("nested",extra,InsightNativeCheckout.MONITOR);
                    else if(args[0].equals("backup"))data.createFile(file.getName()+".keep",extra,InsightNativeCheckout.MONITOR);
                    else throw new IllegalArgumentException("Unknown fixture mutation");
                }finally{extra.release(InsightNativeCheckout.CONSUMER);}
            }
        }finally{program.release(InsightNativeCheckout.CONSUMER);project.close();repository.disconnect();server.disconnect();}
        System.out.println("DISPOSABLE_MUTATION_COMPLETE");System.exit(0);
    }
}
