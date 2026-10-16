import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.util.task.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.nio.file.*;
import java.nio.channels.FileChannel;

/** Persistent native VT session with owned source/destination programs, never caller GPR paths. */
class InsightVersionTracking {
    static String text(JsonObject p,String key){return p.has(key)?p.get(key).getAsString():"";}
    static Map<String,Object> match(VTMatch value){var association=value.getAssociation();return Map.of("set_id",value.getMatchSet().getID(),
        "source",value.getSourceAddress().toString(),"destination",value.getDestinationAddress().toString(),
        "similarity",value.getSimilarityScore().getScore(),"confidence",value.getConfidenceScore().getScore(),
        "status",association.getStatus().toString(),"type",association.getType().toString(),"markup_status",association.getMarkupStatus().toString());}
    static Object matches(VTSessionDB session,JsonObject p){
        int limit=p.has("limit")?p.get("limit").getAsInt():100,offset=p.has("offset")?p.get("offset").getAsInt():0,total=0;List<Object> rows=new ArrayList<>(),sets=new ArrayList<>();Set<Address> sourceMatches=new HashSet<>(),destinationMatches=new HashSet<>();
        for(var set:session.getMatchSets()){
            sets.add(Map.of("id",set.getID(),"correlator",set.getProgramCorrelatorInfo().getName(),"count",set.getMatchCount()));
            for(var value:set.getMatches()){sourceMatches.add(value.getSourceAddress());destinationMatches.add(value.getDestinationAddress());if(total++<offset)continue;if(rows.size()<limit)rows.add(match(value));}}
        return Map.of("match_sets",sets,"items",rows,"total",total,"offset",offset,"limit",limit,"complete",offset+rows.size()>=total,
            "unmatched_source",unmatched(session.getSourceProgram(),sourceMatches),"unmatched_destination",unmatched(session.getDestinationProgram(),destinationMatches),
            "score_semantics","Native VT scores are correlator-specific, not calibrated probabilities. Unmatched means no association from these configured correlators, not proof of no equivalent function.");
    }
    static Object unmatched(Program program,Set<Address> matched){List<Object> rows=new ArrayList<>();int total=0;var iterator=program.getFunctionManager().getFunctions(true);
        while(iterator.hasNext()){Function function=iterator.next();if(matched.contains(function.getEntryPoint()))continue;if(total++<1000)rows.add(Map.of("name",function.getName(),"address",function.getEntryPoint().toString()));}
        return Map.of("items",rows,"total",total,"complete",total<=1000);}
    static VTAssociation association(VTSessionDB session,JsonObject p){
        Address from=session.getSourceProgram().getAddressFactory().getAddress(text(p,"source_address")),to=session.getDestinationProgram().getAddressFactory().getAddress(text(p,"destination_address"));
        if(from==null||to==null)throw new IllegalArgumentException("Invalid VT association addresses");
        for(var set:session.getMatchSets())for(var value:set.getMatches())if(value.getSourceAddress().equals(from)&&value.getDestinationAddress().equals(to))return value.getAssociation();
        throw new IllegalArgumentException("VT association is not in this session");
    }
    static Object markup(VTAssociation association,TaskMonitor monitor)throws Exception{
        List<Object> rows=new ArrayList<>();for(var item:association.getMarkupItems(monitor)){
            if(rows.size()>=1000)throw new IllegalArgumentException("Markup inventory exceeds 1000 items");Map<String,Object> row=new LinkedHashMap<>();
            row.put("type",item.getMarkupType().getDisplayName());row.put("source",item.getSourceAddress().toString());row.put("destination",item.getDestinationAddress()==null?null:item.getDestinationAddress().toString());
            row.put("source_value",Objects.toString(item.getSourceValue(),null));row.put("destination_value",Objects.toString(item.getCurrentDestinationValue(),null));
            row.put("status",item.getStatus().toString());row.put("can_apply",item.canApply());rows.add(row);}
        return Map.of("items",rows,"association_status",association.getStatus().toString(),"read_only",true);
    }
    static Object run(JsonObject p)throws Exception{
        String operation=text(p,"operation"),root=text(p,"root");Object consumer=new Object();GhidraProject project=null;VTSessionDB session=null;Program source=null,destination=null;
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(60,TimeUnit.SECONDS);
        try{
            project=operation.equals("create")?GhidraProject.createProject(root,"project",false):GhidraProject.openProject(root,"project",false);
            var data=project.getProjectData();
            if(operation.equals("create")){
                DomainFile first=data.getRootFolder().createFile("Source",Path.of(text(p,"source_snapshot")).toFile(),monitor);
                DomainFile second=data.getRootFolder().createFile("Destination",Path.of(text(p,"destination_snapshot")).toFile(),monitor);
                source=(Program)first.getDomainObject(consumer,true,false,monitor);destination=(Program)second.getDomainObject(consumer,true,false,monitor);
                if(source.getFunctionManager().getFunctionCount()>10000||destination.getFunctionManager().getFunctionCount()>10000)throw new IllegalArgumentException("VT workflow accepts at most 10000 functions per input");
                session=new VTSessionDB("OwnedVersionTracking",source,destination,consumer);int transaction=session.startTransaction("Correlate owned versions");boolean committed=false;
                try{
                    var exact=new ExactMatchBytesProgramCorrelatorFactory();var options=exact.createDefaultOptions();options.setInt(ExactMatchBytesProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,1);
                    exact.createCorrelator(source,source.getMemory(),destination,destination.getMemory(),options).correlate(session,monitor);
                    var duplicates=new DuplicateFunctionMatchProgramCorrelatorFactory();duplicates.createCorrelator(source,source.getMemory(),destination,destination.getMemory(),duplicates.createDefaultOptions()).correlate(session,monitor);
                    committed=true;
                }finally{session.endTransaction(transaction,committed);}
                data.getRootFolder().createFile("Session",session,monitor);
            }else{
                DomainFile file=data.getFile("/Session");if(file==null)throw new IllegalArgumentException("Native VT session is absent");session=(VTSessionDB)file.getDomainObject(consumer,true,false,monitor);
            }
            Object result;
            if(operation.equals("create")||operation.equals("matches"))result=matches(session,p);
            else if(operation.equals("markup"))result=markup(association(session,p),monitor);
            else if(operation.equals("decide")){
                VTAssociation value=association(session,p);String decision=text(p,"decision");int transaction=session.startTransaction("Explicit match decision");boolean committed=false,closed=false;
                try{switch(decision){case "accepted":value.setAccepted();break;case "rejected":value.setRejected();break;case "available":value.clearStatus();break;default:throw new IllegalArgumentException("Unknown match decision");}committed=true;}
                catch(Exception rejected){closed=true;session.endTransaction(transaction,false);return Map.of("state","rejected","reason","native_association_constraint");}
                finally{if(!closed)session.endTransaction(transaction,committed);}
                session.save("Explicit facade match decision",monitor);result=Map.of("source",value.getSourceAddress().toString(),"destination",value.getDestinationAddress().toString(),"status",value.getStatus().toString());
            }else throw new IllegalArgumentException("Unknown VT operation");
            return result;
        }finally{monitor.finished();if(session!=null)session.release(consumer);if(source!=null)source.release(consumer);if(destination!=null)destination.release(consumer);if(project!=null)project.close();}
    }
    public static void main(String[] args){var output=System.out;System.setOut(System.err);
        try{Application.initializeApplication(new GhidraApplicationLayout(),new HeadlessGhidraApplicationConfiguration());JsonObject p=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();Object value=run(p);
            InsightNativeReceipt.write(p,value);
            output.println(new GsonBuilder().serializeNulls().create().toJson(Map.of("value",value)));System.exit(0);
        }catch(Throwable failure){failure.printStackTrace(System.err);output.println("{\"error\":\"native_version_tracking_failed\"}");System.exit(1);}
    }
}
