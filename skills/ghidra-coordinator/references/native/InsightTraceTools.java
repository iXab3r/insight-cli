package insight;

import com.google.gson.*;
import ghidra.app.services.*;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

/** Typed trace inspection and guarded live-target writes. Trace cache writes never substitute for target writes. */
public class InsightTraceTools {
    static String text(JsonObject p,String key){return p.has(key)?p.get(key).getAsString():"";}
    static int bound(JsonObject p,String key,int fallback,int maximum){int n=p.has(key)?p.get(key).getAsInt():fallback;if(n<1||n>maximum)throw new IllegalArgumentException("Invalid trace work bound");return n;}
    static void require(boolean value,String message){if(!value)throw new IllegalStateException(message);}
    static byte[] hex(String text){if(!text.matches("(?:[a-f0-9A-F]{2}){1,4096}"))throw new IllegalArgumentException("Expected 1–4096 complete byte pairs");return HexFormat.of().parseHex(text);}
    static BigInteger integer(String text){if(!text.matches("(?:0[xX])?[a-f0-9A-F]{1,128}"))throw new IllegalArgumentException("Expected unsigned hex register value");return new BigInteger(text.replaceFirst("(?i)^0x",""),16);}
    static Object value(Object value){
        if(value instanceof TraceObject object)return Map.of("kind","object","object_id",Long.toString(object.getKey()),"path",object.getCanonicalPath().toString(),"schema",object.getSchema().getName().toString());
        if(value instanceof Address at)return Map.of("kind","address","space",at.getAddressSpace().getName(),"address",at.toString());
        if(value instanceof AddressRange range)return Map.of("kind","address_range","start",range.getMinAddress().toString(),"end",range.getMaxAddress().toString());
        if(value instanceof Number)return Map.of("kind","number","value",value.toString());
        if(value instanceof Boolean)return Map.of("kind","boolean","value",value);
        if(value instanceof String string)return Map.of("kind","string","value",string.substring(0,Math.min(4096,string.length())),"complete",string.length()<=4096);
        if(value instanceof byte[] bytes)return Map.of("kind","bytes","hex",HexFormat.of().formatHex(Arrays.copyOf(bytes,Math.min(bytes.length,4096))),"size",bytes.length,"complete",bytes.length<=4096);
        return Map.of("kind","unsupported","java_type",value==null?"null":value.getClass().getSimpleName());
    }
    static Target live(Trace trace,DebuggerTraceManagerService manager,PluginTool tool){
        var targets=tool.getService(DebuggerTargetService.class);Target target=targets==null?null:targets.getTarget(trace);
        require(target!=null&&target.isValid(),"Selected trace is disconnected");var coords=manager.getCurrentFor(trace);
        require(coords.getTime().isSnapOnly()&&coords.getSnap()==target.getSnap(),"Write requires the current live snapshot, not historical/emulated time");
        require(coords.getThread()!=null&&target.getThreadExecutionState(coords.getThread())==TraceExecutionState.STOPPED,"Write requires a selected stopped thread");return target;
    }
    static byte[] memory(Trace trace,Target target,Address at,int size,TaskMonitor monitor)throws Exception{
        target.readMemoryAsync(new AddressSet(at,at.add(size-1)),monitor).get(30,TimeUnit.SECONDS);long snap=target.getSnap();
        var memory=trace.getMemoryManager();for(int i=0;i<size;i++)require(memory.getState(snap,at.add(i))==TraceMemoryState.KNOWN,"Fresh target memory is not known");
        ByteBuffer bytes=ByteBuffer.allocate(size);require(memory.getBytes(snap,at,bytes)==size,"Fresh target memory is incomplete");return bytes.array();
    }
    public static Object run(Trace trace,DebuggerTraceManagerService manager,PluginTool tool,JsonObject p,TaskMonitor monitor)throws Exception{
        boolean[] targetEffect={false};try{Object result=operation(trace,manager,tool,p,monitor,targetEffect);JsonElement json=new Gson().toJsonTree(result);
            String original=trace.getOptions("Insight").getString("Owned Context Root",text(p,"owned_root"));return logical(json,original,text(p,"owned_root"));}
        catch(Exception failure){String operation=text(p,"operation");if((operation.equals("write_memory")||operation.equals("write_register"))&&!targetEffect[0]){
            String diagnostic=failure.getStackTrace().length>0&&failure.getStackTrace()[0].getClassName().equals("insight.InsightTraceTools")?Objects.toString(failure.getMessage(),failure.getClass().getSimpleName()):failure.getClass().getSimpleName();
            return Map.of("status","rejected","target_effect_started",false,"reason","native_live_precondition_changed","diagnostic",diagnostic);}
            throw failure;}
    }
    static JsonElement logical(JsonElement value,String original,String current){
        if(value.isJsonPrimitive()&&value.getAsJsonPrimitive().isString()){String text=value.getAsString();if(!original.isEmpty())text=text.replace(original,"@target");if(!current.isEmpty())text=text.replace(current,"@target");return new JsonPrimitive(text);}
        if(value.isJsonArray()){JsonArray result=new JsonArray();for(JsonElement child:value.getAsJsonArray())result.add(logical(child,original,current));return result;}
        if(value.isJsonObject()){JsonObject result=new JsonObject();for(var entry:value.getAsJsonObject().entrySet())result.add(entry.getKey(),logical(entry.getValue(),original,current));return result;}return value;
    }
    static Object operation(Trace trace,DebuggerTraceManagerService manager,PluginTool tool,JsonObject p,TaskMonitor monitor,boolean[] targetEffect)throws Exception{
        String operation=text(p,"operation");long snap=p.has("snap")?Long.parseLong(text(p,"snap")):manager.getCurrentSnap();
        if(operation.equals("write_memory")){
            Target target=live(trace,manager,tool);byte[] expected=hex(text(p,"expect_hex")),wanted=hex(text(p,"bytes_hex"));if(expected.length!=wanted.length)throw new IllegalArgumentException("Expected/replacement lengths differ");
            Address at=trace.getBaseAddressFactory().getAddress(text(p,"address"));if(at==null)throw new IllegalArgumentException("Invalid trace address");
            require(Arrays.equals(memory(trace,target,at,expected.length,monitor),expected),"Live memory byte precondition changed");
            targetEffect[0]=true;target.writeMemoryAsync(at,wanted).get(30,TimeUnit.SECONDS);require(Arrays.equals(memory(trace,target,at,wanted.length,monitor),wanted),"Fresh live memory readback differs");
            return Map.of("status","written","address",at.toString(),"size",wanted.length,"bytes_hex",HexFormat.of().formatHex(wanted),"verified_from","live_target_refresh","snap",Long.toString(target.getSnap()));
        }
        if(operation.equals("write_register")){
            Target target=live(trace,manager,tool);var coords=manager.getCurrentFor(trace);var platform=coords.getPlatform();Register register=platform.getLanguage().getRegister(text(p,"register"));
            if(register==null)throw new IllegalArgumentException("Unknown platform register");BigInteger expected=integer(text(p,"expect_value")),wanted=integer(text(p,"value"));
            if(expected.bitLength()>register.getBitLength()||wanted.bitLength()>register.getBitLength())throw new IllegalArgumentException("Register value exceeds its exact width");
            target.readRegistersAsync(platform,coords.getThread(),coords.getFrame(),Set.of(register)).get(30,TimeUnit.SECONDS);
            var space=trace.getMemoryManager().getMemoryRegisterSpace(coords.getThread(),coords.getFrame(),false);require(space!=null,"Selected register bank is absent");
            var observed=space.getViewValue(platform,target.getSnap(),register);require(observed!=null&&observed.hasValue()&&expected.equals(observed.getUnsignedValue()),"Live register precondition changed");
            targetEffect[0]=true;target.writeRegisterAsync(platform,coords.getThread(),coords.getFrame(),new RegisterValue(register,wanted)).get(30,TimeUnit.SECONDS);
            target.readRegistersAsync(platform,coords.getThread(),coords.getFrame(),Set.of(register)).get(30,TimeUnit.SECONDS);observed=space.getViewValue(platform,target.getSnap(),register);
            require(observed!=null&&observed.hasValue()&&wanted.equals(observed.getUnsignedValue()),"Fresh live register readback differs");
            return Map.of("status","written","register",register.getName(),"value","0x"+wanted.toString(16),"bits",register.getBitLength(),"verified_from","live_target_refresh","snap",Long.toString(target.getSnap()));
        }
        if(operation.equals("timeline")){
            long before=p.has("before_snap")?Long.parseLong(text(p,"before_snap")):Long.MAX_VALUE;int limit=bound(p,"limit",100,1000);List<Object> rows=new ArrayList<>();boolean complete=false;
            for(int i=0;i<limit;i++){monitor.checkCancelled();TraceSnapshot snapshot=trace.getTimeManager().getMostRecentSnapshot(before);if(snapshot==null){complete=true;break;}
                Map<String,Object> row=new LinkedHashMap<>();row.put("snap",Long.toString(snapshot.getKey()));row.put("description",snapshot.getDescription());row.put("schedule",snapshot.getScheduleString());row.put("real_time",Long.toString(snapshot.getRealTime()));
                row.put("event_thread",snapshot.getEventThread()==null?null:Long.toString(snapshot.getEventThread().getKey()));rows.add(row);
                if(snapshot.getKey()==Long.MIN_VALUE){complete=true;break;}before=snapshot.getKey()-1;}
            Map<String,Object> out=new LinkedHashMap<>();out.put("items",rows);out.put("complete",complete);if(!complete)out.put("next_before_snap",Long.toString(before));return out;
        }
        if(operation.equals("objects")){
            int limit=bound(p,"limit",100,1000),budget=bound(p,"max_scan",10000,200000),visited=0;List<Object> rows=new ArrayList<>();String prefix=text(p,"path_prefix").replace("@target",trace.getOptions("Insight").getString("Owned Context Root",text(p,"owned_root")));
            try(var stream=trace.getObjectManager().getAllObjects()){var iterator=stream.iterator();
                while(iterator.hasNext()&&rows.size()<limit&&visited<budget){monitor.checkCancelled();TraceObject object=iterator.next();visited++;
                    if(object.isAlive(snap)&&object.getCanonicalPath().toString().startsWith(prefix))rows.add(Map.of("object_id",Long.toString(object.getKey()),"path",object.getCanonicalPath().toString(),"schema",object.getSchema().getName().toString(),"life",object.getLife().toString()));}
                return Map.of("snap",Long.toString(snap),"items",rows,"visited",visited,"complete",!iterator.hasNext());}
        }
        if(operation.equals("object_values")){
            TraceObject object=trace.getObjectManager().getObjectById(Long.parseLong(text(p,"object_id")));if(object==null)throw new IllegalArgumentException("Trace object ID is absent");
            String key=text(p,"key");long from=p.has("from_snap")?Long.parseLong(text(p,"from_snap")):snap,to=p.has("to_snap")?Long.parseLong(text(p,"to_snap")):from;
            if(to<from||BigInteger.valueOf(to).subtract(BigInteger.valueOf(from)).compareTo(BigInteger.valueOf(999))>0)throw new IllegalArgumentException("Value history range is 1–1000 snaps");
            List<Object> rows=new ArrayList<>();String previous="";
            for(long current=from;;current++){monitor.checkCancelled();TraceObjectValue entry=object.getValue(current,key);
                if(entry!=null&&!entry.getLifespan().toString().equals(previous)){rows.add(Map.of("key",key,"lifespan",entry.getLifespan().toString(),"value",value(entry.getValue())));previous=entry.getLifespan().toString();}
                if(current==to)break;}
            return Map.of("object_id",Long.toString(object.getKey()),"path",object.getCanonicalPath().toString(),"key",key,"from_snap",Long.toString(from),"to_snap",Long.toString(to),"items",rows,"complete",true);
        }
        if(operation.equals("schedule")){
            TraceSchedule schedule=TraceSchedule.parse(text(p,"schedule"));schedule.validate(trace);
            return Map.of("schedule",schedule.toString(),"base_snap",Long.toString(schedule.getSnap()),"ticks",Long.toString(schedule.totalTickCount()),"patches",Long.toString(schedule.totalPatchCount()),"snap_only",schedule.isSnapOnly(),"validated",true,"executed",false);
        }
        throw new IllegalArgumentException("Unknown typed trace operation");
    }
}
