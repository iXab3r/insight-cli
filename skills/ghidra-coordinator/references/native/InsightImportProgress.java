import com.google.gson.*;
import ghidra.util.task.TaskMonitorAdapter;
import insight.InsightInitialJournal;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** A bounded observation channel, never a completion receipt or an overall percentage. */
class InsightImportProgress extends TaskMonitorAdapter implements AutoCloseable {
    private final Path root;
    private final String target,attempt;
    private final String started=Instant.now().toString();
    private final Timer heartbeat=new Timer("insight-import-progress",true);
    private String phase="starting",state="running";
    private String message="";
    private long completed,total;
    private boolean indeterminate=true;
    private volatile Throwable writeFailure;
    InsightImportProgress(Path root,String target)throws Exception{
        this(root,target,null);
    }
    InsightImportProgress(Path root,String target,String attempt)throws Exception{
        super(true);this.root=root;this.target=target;this.attempt=attempt;
        Path previous=root.resolve("progress.json");
        if(Files.exists(previous)){
            JsonObject saved=InsightInitialJournal.read(previous);
            if(saved.get("schema").getAsInt()!=1||!target.equals(saved.get("target").getAsString()))throw new SecurityException("Initial progress binding changed");
            // Preserve observations only; an analysis checkpoint requires its own prepared snapshot.
            InsightInitialJournal.write(root.resolve("progress-history-"+UUID.randomUUID()+".json"),saved);
        }
        emit();
        heartbeat.scheduleAtFixedRate(new TimerTask(){public void run(){try{emit();}catch(Throwable failure){writeFailure=failure;}}},2000,2000);
    }
    synchronized void phase(String value)throws Exception{phase=value;setMessage("");initialize(0);setIndeterminate(true);emit();}
    public synchronized void setMessage(String value){message=Objects.toString(value,"");}
    public synchronized String getMessage(){return message;}
    public synchronized void initialize(long maximum){completed=0;total=maximum;indeterminate=maximum<=0;}
    public synchronized void setProgress(long value){completed=value;}
    public synchronized void incrementProgress(long value){completed+=value;}
    public synchronized long getProgress(){return completed;}
    public synchronized void setMaximum(long value){total=value;}
    public synchronized long getMaximum(){return total;}
    public synchronized void setIndeterminate(boolean value){indeterminate=value;}
    public synchronized boolean isIndeterminate(){return indeterminate;}
    synchronized void state(String value)throws Exception{state=value;emit();}
    private synchronized void emit()throws Exception{
        JsonObject p=new JsonObject();p.addProperty("schema",1);p.addProperty("target",target);p.addProperty("phase",phase);p.addProperty("state",state);
        if(attempt!=null)p.addProperty("attempt",attempt);
        p.addProperty("pid",ProcessHandle.current().pid());p.addProperty("startedAt",started);p.addProperty("updatedAt",Instant.now().toString());
        p.addProperty("indeterminate",isIndeterminate());String message=Objects.toString(getMessage(),"");p.addProperty("message",message.substring(0,Math.min(message.length(),1024)));
        if(!isIndeterminate()&&getMaximum()>0){p.addProperty("completed",getProgress());p.addProperty("total",getMaximum());}
        InsightInitialJournal.write(root.resolve("progress.json"),p);
    }
    public synchronized void close()throws Exception{heartbeat.cancel();if(state.equals("running"))state=isCancelled()?"cancelled":"failed";emit();if(writeFailure!=null)throw new java.io.IOException("Progress persistence failed",writeFailure);}
}
