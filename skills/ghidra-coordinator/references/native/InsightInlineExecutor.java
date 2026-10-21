package insight;

import com.google.gson.*;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
import javax.tools.*;

/** Owned Java-only inline executor. Never infers non-execution from exception text or stdout. */
public final class InsightInlineExecutor {
    static final int OUTPUT_BYTES=32768, MAX_DIAGNOSTICS=100;
    static final Gson JSON=new GsonBuilder().serializeNulls().create();
    static final class BoundedOutput extends OutputStream {
        final ByteArrayOutputStream bytes=new ByteArrayOutputStream(); boolean truncated;
        public synchronized void write(int b){if(bytes.size()<OUTPUT_BYTES)bytes.write(b);else truncated=true;}
        public synchronized void write(byte[] b,int start,int length){int n=Math.min(length,OUTPUT_BYTES-bytes.size());bytes.write(b,start,n);if(n<length)truncated=true;}
        synchronized String text(){return bytes.toString(StandardCharsets.UTF_8);}
        synchronized Map<String,Object> value(){return Map.of("text",text(),"truncated",truncated,"maximumBytes",OUTPUT_BYTES);}
    }
    record Source(String name,String text,int prefixLines,int userLines,boolean wrapped) {}
    /** Keep offsets/newlines, but hide comments and literals from declaration/import recognition. */
    static String lexical(String s){
        char[] out=s.toCharArray();int state=0;
        for(int i=0;i<s.length();i++){
            char c=s.charAt(i),n=i+1<s.length()?s.charAt(i+1):0;
            if(state==0){
                if(c=='/'&&n=='/'){out[i]=out[++i]=' ';state=1;}
                else if(c=='/'&&n=='*'){out[i]=out[++i]=' ';state=2;}
                else if(c=='"'&&i+2<s.length()&&s.startsWith("\"\"\"",i)){out[i]=out[i+1]=out[i+2]=' ';i+=2;state=5;}
                else if(c=='"'||c=='\''){out[i]=' ';state=c=='"'?3:4;}
            }else{
                if(c!='\n'&&c!='\r')out[i]=' ';
                if(state==1&&c=='\n')state=0;
                else if(state==2&&c=='*'&&n=='/'){out[++i]=' ';state=0;}
                else if((state==3||state==4)&&c=='\\'&&i+1<s.length()){if(s.charAt(i+1)!='\n')out[++i]=' ';}
                else if((state==3&&c=='"')||(state==4&&c=='\''))state=0;
                else if(state==5&&s.startsWith("\"\"\"",i)){out[i]=out[i+1]=out[i+2]=' ';i+=2;state=0;}
            }
        }
        return new String(out);
    }
    static Source source(String code,String attempt){
        String lex=lexical(code);
        Matcher type=Pattern.compile("\\bpublic\\s+(?:(?:abstract|final|strictfp|sealed|non-sealed)\\s+)*(?:class|interface|enum|record)\\s+([A-Za-z_$][\\w$]*)").matcher(lex);
        if(type.find()){
            Matcher pkg=Pattern.compile("\\bpackage\\s+([A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*)\\s*;").matcher(lex);
            String prefix=pkg.find()?pkg.group(1).replaceAll("\\s","")+".":"";
            return new Source(prefix+type.group(1),code,0,code.split("\n",-1).length,false);
        }
        StringBuilder imports=new StringBuilder("import ghidra.app.script.GhidraScript;\n");char[] body=code.toCharArray();int lines=1;
        Matcher im=Pattern.compile("(?m)^\\h*import\\s+(?:static\\s+)?[\\w.$*]+\\s*;").matcher(lex);
        while(im.find()){
            imports.append(code,im.start(),im.end()).append('\n');lines++;
            for(int i=im.start();i<im.end();i++)if(body[i]!='\n'&&body[i]!='\r')body[i]=' ';
        }
        String name="InsightUser_"+attempt.replace("-","");
        return new Source(name,imports+"public class "+name+" extends GhidraScript {\npublic void run() throws Exception {\n"+new String(body)+"\n}\n}\n",lines+2,code.split("\n",-1).length,true);
    }
    static String sha(String s)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));}
    static Map<String,Object> execution(String stage,boolean mayRun,Object invoked){
        Map<String,Object> m=new LinkedHashMap<>();m.put("stage",stage);m.put("userCode",mayRun?"may_have_started":"not_started");m.put("entrypointInvoked",invoked);return m;
    }
    static List<Map<String,Object>> diagnostics(List<Diagnostic<? extends JavaFileObject>> all,Source source){
        List<Map<String,Object>> out=new ArrayList<>();
        for(var d:all){
            if(out.size()==MAX_DIAGNOSTICS)break;
            Map<String,Object> v=new LinkedHashMap<>();v.put("severity",d.getKind().name().toLowerCase(Locale.ROOT));v.put("code",d.getCode());
            String message=d.getMessage(Locale.ROOT);v.put("message",message.substring(0,Math.min(message.length(),512)));v.put("messageTruncated",message.length()>512);
            v.put("line",d.getLineNumber()>0?d.getLineNumber():null);v.put("column",d.getColumnNumber()>0?d.getColumnNumber():null);
            long userLine=d.getLineNumber()-source.prefixLines();v.put("sourceLine",userLine>0&&userLine<=source.userLines()?userLine:null);v.put("generatedWrapper",source.wrapped());out.add(v);
        }
        return out;
    }
    static void failure(Map<String,Object> out,String stage,Throwable error,String fallback){
        out.put("success",false);
        Throwable cause=error;
        if(cause instanceof InvocationTargetException e&&e.getTargetException()!=null)cause=e.getTargetException();
        String message=cause==null?fallback:cause.getClass().getSimpleName()+": "+Objects.toString(cause.getMessage(),"");
        out.put("diagnostic",Map.of("kind",stage.equals("compile")?"java-compile":stage.equals("load")?"java-load":"java-"+stage,"message",message.substring(0,Math.min(message.length(),2048)),"messageTruncated",message.length()>2048));
    }
    public static void execute(Path requestFile,GhidraState state,TaskMonitor monitor)throws Exception {
        JsonObject p=JsonParser.parseString(Files.readString(requestFile)).getAsJsonObject();
        Path root=requestFile.toAbsolutePath().getParent();String code=p.get("code").getAsString(),attempt=p.get("attemptId").getAsString();
        if(!sha(code).equals(p.get("sourceSha256").getAsString())||!attempt.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Inline attempt binding differs");
        Source source=source(code,attempt);BoundedOutput build=new BoundedOutput(),console=new BoundedOutput();
        Map<String,Object> out=new LinkedHashMap<>();out.put("protocol","insight-inline-v1");out.put("attemptId",attempt);out.put("requestId",p.get("requestId").getAsString());out.put("sourceSha256",sha(code));out.put("success",false);
        String stage="prepare";boolean mayRun=false;Object invoked=false;
        PrintStream originalOut=System.out,originalErr=System.err;
        PrintWriter scriptWriter=new PrintWriter(new OutputStreamWriter(console,StandardCharsets.UTF_8),true);
        try {
            JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();if(compiler==null)throw new IllegalStateException("JDK Java compiler is unavailable");
            Path file=root.resolve("source").resolve(source.name().replace('.','/')+".java"),classes=root.resolve("classes");
            Files.createDirectories(file.getParent());Files.createDirectory(classes);Files.writeString(file,source.text(),StandardOpenOption.CREATE_NEW);
            stage="compile";DiagnosticCollector<JavaFileObject> ds=new DiagnosticCollector<>();
            try(StandardJavaFileManager manager=compiler.getStandardFileManager(ds,Locale.ROOT,StandardCharsets.UTF_8)){
                // Compile only this immutable attempt. No source discovery or annotation/plugin execution.
                List<String> options=List.of("-proc:none","-encoding","UTF-8","-classpath",System.getProperty("java.class.path"),"-sourcepath",root.resolve("source").toString(),"-d",classes.toString());
                boolean ok=Boolean.TRUE.equals(compiler.getTask(new OutputStreamWriter(build,StandardCharsets.UTF_8),manager,ds,options,null,manager.getJavaFileObjects(file)).call());
                out.put("diagnostics",diagnostics(ds.getDiagnostics(),source));out.put("diagnosticsTruncated",ds.getDiagnostics().size()>MAX_DIAGNOSTICS);
                if(!ok){
                    PrintWriter messages=new PrintWriter(new OutputStreamWriter(build,StandardCharsets.UTF_8));
                    for(var d:ds.getDiagnostics())messages.println("Inline.java:"+d.getLineNumber()+":"+d.getColumnNumber()+": "+d.getKind()+": "+d.getMessage(Locale.ROOT));messages.flush();
                    failure(out,stage,null,ds.getDiagnostics().stream().filter(d->d.getKind()==Diagnostic.Kind.ERROR).findFirst().map(d->d.getMessage(Locale.ROOT)).orElse("Java compilation failed"));return;
                }
            }
            stage="load";
            try(URLClassLoader loader=new URLClassLoader(new URL[]{classes.toUri().toURL()},InsightInlineExecutor.class.getClassLoader())){
                // Resolution and reflection are performed without class initialization.
                Class<?> type=Class.forName(source.name(),false,loader);
                if(type.getClassLoader()!=loader)throw new IllegalArgumentException("Source class collides with a parent class");
                if(!GhidraScript.class.isAssignableFrom(type)||Modifier.isAbstract(type.getModifiers())||!Modifier.isPublic(type.getModifiers()))throw new IllegalArgumentException("Inline class must be a public concrete GhidraScript");
                Constructor<?> constructor=type.getDeclaredConstructor();if(!Modifier.isPublic(constructor.getModifiers()))throw new IllegalAccessException("Inline class needs a public default constructor");
                // Set the conservative barrier BEFORE initialization or any caller-controlled method.
                System.setOut(new PrintStream(console,true,StandardCharsets.UTF_8));System.setErr(System.out);
                stage="initialize";mayRun=true;Class.forName(source.name(),true,loader);
                stage="construct";
                GhidraScript script=(GhidraScript)constructor.newInstance();
                script.setSourceFile(new ResourceFile(file.toFile()));
                String args=p.get("args").getAsString().trim();script.setScriptArgs(args.isEmpty()?new String[0]:args.split("\\s+"));
                stage="execute";invoked=null; // Framework setup may fail before run(); never assert run() entry from an exception.
                script.execute(state,monitor,scriptWriter);
                out.put("success",true);
            }
        }catch(Throwable error){failure(out,stage,error,"Inline attempt failed");}
        finally {
            scriptWriter.flush();
            System.setOut(originalOut);System.setErr(originalErr);
            out.put("execution",execution(stage,mayRun,invoked));out.put("compilerOutput",build.value());out.put("console_output",console.text());out.put("outputTruncated",console.truncated);
            Path receipt=root.resolve("receipt.json"),temporary=root.resolve("receipt.new");Files.writeString(temporary,JSON.toJson(out),StandardOpenOption.CREATE_NEW);
            try(FileChannel channel=FileChannel.open(temporary,StandardOpenOption.WRITE)){channel.force(true);}
            Files.move(temporary,receipt,StandardCopyOption.ATOMIC_MOVE);
        }
    }
}
