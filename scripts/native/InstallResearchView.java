import org.objectweb.asm.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/** Single pinned constructor insertion; all original endpoints/auth/threading remain upstream. */
public class InstallResearchView {
  public static void main(String[] args)throws Exception {
    String owner="com/xebyte/core/AnnotationScanner";
    String[] helpers={"com/eyeauras/insight/InsightResearchView","com/eyeauras/insight/InsightStringAnchors","com/eyeauras/insight/InsightFunctionBoundaries"};
    int[] patched={0};byte[] scanner;
    try(JarFile jar=new JarFile(args[0])){scanner=jar.getInputStream(jar.getJarEntry(owner+".class")).readAllBytes();}
    ClassReader reader=new ClassReader(scanner);ClassWriter writer=new ClassWriter(reader,ClassWriter.COMPUTE_MAXS);
    reader.accept(new ClassVisitor(Opcodes.ASM9,writer){
      @Override public MethodVisitor visitMethod(int access,String name,String desc,String signature,String[] exceptions){
        MethodVisitor base=super.visitMethod(access,name,desc,signature,exceptions);
        if(!name.equals("<init>")||!desc.equals("(Lcom/xebyte/core/ProgramProvider;Lcom/xebyte/core/ThreadingStrategy;[Ljava/lang/Object;)V"))return base;
        return new MethodVisitor(Opcodes.ASM9,base){
          boolean inserted=false;
          @Override public void visitFieldInsn(int opcode,String target,String name,String descriptor){
            // Before the original sort, preserving deterministic descriptors and auth registration.
            if(!inserted&&opcode==Opcodes.GETFIELD&&target.equals(owner)&&name.equals("endpoints")){
              inserted=true;patched[0]++;
              for(String helper:helpers){
              super.visitVarInsn(Opcodes.ALOAD,0);super.visitTypeInsn(Opcodes.NEW,helper);super.visitInsn(Opcodes.DUP);
              super.visitVarInsn(Opcodes.ALOAD,1);super.visitVarInsn(Opcodes.ALOAD,0);
              super.visitFieldInsn(Opcodes.GETFIELD,owner,"threadingStrategy","Lcom/xebyte/core/ThreadingStrategy;");
              super.visitMethodInsn(Opcodes.INVOKESPECIAL,helper,"<init>","(Lcom/xebyte/core/ProgramProvider;Lcom/xebyte/core/ThreadingStrategy;)V",false);
              super.visitMethodInsn(Opcodes.INVOKEVIRTUAL,owner,"scanService","(Ljava/lang/Object;)V",false);
              }
            }
            super.visitFieldInsn(opcode,target,name,descriptor);
          }
        };
      }
    },0);
    if(patched[0]!=1)throw new IllegalStateException("Expected one pinned scanner insertion");
    Map<String,byte[]> entries=new TreeMap<>();
    try(JarFile jar=new JarFile(args[0])){for(var e:Collections.list(jar.entries()))if(!e.isDirectory())entries.put(e.getName(),jar.getInputStream(e).readAllBytes());}
    entries.put(owner+".class",writer.toByteArray());
    Path directory=Path.of(args[1],"com/eyeauras/insight");
    try(var files=Files.list(directory)){for(Path file:files.filter(p->p.getFileName().toString().endsWith(".class")).toList())entries.put("com/eyeauras/insight/"+file.getFileName(),Files.readAllBytes(file));}
    try(JarOutputStream out=new JarOutputStream(Files.newOutputStream(Path.of(args[2])))){
      for(var e:entries.entrySet()){JarEntry entry=new JarEntry(e.getKey());entry.setTime(315532800000L);out.putNextEntry(entry);out.write(e.getValue());out.closeEntry();}
    }
  }
}
