import java.nio.file.*;
import java.util.*;

/** Fixed certificate preparation; the secret remains in the child environment. */
class InsightKeytool {
  public static void main(String[] args) throws Exception {
    if(args.length!=1 || System.getenv("INSIGHT_KEYSTORE_PASSWORD")==null) throw new IllegalArgumentException();
    var executable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"keytool.exe":"keytool");
    var command=new ArrayList<String>(List.of(executable.toString(),"-genkeypair","-alias","insight","-keyalg","RSA","-keysize","2048",
      "-dname","CN=GhidraServer","-ext","SAN=IP:127.0.0.1","-ext","KU=digitalSignature,keyEncipherment","-validity","3650",
      "-keystore",args[0],"-storetype","PKCS12","-storepass:env","INSIGHT_KEYSTORE_PASSWORD"));
    var process=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
    int code=process.waitFor(); if(code!=0) System.exit(code);
    System.out.println("{\"state\":\"ready\"}");
  }
}
