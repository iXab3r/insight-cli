package insight.nativecheckout;

import ghidra.framework.client.*;
import ghidra.framework.remote.*;
import java.net.Authenticator;
import java.awt.Component;
import javax.security.auth.callback.*;

/** Private program workers never authenticate to the repository, including on project reopen. */
public final class InsightOfflineAuthenticator implements ClientAuthenticator {
    public static void install(){ClientUtil.setClientAuthenticator(new InsightOfflineAuthenticator());}
    public Authenticator getAuthenticator(){return new Authenticator(){};}
    public boolean processPasswordCallbacks(String a,String b,String c,boolean d,NameCallback n,
        PasswordCallback p,ChoiceCallback choice,AnonymousCallback anon,String e){return false;}
    public boolean promptForReconnect(Component c,String m){return false;}
    public char[] getNewPassword(Component c,String s,String u){return null;}
    public boolean isSSHKeyAvailable(){return false;}
    public boolean processSSHSignatureCallbacks(String s,NameCallback n,SSHSignatureCallback cb){return false;}
    public char[] getKeyStorePassword(String s,boolean b){return null;}
}
