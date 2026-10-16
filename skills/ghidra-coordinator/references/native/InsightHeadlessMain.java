import com.xebyte.core.NamingPolicy;
import com.xebyte.headless.GhidraMCPHeadlessServer;

/** Preserve caller-selected names in the owned facade, including structure fields. */
class InsightHeadlessMain {
  public static void main(String[] args) {
    NamingPolicy.getInstance().setStrictNamingEnforcement(false, "insight facade");
    GhidraMCPHeadlessServer.main(args);
  }
}
