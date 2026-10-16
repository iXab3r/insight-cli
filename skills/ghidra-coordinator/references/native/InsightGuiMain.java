import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import javax.swing.SwingUtilities;

/** An isolated frontend for a saved facade context; never loads a user's default project. */
class InsightGuiMain {
  static class OwnedProjectManager extends DefaultProjectManager { OwnedProjectManager(){super();} }
  public static void main(String[] args) throws Exception {
    if(args.length!=3 || System.getenv("GHIDRA_MCP_AUTH_TOKEN")==null) throw new IllegalArgumentException();
    GhidraApplicationConfiguration configuration=new GhidraApplicationConfiguration();
    configuration.setShowSplashScreen(false);
    Application.initializeApplication(new GhidraApplicationLayout(),configuration);
    SwingUtilities.invokeAndWait(()->{
      try {
        var manager=new OwnedProjectManager();
        var project=manager.openProject(new ProjectLocator(args[0],args[1]),false,false);
        var frontend=new FrontEndTool(manager);
        if(project.getToolManager().getActiveWorkspace()==null) project.getToolManager().createWorkspace("Research").setActive();
        frontend.setActiveProject(project);
        var options=frontend.getOptions("GhidraMCP HTTP Server");
        options.setInt("Server Port",Integer.parseInt(args[2]));
        options.setBoolean("Enable UDS Transport",false); options.setBoolean("Enable TCP Transport",true);
        options.setBoolean("Strict Naming Enforcement",false);
        frontend.addPlugin("com.xebyte.GhidraMCPPlugin"); frontend.setVisible(true);
      } catch(Exception failure) { throw new RuntimeException(failure); }
    });
  }
}
