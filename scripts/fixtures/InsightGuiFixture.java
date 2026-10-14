import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import javax.swing.SwingUtilities;

/** Dedicated disposable GUI process. No default project or existing user preferences are opened. */
class InsightGuiFixture {
  static class OwnedProjectManager extends DefaultProjectManager {
    OwnedProjectManager() { super(); }
  }
  public static void main(String[] args) throws Exception {
    if(args.length!=3) throw new IllegalArgumentException();
    GhidraApplicationConfiguration configuration=new GhidraApplicationConfiguration();
    configuration.setShowSplashScreen(false);
    Application.initializeApplication(new GhidraApplicationLayout(),configuration);
    SwingUtilities.invokeAndWait(()->{
      try {
        OwnedProjectManager manager=new OwnedProjectManager();
        var project=manager.openProject(new ProjectLocator(args[0],args[1]),false,false);
        FrontEndTool frontEnd=new FrontEndTool(manager);
        if(project.getToolManager().getActiveWorkspace()==null) {
          project.getToolManager().createWorkspace("Owned Fixture").setActive();
        }
        frontEnd.setActiveProject(project);
        var options=frontEnd.getOptions("GhidraMCP HTTP Server");
        options.setInt("Server Port",Integer.parseInt(args[2]));
        options.setBoolean("Enable UDS Transport",false);
        options.setBoolean("Enable TCP Transport",true);
        frontEnd.addPlugin("com.xebyte.GhidraMCPPlugin");
        frontEnd.setVisible(true);
      } catch(Exception error) { throw new RuntimeException(error); }
    });
  }
}
