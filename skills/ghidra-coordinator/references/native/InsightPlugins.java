import insight.InsightExtensions;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.*;
import ghidra.util.classfinder.ClassSearcher;
import java.util.*;
import javax.swing.SwingUtilities;

/** Enable/disable only plugins from explicitly consumed managed modules, in this GUI tool. */
public class InsightPlugins extends GhidraScript {
    public void run() throws Exception {
        JsonObject p=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        var tool=state.getTool();if(tool==null)throw new IllegalStateException("Owned GUI required");
        final Object[] value={null};final Exception[] failure={null};
        SwingUtilities.invokeAndWait(()->{try{
            String operation=p.get("operation").getAsString();
            if(operation.equals("set")){
                String name=p.get("plugin").getAsString();Class<? extends Plugin> type=null;
                for(var c:ClassSearcher.getClasses(Plugin.class))if(c.getName().equals(name)&&InsightExtensions.managed(c)){type=c;break;}
                if(type==null)throw new IllegalArgumentException("Choose a plugin from an enabled managed module");
                Plugin existing=tool.getManagedPlugins().stream().filter(x->x.getClass().getName().equals(name)).findFirst().orElse(null);
                boolean enabled=p.get("enabled").getAsBoolean();
                if(enabled&&existing==null)tool.addPlugin(name);else if(!enabled&&existing!=null)tool.removePlugins(List.of(existing));
                if(tool.getManagedPlugins().stream().anyMatch(x->x.getClass().getName().equals(name))!=enabled)throw new IllegalStateException("Plugin enablement readback differs");
                value[0]=Map.of("plugin",name,"enabled",enabled,"lifetime","current-gui-tool");
            }else if(operation.equals("list")){
                List<Object> rows=new ArrayList<>();for(Plugin plugin:tool.getManagedPlugins())if(InsightExtensions.managed(plugin.getClass()))rows.add(Map.of("id",plugin.getClass().getName(),"name",plugin.getName(),"enabled",true));
                rows.sort(Comparator.comparing(r->((Map<?,?>)r).get("id").toString()));
                if(rows.size()>100)throw new IllegalStateException("Managed GUI plugin inventory exceeds 100 entries");value[0]=Map.of("items",rows,"lifetime","current-gui-tool");
            }else throw new IllegalArgumentException();
        }catch(Exception e){failure[0]=e;}});
        if(failure[0]!=null)throw failure[0];println("INSIGHT_PLUGINS:"+new Gson().toJson(value[0]));
    }
}
