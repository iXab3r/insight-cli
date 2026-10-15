package insight;
import com.google.gson.*;
import ghidra.app.services.Analyzer;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.classfinder.ClassSearcher;
import java.io.File;
import java.nio.file.*;
import java.util.*;

/** Native discovery for pinned modules, with logical identities rather than installation paths. */
public class InsightExtensions {
    public static boolean managed(Class<?> c) throws Exception {
        var source=c.getProtectionDomain().getCodeSource();if(source==null)return false;
        Path location=Path.of(source.getLocation().toURI()).toRealPath();
        for(String root:System.getProperty("ghidra.external.modules","").split(java.util.regex.Pattern.quote(File.pathSeparator)))
            if(!root.isBlank()&&location.startsWith(Path.of(root).toRealPath()))return true;
        return false;
    }
    public static Object inventory(JsonObject p) throws Exception {
        String kind=p.get("kind").getAsString(),filter=p.get("filter").getAsString().toLowerCase(Locale.ROOT);
        int limit=p.get("limit").getAsInt(),offset=p.get("offset").getAsInt();if(limit<1||limit>100||offset<0)throw new IllegalArgumentException();
        List<Map<String,Object>> rows=new ArrayList<>();
        if(kind.equals("languages"))for(var language:DefaultLanguageService.getLanguageService().getLanguageDescriptions(false)){
            var compilers=language.getCompatibleCompilerSpecDescriptions().stream().map(c->Map.of("id",c.getCompilerSpecID().toString(),"name",c.getCompilerSpecName())).toList();
            rows.add(Map.of("id",language.getLanguageID().toString(),"processor",language.getProcessor().toString(),"description",language.getDescription(),"size",language.getSize(),"endian",language.getEndian().toString(),"compilers",compilers));
        }else if(kind.equals("analyzers"))for(Analyzer a:ClassSearcher.getInstances(Analyzer.class))rows.add(Map.of("id",a.getClass().getName(),"name",a.getName(),"description",a.getDescription(),"managed",managed(a.getClass())));
        else if(kind.equals("plugins"))for(Class<? extends Plugin> c:ClassSearcher.getClasses(Plugin.class)){
            PluginDescription d=PluginDescription.getPluginDescription(c);rows.add(Map.of("id",c.getName(),"name",d.getName(),"description",d.getShortDescription(),"managed",managed(c),"status",d.getStatus().toString()));
        }else throw new IllegalArgumentException("Expected languages, analyzers or plugins");
        rows.removeIf(r->!r.toString().toLowerCase(Locale.ROOT).contains(filter));rows.sort(Comparator.comparing(r->r.get("id").toString()));
        int start=Math.min(offset,rows.size()),end=(int)Math.min((long)rows.size(),(long)start+limit);
        return Map.of("kind",kind,"items",rows.subList(start,end),"total",rows.size(),"offset",offset,"limit",limit,"truncated",end<rows.size());
    }
}
