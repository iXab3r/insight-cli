/*
 * Test-only headless orchestration around the stock Ghidra 12.1.2 merge manager.
 * Orchestration derives from Ghidra's MergeManager.java,
 * Copyright National Security Agency, licensed under Apache-2.0.
 * The stock superclass creates and orders all native resolvers. No merge
 * algorithms or category selection are implemented by this subclass.
 */
package insight.prototype;

import java.util.*;
import javax.swing.JComponent;
import ghidra.app.merge.*;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.ModalPluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HeadlessProgramMergeManager extends ProgramMultiUserMergeManager {
    public static int invocations;
    public static final List<String> phases = new ArrayList<>();
    public static final class UnresolvedNativeConflict extends RuntimeException {
        UnresolvedNativeConflict(String category) { super("Native conflict requires a decision: " + category); }
    }
    private static String describe(JComponent component){
        StringBuilder text=new StringBuilder();ArrayDeque<java.awt.Component> pending=new ArrayDeque<>();pending.add(component);
        int visited=0;
        while(!pending.isEmpty()&&visited++<256&&text.length()<8192){
            var c=pending.removeFirst();String value=null;
            if(c instanceof javax.swing.JLabel label)value=label.getText();
            else if(c instanceof javax.swing.text.JTextComponent field)value=field.getText();
            if(value!=null&&!value.isBlank())text.append(' ').append(value.substring(0,Math.min(value.length(),512)));
            if(c instanceof java.awt.Container container)pending.addAll(Arrays.asList(container.getComponents()));
        }
        return text.toString();
    }
    public HeadlessProgramMergeManager(Program result, Program mine, Program original,
            Program latest, ProgramChangeSet latestChanges, ProgramChangeSet myChanges) {
        super(result, mine, original, latest, latestChanges, myChanges);
    }
    @Override public boolean merge(TaskMonitor monitor) throws CancelledException {
        if (!java.awt.GraphicsEnvironment.isHeadless()) throw new IllegalStateException("Headless proof only");
        invocations++;
        for (currentIndex=0; currentIndex<mergeResolvers.length; currentIndex++) {
            monitor.checkCancelled();
            MergeResolver resolver=mergeResolvers[currentIndex];
            phases.add(resolver.getName());
            try { resolver.merge(monitor); }
            catch (CancelledException e) { throw e; }
            catch (RuntimeException e) { throw e; }
            catch (Exception e) { throw new IllegalStateException("Native resolver failed: "+resolver.getName(),e); }
        }
        mergeCompleted=true;
        return true;
    }
    @Override protected MergeManagerPlugin createMergeManagerPlugin(ModalPluginTool t,MergeManager m,DomainObject d) { throw new IllegalStateException("GUI forbidden"); }
    @Override protected void initializeMerge() { throw new IllegalStateException("GUI forbidden"); }
    @Override protected void cleanupMerge() {}
    public ListingMergePanel getListingMergePanel() { return null; }
    public boolean isShowListingPanel() { return false; }
    public boolean isMergeToolVisible() { return false; }
    public boolean isShowingListingMergePanel() { return false; }
    public void removeListingMergePanel() {}
    public void refreshListingMergePanel(Address r,Address l,Address m,Address o) {}
    public void showListingMergePanel(Address a) { throw new UnresolvedNativeConflict("listing"); }
    public void showListingMergePanel(Address r,Address l,Address m,Address o) { throw new UnresolvedNativeConflict("listing"); }
    @Override public void showComponent(JComponent component,String id,HelpLocation help) {
        if(component!=null) throw new UnresolvedNativeConflict(id+describe(component));
    }
    @Override public void showDefaultMergePanel(String description) {}
    @Override public void setApplyEnabled(boolean enabled) {}
    @Override public void clearStatusText() {}
    @Override public void setStatusText(String text) {}
    @Override public void showMonitorComponent(boolean visible) {}
    @Override public void showProgressIcon(boolean visible) {}
    @Override public void removeComponent(JComponent component) {}
    @Override public void waitForInput() { throw new UnresolvedNativeConflict("input"); }
    @Override public void setInProgress(String[] phase) {}
    @Override public void setCompleted(String[] phase) {}
    @Override public void updateProgress(int percentage) {}
    @Override public void updateProgress(int percentage,String message) {}
    @Override public void updateProgress(String message) {}
}
