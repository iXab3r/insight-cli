import {createHash} from 'node:crypto';
import {join} from 'node:path';
import * as zip from 'yauzl';
import {fail} from './model.js';

/** Version-pinned upstream display/entry adapters and native compatibility fixes.
 * Ghidra still creates/orders every resolver. No coordinator object merge lives here. */
const pins=[
 ['Features/Base','ghidra/app/merge/listing/ListingMergeManager.java','3b6ce2e22fd414d6cc63ce2a3be6c533f13524b9513767b932f6da8f2d9326d6'],
 ['Framework/Project','ghidra/framework/data/GhidraFileData.java','aafc9c66f42ce12c3f0e7847529d982545b4f760dd570db482133578e9d531e2'],
 ['Features/Base','ghidra/app/merge/listing/ProgramContextMergeManager.java','f2a57f5100de73f980fab99a8ba1d79cf8ecee6257ba32686b78f3512e4c67bb'],
 ['Features/Base','ghidra/app/merge/listing/ExternalFunctionMerger.java','76aa623434213057e936c8abef1539844c41c30361891b4398665d673574f519'],
 ['Features/Base','ghidra/app/merge/listing/AbstractFunctionMerger.java','9e4ea08167344d8527701dac0ed1607fd68e0670849c8b453463fcf8fccb4fb5'],
 ['Features/Base','ghidra/app/merge/memory/MemoryMergeManager.java','28b1fd583e694a7b48d37dcdebdae6674990ee0c2b3dbf3d44a726da33dd1129'],
] as const;
async function entry(archive:string,name:string):Promise<string>{
 const file=await new Promise<zip.ZipFile>((ok,bad)=>zip.open(archive,{lazyEntries:true},(e,z)=>e?bad(e):ok(z!)));
 return new Promise((ok,bad)=>{
  let found=false;const failed=(error:unknown)=>{file.close();bad(error);};file.on('error',failed);
  file.on('end',()=>{if(!found)failed(new Error('Pinned native source is absent'));});
  file.on('entry',(item:zip.Entry)=>{
   if(item.fileName!==name){file.readEntry();return;}found=true;
   if(item.uncompressedSize>2*1024*1024){failed(new Error('Native source exceeds bound'));return;}
   file.openReadStream(item,(error,stream)=>{if(error){failed(error);return;}const chunks:Buffer[]=[];
    stream!.on('error',failed);stream!.on('data',(bytes:Buffer)=>chunks.push(bytes));stream!.on('end',()=>{file.close();ok(Buffer.concat(chunks).toString('utf8'));});});
  });file.readEntry();
 });
}
function replace(source:string,before:string,after:string,count=1){
 if(source.split(before).length!==count+1)fail('binding','Pinned native merge source seam changed.');
 return source.replaceAll(before,after);
}
export async function nativeMergeSources(home:string){
 const result=[];
 for(const [module,name,pin]of pins){
  const archive=join(home,'Ghidra',module,'lib',module.split('/')[1]+'-src.zip');
  let source=await entry(archive,name);
  if(createHash('sha256').update(source).digest('hex')!==pin)fail('binding','Native merge requires the pinned Ghidra 12.1.2 sources.');
  if(name.endsWith('/ListingMergeManager.java')){
   source=replace(source,'mergePanel.setTopComponent(conflictInfoPanel);','if (mergePanel != null) mergePanel.setTopComponent(conflictInfoPanel);');
   for(const method of ['setListingViewsToEntireProgram','emptyListingViewForPrograms'])source=replace(source,'private void '+method+'() {','private void '+method+'() {\n\t\tif (mergePanel == null) return;');
  }else if(name.endsWith('/GhidraFileData.java')){
   source=replace(source,'if (SystemUtilities.isInHeadlessMode()) {','if (false /* Insight native headless merge adapter installed */) {',2);
   source=replace(source,'DomainObject latestObj = null; // TODO: Is there some way to leverage the buffer file we already copied into tmpItem? Missing required change set',
    'boolean mergeChanged = true;\n\t\t\t\tDomainObject latestObj = null; // TODO: Is there some way to leverage the buffer file we already copied into tmpItem? Missing required change set');
   source=replace(source,'mergeObj.save("Merge with version " + mergeVer, monitor);',
    `// A native merge can leave the latest-version result unchanged, even when
					// the source checkout has local saves (e.g. Ghidra's open-time rewrite).
					// save() otherwise skips it, leaving no cumulative change files for
					// updateCheckoutFrom. Let the native save create those files, without
					// adding an edit or synthesizing a change set.
					mergeChanged = ((DomainObjectAdapterDB) mergeObj).getDBHandle().isChanged();
					((DomainObjectAdapterDB) mergeObj).setChanged(true);
					mergeObj.save("Merge with version " + mergeVer, monitor);`);
   source=replace(source,'tmpItem = null; // update removes temporary file if successful',
    `tmpItem = null; // update removes temporary file if successful
				if (!mergeChanged) {
					// The native result had no buffer changes relative to mergeVer.
					// Record its new local version as clean, keeping the same checkout
					// and the exact version merged, even if the server advances again.
					folderItem.setCheckout(checkoutId, folderItem.isCheckedOutExclusive(), mergeVer,
						folderItem.getCurrentVersion());
				}`);
  }
  else if(name.endsWith('/ProgramContextMergeManager.java'))source=replace(source,'mergePanel.setTopComponent(conflictInfoPanel);','if (mergePanel != null) mergePanel.setTopComponent(conflictInfoPanel);');
  else if(name.endsWith('/ExternalFunctionMerger.java'))for(const panel of ['conflictInfoPanel','listingConflictInfoPanel'])source=replace(source,'listingMergePanel.setTopComponent('+panel+');','if (listingMergePanel != null) listingMergePanel.setTopComponent('+panel+');');
  else if(name.endsWith('/AbstractFunctionMerger.java'))source=replace(source,'final Address entryPt, final TaskMonitor monitor) {\n\n\t\tif (conflictPanel == null) {',
   'final Address entryPt, final TaskMonitor monitor) {\n\n\t\tif (java.awt.GraphicsEnvironment.isHeadless()) {\n\t\t\tmergeManager.showListingMergePanel(entryPt);\n\t\t\tthrow new IllegalStateException("Headless function conflict was not rejected");\n\t\t}\n\n\t\tif (conflictPanel == null) {');
  else {
   source=replace(source,'if (myComment != null && !myComment.equals(origBlocks[index].getComment()) ||\n\t\t\t\t(myComment == null)) {','if (!java.util.Objects.equals(myComment, origBlocks[index].getComment())) {');
   const start=source.indexOf('\tprivate boolean isCommentConflict(int index) {');if(start<0)fail('binding','Pinned native memory conflict source changed.');
   let depth=0,end=0;for(let n=source.indexOf('{',start);n<source.length;n++){if(source[n]==='{')depth++;if(source[n]==='}'&&--depth===0){end=n+1;break;}}
   if(!end)fail('binding','Pinned native memory conflict source changed.');
   source=source.slice(0,start)+`\tprivate boolean isCommentConflict(int index) {
        String original = origBlocks[index].getComment();
        String latest = latestBlocks[index].getComment();
        String mine = myBlocks[index].getComment();
        return !java.util.Objects.equals(mine, original) &&
            !java.util.Objects.equals(latest, original) && !java.util.Objects.equals(mine, latest);
    }`+source.slice(end);
  }
  result.push({name,upstreamSha256:pin,sha256:createHash('sha256').update(source).digest('hex'),source});
 }
 return result;
}
