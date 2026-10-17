import {readFile,mkdir,stat,rename,rm,open} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {basename,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export function validateRecipe(recipe){
 if(recipe.schema!==1||recipe.repository!=='iXab3r/insight-cli'||!/^tool-[a-z0-9.+-]+-r\d+$/.test(recipe.tag))throw Error('Invalid distribution identity');
 const names=new Set();
 if(!Array.isArray(recipe.assets)||!recipe.assets.length||!recipe.redistribution)throw Error('Incomplete distribution');
 for(const a of recipe.assets){
  if(a.delivery?.kind==='vendor-direct')throw Error('Vendor-only distribution must never be mirrored');
  if(!/^[a-zA-Z0-9_.+-]+$/.test(a.name)||names.has(a.name)||a.name==='manifest.json')throw Error('Invalid/duplicate asset name');names.add(a.name);
  if(a.repack){const r=a.repack;if(a.recompress||r.format!=='tar-zstd-subset-v1'||!(/^[a-f0-9]{64}$/.test(r.sha256))||!Number.isSafeInteger(r.size)||r.size<1||r.size>=2*1024**3||!(/^[a-zA-Z0-9][a-zA-Z0-9_.+-]*\/$/.test(r.stripPrefix))||!(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(r.outputRoot))||!Array.isArray(r.entries)||!r.entries.length||r.entries.length>100||new Set(r.entries).size!==r.entries.length||r.entries.some(p=>typeof p!=='string'||p.startsWith('/')||p.includes('\\')||p.split('/').some(s=>!s||s==='.'||s==='..')))throw Error('Unpinned or unsafe subset recipe');}
  if(a.recompress&&(a.recompress.format!=='xz-to-gzip'||!(/^[a-f0-9]{64}$/.test(a.recompress.sha256))||!Number.isSafeInteger(a.recompress.size)||a.recompress.size<1||a.recompress.size>=2*1024**3))throw Error('Unpinned recompression input');
  if(new URL(a.upstream).protocol!=='https:'||!/^[a-f0-9]{64}$/.test(a.sha256)||!Number.isSafeInteger(a.size)||a.size<1||a.size>=2*1024**3||!a.license)throw Error('Unpinned distribution asset');
 }
 for(const a of recipe.assets)for(const extra of a.repack?.appendAssets??[]){const other=recipe.assets.find(v=>v.name===extra.asset);if(!other||other.repack||other.recompress||other.role!=='license-companion'||other.size>1024**2||typeof extra.path!=='string'||extra.path.startsWith('/')||extra.path.includes('\\')||extra.path.split('/').some(p=>!p||p==='.'||p==='..'))throw Error('Subset notice companion is absent or unsafe');}
 if(!recipe.assets.some(a=>a.role==='source'))throw Error('Distribution source companion is required');
 return recipe;
}
export async function sha256(path){const hash=createHash('sha256');for await(const b of createReadStream(path))hash.update(b);return hash.digest('hex');}
async function matches(path,a){try{return (await stat(path)).size===a.size&&await sha256(path)===a.sha256;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
export async function acquire(a,directory,fetcher=fetch,companions=[]){
 const file=join(directory,a.name);if(await matches(file,a))return file;
 const partial=file+'.partial';await rm(partial,{force:true});
 if(a.repack){
  const input=await acquire({...a,name:a.name+'.upstream.zst',sha256:a.repack.sha256,size:a.repack.size,repack:undefined},directory,fetcher);
  const appendFiles=[];for(const extra of a.repack.appendAssets??[]){const companion=companions.find(v=>v.name===extra.asset);if(!companion)throw Error('Missing subset notice companion');appendFiles.push({file:await acquire(companion,directory,fetcher,companions),path:extra.path});}
  execFileSync('python3',['-I',fileURLToPath(new URL('./tool-repack.py',import.meta.url)),input,partial,JSON.stringify({...a.repack,appendFiles})],{timeout:600000,stdio:['ignore','pipe','pipe']});
  if(!await matches(partial,a)){await rm(partial,{force:true});throw Error('Subset asset differs from reviewed recipe: '+a.name);}
  await rename(partial,file);return file;
 }
 if(a.recompress){
  const input=await acquire({...a,name:a.name+'.upstream.xz',...a.recompress,recompress:undefined},directory,fetcher);
  execFileSync('python3',['-I',fileURLToPath(new URL('./tool-recompress.py',import.meta.url)),input,partial],{timeout:600000,stdio:['ignore','pipe','pipe']});
  if(!await matches(partial,a)){await rm(partial,{force:true});throw Error('Recompressed asset differs from reviewed recipe: '+a.name);}
  await rename(partial,file);return file;
 }
 let headers={};
 // Acquisition-only provider detail. Installed tool catalogs contain our release URLs only.
 if(a.upstream.startsWith('https://ghcr.io/v2/homebrew/core/ghidra/blobs/')){
  const r=await fetcher('https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/ghidra:pull');if(!r.ok)throw Error('Registry authorization failed');
  const body=await r.json();if(typeof body.token!=='string'||body.token.length>8192)throw Error('Invalid registry authorization');headers.Authorization='Bearer '+body.token;
 }
 const r=await fetcher(a.upstream,{headers,signal:AbortSignal.timeout(600000)});if(!r.ok||!r.body)throw Error('Acquisition failed: '+a.name+' HTTP '+r.status);
 let size=0;const out=await open(partial,'wx',0o600);
 try{for await(const b of r.body){size+=b.byteLength;if(size>a.size)throw Error('Oversized upstream asset');await out.writeFile(b);}await out.sync();}
 finally{await out.close();}
 if(!await matches(partial,a)){await rm(partial,{force:true});throw Error('Upstream asset differs from reviewed recipe: '+a.name);}
 await rename(partial,file);return file;
}
const gh=(...args)=>execFileSync('gh',args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:4*1024**2}).trim();
function api(path){return JSON.parse(gh('api',path));}
function release(recipe){
 try{return api(`repos/${recipe.repository}/releases/tags/${recipe.tag}`);}
 catch(e){
  if(!e.stderr?.includes('HTTP 404'))throw e;
  // The by-tag endpoint does not expose untagged drafts. Reconcile exact drafts through inventory.
  const pages=JSON.parse(gh('api',`repos/${recipe.repository}/releases?per_page=100`,'--paginate','--slurp'));
  return pages.flat().find(r=>r.tag_name===recipe.tag);
 }
}
export async function waitFor(reader,ready,attempts=20,delayMs=500){
 for(let i=0;i<attempts;i++){const value=await reader();if(ready(value))return value;if(i+1<attempts)await new Promise(ok=>setTimeout(ok,delayMs));}
 throw Error('Release visibility is unresolved; inspect this exact tag before retrying');
}
async function readback(recipe,assets,directory,download=true){
 const current=await waitFor(()=>release(recipe),r=>r&&r.assets.length>=assets.length);
 if(current.assets.length!==assets.length)throw Error('Release asset inventory differs');
 for(const a of assets){
  const remote=current.assets.find(x=>x.name===a.name);if(!remote||remote.size!==a.size)throw Error('Missing/different asset: '+a.name);
  if(remote.digest&&remote.digest!=='sha256:'+a.sha256)throw Error('Remote digest differs: '+a.name);
  if(!download){if(remote.digest!=='sha256:'+a.sha256)throw Error('Published asset digest is unavailable');continue;}
  const dest=join(directory,'readback',a.name);await mkdir(dest,{recursive:true});
  gh('release','download',recipe.tag,'--repo',recipe.repository,'--pattern',a.name,'--dir',dest,'--clobber');
  if(!await matches(join(dest,a.name),a))throw Error('Downloaded release bytes differ: '+a.name);
  console.error('Verified release bytes: '+a.name);
 }
 return current;
}
export async function mirror(recipe,directory,publish=false){
 validateRecipe(recipe);await mkdir(directory,{recursive:true});
 const manifest=Buffer.from(JSON.stringify(recipe,null,2)+'\n');
 const manifestAsset={name:'manifest.json',size:manifest.length,sha256:createHash('sha256').update(manifest).digest('hex')};
 const file=await open(join(directory,'manifest.json'),'w',0o600);try{await file.writeFile(manifest);}finally{await file.close();}
 const assets=[...recipe.assets,manifestAsset];
 if(!publish){for(const a of recipe.assets)await acquire(a,directory,fetch,recipe.assets);return {state:'prepared',tag:recipe.tag,assets:assets.length};}
 if(process.env.GITHUB_ACTIONS==='true'){
  if(process.env.TOOL_RELEASE_IMMUTABLE_READY!=='true')throw Error('Repository immutability setup is not confirmed');
 }else if(api(`repos/${recipe.repository}/immutable-releases`).enabled!==true)throw Error('Immutable releases must be enabled before publication');
 let current=release(recipe);
 if(current&&!current.draft){
  current=await readback(recipe,assets,directory,false);
  if(current.immutable!==true)throw Error('Existing release is not immutable');
  return {state:'published_verified',tag:recipe.tag,url:current.html_url,assets:assets.length};
 }
 for(const a of recipe.assets)await acquire(a,directory,fetch,recipe.assets);
 if(!current){
  // An unknown create response ends this invocation; a later invocation reconciles by exact tag.
  gh('release','create',recipe.tag,'--repo',recipe.repository,'--draft','--latest=false','--target',process.env.GITHUB_SHA??execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),'--title',recipe.title,'--notes',recipe.redistribution);
  current=await waitFor(()=>release(recipe),Boolean);
 }
 if(current.draft){
  for(const a of assets){
   const existing=current.assets.find(v=>v.name===a.name);
   if(existing){if(existing.size!==a.size||existing.digest&&existing.digest!=='sha256:'+a.sha256)throw Error('Existing draft asset differs');continue;}
   // No clobber or automatic upload retry. A lost response is reconciled by readback on rerun.
   gh('release','upload',recipe.tag,join(directory,a.name),'--repo',recipe.repository);
  }
  await readback(recipe,assets,directory);
  try{gh('release','edit',recipe.tag,'--repo',recipe.repository,'--draft=false','--latest=false');}
  catch(e){current=release(recipe);if(!current||current.draft)throw Error('Publication outcome is unknown; inspect this exact tag before retrying',{cause:e});}
 }
 await waitFor(()=>release(recipe),r=>r&&!r.draft);
 current=await readback(recipe,assets,directory,false);
 if(current.draft||current.immutable!==true)throw Error('Published release is not verified immutable');
 return {state:'published_verified',tag:recipe.tag,url:current.html_url,assets:assets.length};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [recipePath,directory,...flags]=process.argv.slice(2);
 const recipe=JSON.parse(await readFile(recipePath,'utf8'));
 console.log(JSON.stringify(await mirror(recipe,resolve(directory),flags.includes('--publish'))));
}
