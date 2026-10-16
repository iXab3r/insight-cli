import {readFile,readdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {validateRecipe} from './tool-release.mjs';
const root=new URL('../',import.meta.url),directory=new URL('scripts/tool-distributions/',root),catalog={};
for(const file of (await readdir(directory)).sort()){
 if(!file.endsWith('.json'))continue;
 const r=validateRecipe(JSON.parse(await readFile(new URL(file,directory),'utf8')));
 for(const a of r.assets){
  if(a.role!=='binary')continue;
  if(!['zip','tgz'].includes(a.format)||typeof a.root!=='string')throw Error('Binary recipe omitted its installation layout');
  catalog[a.sha256]={...Object.fromEntries(['name','sha256','size','format','root','license'].map(k=>[k,a[k]])),url:`https://github.com/${r.repository}/releases/download/${r.tag}/${a.name}`};
 }
}
const path=new URL('skills/ghidra-coordinator/runtime/tool-catalog.json',root),bytes=JSON.stringify(catalog,null,2)+'\n';
if(process.argv.includes('--check')){if(await readFile(path,'utf8')!==bytes)throw Error('Tool catalog differs; regenerate with node scripts/tool-catalog.mjs');}
else await writeFile(path,bytes);
console.log('Pinned tool catalog verified:',Object.keys(catalog).length,'binary assets');
