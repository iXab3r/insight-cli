import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=new URL('../',import.meta.url);
const destination=new URL('skills/ghidra-coordinator/README.md',root);

export function packageReadme(source){
 return source.replaceAll('\r\n','\n').replace(/\]\(([^\s)]+)\)/g,(link,target)=>{
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(target)) return link;
  return `](${new URL(target,'https://github.com/iXab3r/insight-cli/blob/main/').href})`;
 });
}

export async function checkPackageReadme(){
 const expected=packageReadme(await readFile(new URL('README.md',root),'utf8'));
 const actual=(await readFile(destination,'utf8')).replaceAll('\r\n','\n');
 assert.equal(actual,expected,'Package README is stale. Run node scripts/sync-package-readme.mjs after editing the root README.');
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--check')) await checkPackageReadme();
 else await writeFile(destination,packageReadme(await readFile(new URL('README.md',root),'utf8')));
}
