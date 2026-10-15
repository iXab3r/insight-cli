import {readFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
/** Bind executable native acceptance inputs; prose and offline packaging have separate gates. */
export async function p3Inputs(){
 const files=['package.json','package-lock.json','vendor/provenance.json','vendor/factory-ipc-a2094fb.tgz','scripts/proof-p3.mjs','scripts/native-p3-inputs.mjs','scripts/native-proof-guard.mjs','skills/ghidra-coordinator/package.json','skills/ghidra-coordinator/runtime/GhidraMCP-7.0.0.jar'];
 async function walk(path,accept){for(const e of await readdir(join(root,path),{withFileTypes:true})){const name=join(path,e.name);if(e.isDirectory())await walk(name,accept);else if(e.isFile()&&accept(name))files.push(name);}}
 await walk('skills/ghidra-coordinator/src',n=>n.endsWith('.ts'));await walk('skills/ghidra-coordinator/dist/src',n=>n.endsWith('.js'));
 await walk('skills/ghidra-coordinator/references',n=>/\.(java|json)$/.test(n));await walk('scripts/fixtures/p3',()=>true);
 return Object.fromEntries(await Promise.all(files.sort().map(async n=>[n.split('\\').join('/'),createHash('sha256').update(await readFile(join(root,n))).digest('hex')])));
}
