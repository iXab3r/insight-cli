import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {exportsOf} from '../business/prepare.mjs';
const exec=promisify(execFile);
export async function fixtures(root,{clang='clang',lld='lld-link'}={}){
 await mkdir(root,{recursive:true});const out=[];
 for(const [name,size] of [['tiny',256],['large',80*1024**2]]){
  const dir=join(root,name);await mkdir(dir,{recursive:true});
  const source=`__declspec(dllexport) const unsigned char owned_data[${size}]={1,2,3,4};\n__declspec(dllexport) const char owned_string[]="owned performance fixture";\n__declspec(dllexport) __declspec(noinline) int owned_add(int x){return x+17;}\n__declspec(dllexport) __declspec(noinline) int owned_hash(const char *p){unsigned h=5381;while(*p)h=h*33+(unsigned char)*p++;return h;}\n__declspec(dllexport) int main(void){return owned_add(owned_hash(owned_string))+owned_data[0];}\n`;
  const c=join(dir,'owned.c'),obj=join(dir,'owned.obj'),path=join(dir,'owned.exe');await writeFile(c,source);
  await exec(clang,['--target=x86_64-pc-windows-msvc','-O1','-fno-builtin','-c',c,'-o',obj]);
  await exec(lld,['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/out:'+path,obj]);
  const bytes=await readFile(path);out.push({name,path:resolve(path),size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),sourceSha256:createHash('sha256').update(source).digest('hex'),exports:exportsOf(bytes)});
 }
 await writeFile(join(root,'compiler.json'),JSON.stringify({clang:(await exec(clang,['--version'])).stdout,lld:(await exec(lld,['--version'])).stdout,compile:['--target=x86_64-pc-windows-msvc','-O1','-fno-builtin','-c'],link:['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0'],recipeSha256:createHash('sha256').update(await readFile(new URL(import.meta.url))).digest('hex')},null,2)+'\n');
 await writeFile(join(root,'manifest.json'),JSON.stringify(out,null,2)+'\n');return out;
}
if(process.argv[1]===new URL(import.meta.url).pathname)console.log(JSON.stringify(await fixtures(resolve(process.argv[2]))));
