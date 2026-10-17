// Read-only exact-byte check of a global installation against its packed candidate.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {readFile,writeFile,realpath,stat} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import * as tar from 'tar';
const [archive,installed,output]=process.argv.slice(2);assert.ok(archive&&installed&&output,'tarball, installed package root/POSIX executable and output JSON required');
const path=await realpath(installed),root=(await stat(path)).isDirectory()?path:dirname(dirname(dirname(path))),seen=new Set(),checks=[];
const digest=async file=>{const hash=createHash('sha256');for await(const bytes of createReadStream(file))hash.update(bytes);return hash.digest('hex');};
await tar.t({file:archive,strict:true,onReadEntry(entry){
 if(entry.type!=='File')return;
 assert.ok(entry.path.startsWith('package/'));const name=entry.path.slice(8);assert.ok(name&&!name.startsWith('/')&&!name.includes('\\')&&!name.split('/').includes('..'));assert.ok(!seen.has(name));seen.add(name);
 const hash=createHash('sha256');entry.on('data',bytes=>hash.update(bytes));const check=new Promise((ok,bad)=>{entry.on('error',bad);entry.once('end',()=>{const expected=hash.digest('hex');digest(join(root,name)).then(actual=>{assert.equal(actual,expected,'Global package differs: '+name);ok();}).catch(bad);});});checks.push(check);void check.catch(()=>{});
}});await Promise.all(checks);assert.ok(seen.has('.cli-package-build.json')&&seen.has('dist/src/bin.js'));
const result={state:'passed',files:seen.size,packageSha256:await digest(archive),build:JSON.parse(await readFile(join(root,'.cli-package-build.json'),'utf8'))};await writeFile(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
