import {mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runNpm} from './npm-command.mjs';
import {packCli} from './factory-bundle.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
try{
 const result=await runNpm(['run','build'],{cwd:root,maxBuffer:1024*1024});
 process.stdout.write(result.stdout);process.stderr.write(result.stderr);
 const {packed}=await packCli(fileURLToPath(new URL('../artifacts/',import.meta.url)));
 console.log(packed.filename);
}catch(error){process.stdout.write(error.stdout??'');process.stderr.write(error.stderr??String(error));process.exitCode=typeof error.code==='number'?error.code:1;}
