import {mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runNpm} from './npm-command.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
try{
 const result=await runNpm(['pack','--workspace','@eyeauras/insight-cli','--pack-destination','artifacts'],{cwd:root,maxBuffer:1024*1024});
 process.stdout.write(result.stdout);process.stderr.write(result.stderr);
}catch(error){process.stdout.write(error.stdout??'');process.stderr.write(error.stderr??String(error));process.exitCode=typeof error.code==='number'?error.code:1;}
