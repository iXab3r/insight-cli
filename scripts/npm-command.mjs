import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,join} from 'node:path';
const exec=promisify(execFile);
/** Execute npm without a shell, including Windows where npm is a .cmd shim. */
export function runNpm(args,options){
 if(process.platform==='win32')return exec(process.execPath,[process.env.npm_execpath??join(dirname(process.execPath),'node_modules/npm/bin/npm-cli.js'),...args],options);
 return exec('npm',args,options);
}
