import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,join} from 'node:path';
import {access} from 'node:fs/promises';
const exec=promisify(execFile);
/** Execute npm without a shell, including Windows where npm is a .cmd shim. */
export async function runNpm(args,options){
 if(process.platform==='win32'){
  const candidates=[process.env.npm_execpath,join(dirname(process.execPath),'node_modules/npm/bin/npm-cli.js'),...(process.env.PATH??'').split(';').filter(Boolean).map(path=>join(path,'node_modules/npm/bin/npm-cli.js'))].filter(Boolean);
  for(const path of candidates)try{await access(path);return exec(process.execPath,[path,...args],options);}catch(error){if(error.code!=='ENOENT')throw error;}
  throw new Error('npm CLI was not found beside Node or on PATH.');
 }
 return exec('npm',args,options);
}
