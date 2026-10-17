import {fileURLToPath} from 'node:url';
import {CliError} from '@eyeauras/cli-factory';
import {fileSha256} from './archives.js';
/** Internal, first-party exec helper. No service or timer in the owner is needed after exec. */
export async function deadlineLaunch(executable:string,args:string[],timeoutMs:number){
 if(process.platform!=='darwin'||process.arch!=='arm64')throw new CliError('This tool requires the packaged macOS ARM64 native deadline.',{code:'tool.unsupported'});
 if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>600000)throw new CliError('Native deadline must be between one and 600 seconds.',{code:'tool.configuration'});
 const helper=fileURLToPath(new URL('../../../runtime/native/deadline-exec-darwin-arm64',import.meta.url));
 if(await fileSha256(helper)!=='32c146075d1c83422b068eeedd4a244d5e30cb768b279b185756c5d3b8008d88')throw new CliError('Packaged native deadline differs from its reviewed build.',{code:'tool.binding'});
 return {executable:helper,arguments:[String(Math.ceil(timeoutMs/1000)),'--',executable,...args]};
}
