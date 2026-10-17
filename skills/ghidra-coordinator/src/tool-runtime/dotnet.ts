import {join} from 'node:path';
import {catalogArtifact} from './catalog.js';
import type {ToolLaunch} from './installer.js';
import {fail} from '../model.js';
const runtimeHashes:Record<string,string>={
 'darwin-arm64':'fdf7ef21688338ad5d1d99d7eca7f3cf2e159c86e552d3f5acd0553b11c80ca6',
 'darwin-x64':'50fd6ea005731494a6144fd4617746f4155fdc0f3682d0ba7292eac9e9bf46e3',
 'linux-x64':'958c952691d2c3f8ce21f717f4e911c02b5da0e21ead21bd576368c454b79c77',
 'win32-x64':'8db74a746baa450925d01325a2108ccf6ac39af4018047475292ae155c013d89',
};
/** Shared private runtime dependency; it is not an independent analytical tool. */
export function dotnetArtifact(platform:string=process.platform,architecture=process.arch){
 const hash=runtimeHashes[platform+'-'+architecture];if(!hash)fail('configuration','No pinned private .NET runtime for this platform; select an external compatible tool executable.');
 return catalogArtifact(hash);
}
export function dotnetLaunch(root:string,entryPoint:string):ToolLaunch{return {
 executable:join(root,'dotnet'+(process.platform==='win32'?'.exe':'')),arguments:[entryPoint],
 environment:{DOTNET_ROOT:root,DOTNET_MULTILEVEL_LOOKUP:'0',DOTNET_CLI_TELEMETRY_OPTOUT:'1',DOTNET_NOLOGO:'1'},
};}
