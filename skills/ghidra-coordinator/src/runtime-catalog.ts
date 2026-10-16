import {release} from 'node:os';
import {fail} from './model.js';
export interface RuntimeArtifact {name:string;url:string;sha256:string;format:'zip'|'tgz';root:string;license:string}
const github='https://github.com/';
export const ghidraArchive:RuntimeArtifact={name:'ghidra-12.1.2',url:github+'NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip',sha256:'b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d',format:'zip',root:'ghidra_12.1.2_PUBLIC',license:'Apache-2.0 and included third-party licenses'};
const bottles:Record<string,string>={arm64_sonoma:'40f68357d6b62a08429c36228907c995e3449283b6d2e08ba5a4e30b53a09725',arm64_sequoia:'90aa942184fca2337ad0a123f818f37372ea642e8e69e969d45cc144a6f26fdf',arm64_tahoe:'079007d8a3a477c8d5901e6596947612d86c8641956424a2bcb71ecd798bedcc',sonoma:'e30f8c84b64331f87f6ef1890cbdded6672bb7fcc8b674794ac93e4b3e62ad2b'};
const jdks:Record<string,[string,string]>={
 'darwin-arm64':['aarch64_mac','6ebcf221c9b41507b14c098e93c6ead6440b8d9bd154f8ec666c4c73abbdb201'],
 'darwin-x64':['x64_mac','34180eb03e6d207c388cce3da668f6cc7cd7508c185c24782fadac2c9c0e66f9'],
 'linux-x64':['x64_linux','4b2220e232a97997b436ca6ab15cbf70171ecff52958a46159dfa5a8c44ca4de'],
 'win32-x64':['x64_windows','d3625e7cadf23787ea540229544b6e2ab494b3b54da1801879e583e1dfee0a64'],
};
export function runtimeCatalog(platform:string=process.platform,arch:string=process.arch,kernel=release()) {
 const jdk=jdks[platform+'-'+arch];if(!jdk)fail('configuration','No verified managed runtime for this OS/architecture; use an external compatible Ghidra installation.');
 const windows=platform==='win32',format=windows?'zip':'tgz',extension=windows?'zip':'tar.gz';
 const java:RuntimeArtifact={name:'temurin-21.0.11+10-'+platform+'-'+arch,url:github+'adoptium/temurin21-binaries/releases/download/jdk-21.0.11%2B10/OpenJDK21U-jdk_'+jdk[0]+'_hotspot_21.0.11_10.'+extension,sha256:jdk[1],format,root:'jdk-21.0.11+10'+(platform==='darwin'?'.jdk/Contents/Home':''),license:'GPL-2.0 WITH Classpath-exception-2.0; included legal notices'};
 let ghidra=ghidraArchive;
 if(platform==='darwin'){
   const major=Number(kernel.split('.')[0]);if(major<23)fail('configuration','Managed macOS runtimes require macOS 14 or newer.');
   const tag=arch==='x64'?'sonoma':major>=25?'arm64_tahoe':major>=24?'arm64_sequoia':'arm64_sonoma',hash=bottles[tag]!;
   ghidra={name:'ghidra-12.1.2-'+tag,url:'https://ghcr.io/v2/homebrew/core/ghidra/blobs/sha256:'+hash,sha256:hash,format:'tgz',root:'ghidra/12.1.2/libexec',license:ghidraArchive.license};
 }
 return {schema:1,ghidraVersion:'12.1.2',javaVersion:'21.0.11+10',platform,architecture:arch,ghidra,java};
}
