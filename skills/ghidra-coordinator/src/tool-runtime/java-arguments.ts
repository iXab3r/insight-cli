import {writeFile} from 'node:fs/promises';
import {join,win32} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);

/** The Windows java launcher uses ACP, while Java 21 javac reads UTF-8 @files. */
export async function encodeJavaLauncherFile(value:string):Promise<Buffer> {
 if(!/[^\x00-\x7f]/.test(value))return Buffer.from(value,'ascii');
 // Fixed script; text travels over stdin, never through PowerShell's command parser.
 // Match the native launcher without silently replacing unmappable path characters.
 const script='[Console]::InputEncoding=[Text.UTF8Encoding]::new($false,$true);$s=[Console]::In.ReadToEnd();$e=[Text.Encoding]::GetEncoding([Text.Encoding]::Default.CodePage,[Text.EncoderExceptionFallback]::new(),[Text.DecoderExceptionFallback]::new());[Console]::Out.Write([Convert]::ToBase64String($e.GetBytes($s)))';
 const pending=exec(join(process.env.SystemRoot??'C:\\Windows','System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,timeout:15000,maxBuffer:Math.max(4096,Buffer.byteLength(value)*4)});
 pending.child.stdin?.on('error',()=>{});pending.child.stdin?.end(value,'utf8');
 try{return Buffer.from((await pending).stdout.trim(),'base64');}
 catch{throw new Error('Java classpath cannot be encoded for the Windows launcher; no process was started. Inspect the retained run and the JDK system-code-page path restrictions.');}
}

/** Java's quoted argument-file grammar (not JSON: it has no \u escapes). */
export function quoteJavaArgument(value:string):string {
 if(value.includes('\0'))throw new Error('Java argument contains NUL');
 return '"'+value.replace(/[\\"\n\r\t\f]/g,c=>({'\\':'\\\\','"':'\\"','\n':'\\n','\r':'\\r','\t':'\\t','\f':'\\f'}[c]!))+'"';
}

/** Keep all other argv entries in place, including JVM flags and application arguments. */
export async function javaClasspathArguments(root:string,tool:string,executable:string,args:string[],platform:string=process.platform):Promise<string[]> {
 if(platform!=='win32'||tool!=='ghidra'||!/^(java|javac)\.exe$/i.test(win32.basename(executable)))return args;
 // Conservative upper bound for Windows quoting, with room below CreateProcess's 32767 limit.
 if(executable.length*2+args.reduce((n,arg)=>n+arg.length*2+3,3)<=28000)return args;
 const index=args.findIndex(arg=>arg==='-cp'||arg==='-classpath'||arg==='--class-path');
 if(index<0||args[index+1]===undefined)return args;
 const path=join(root,'java-classpath.args');
 const content='-classpath\n'+quoteJavaArgument(args[index+1]!)+'\n';
 const bytes=/^java\.exe$/i.test(win32.basename(executable))&&process.platform==='win32'?await encodeJavaLauncherFile(content):Buffer.from(content,'utf8');
 await writeFile(path,bytes,{flag:'wx',mode:0o600});
 return [...args.slice(0,index),'@'+path,...args.slice(index+2)];
}
