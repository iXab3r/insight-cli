import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,readdir,rm,writeFile,copyFile,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,delimiter} from 'node:path';
import {javaClasspathArguments,quoteJavaArgument,encodeJavaLauncherFile} from '../src/tool-runtime/java-arguments.js';
import {runTool} from '../src/tool-runtime/run.js';
import {launchProcess,processStatus} from '../src/tool-runtime/supervisor.js';
import {randomUUID} from 'node:crypto';

async function fixture(t:test.TestContext){const root=await mkdtemp(join(tmpdir(),'java-args-'));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test('Java quoting preserves whitespace, quotes, backslashes, hashes and Unicode',()=>{
 assert.equal(quoteJavaArgument('C:\\space Ω\\tab\t\\"quoted"\n\r\f#end\\'),'"C:\\\\space Ω\\\\tab\\t\\\\\\"quoted\\"\\n\\r\\f#end\\\\"');
 assert.equal(quoteJavaArgument(''),'""');assert.throws(()=>quoteJavaArgument('\0'),/NUL/);
});
test('only long Windows Ghidra java/javac classpaths move into an exclusive owned file',async t=>{
 const root=await fixture(t);
 for(const [i,flag] of ['-cp','-classpath','--class-path'].entries()){
  const run=join(root,String(i));await mkdir(run);
  const cp=(i===1?'C:\\space Ω\\lib\\':'C:\\space #\\lib\\').repeat(2600);
  const original=['-Xmx768m',flag,cp,'Main','literal "quote"','@application-argument'];
  const actual=await javaClasspathArguments(run,'ghidra',i===1?'C:\\jdk\\JAVAC.EXE':'C:\\jdk\\java.exe',original,'win32');
  assert.deepEqual(actual,['-Xmx768m','@'+join(await realpath(run),'java-classpath.args'),'Main','literal "quote"','@application-argument']);
  assert.equal(await readFile(join(run,'java-classpath.args'),'utf8'),'-classpath\n'+quoteJavaArgument(cp)+'\n');
  assert.equal(original[2],cp);
  await assert.rejects(javaClasspathArguments(run,'ghidra',i===1?'C:\\jdk\\javac.exe':'C:\\jdk\\java.exe',original,'win32'),{code:'EEXIST'});
 }
});
test('other tools, platforms, executables, short calls and missing classpaths remain unchanged',async t=>{
 const root=await fixture(t),long=['-cp','x'.repeat(40000),'Main'];
 for(const [tool,exe,args,platform] of [
  ['other','C:\\jdk\\java.exe',long,'win32'],['ghidra','C:\\jdk\\java.exe',long,'linux'],
  ['ghidra','C:\\jdk\\keytool.exe',long,'win32'],['ghidra','C:\\jdk\\java.exe',['-cp','short','Main'],'win32'],
  ['ghidra','C:\\jdk\\java.exe',['x'.repeat(40000),'-cp'],'win32'],
  ['ghidra','C:\\jdk\\java.exe',['x'.repeat(40000)],'win32'],
 ] as const)assert.equal(await javaClasspathArguments(root,tool,exe,args as unknown as string[],platform),args);
 assert.deepEqual(await readdir(root),[]);
});

// Opt-in native regression: use the disposable managed JDK, never the host's PATH Java.
test('Windows JDK compiles and launches with a >32767 classpath and exact quoted arguments',{skip:process.platform!=='win32'||!process.env.INSIGHT_TEST_JDK},async t=>{
 const root=await fixture(t),jdk=process.env.INSIGHT_TEST_JDK!,classes=join(root,'classes spaces');await mkdir(classes);
 const c={appArguments:{AppDataDirectory:root},signal:new AbortController().signal,environment:{PATH:process.env.PATH}};
 const helper=join(root,'Helper.java');await writeFile(helper,'class Helper { static boolean ok() { return true; } }');
 await runTool(c,{tool:'ghidra',role:'compile-dependency',executable:join(jdk,'javac.exe'),arguments:['-d',classes,helper]});
 const unicode=join(root,'unicode Ω-漢字-Ж');await mkdir(unicode);await copyFile(join(classes,'Helper.class'),join(unicode,'Helper.class'));
 const source=join(root,'Echo.java');await writeFile(source,'public class Echo { public static void main(String[] args) throws Exception { System.out.print(Helper.ok() && System.getProperty("java.class.path").equals(java.nio.file.Files.readString(java.nio.file.Path.of(args[0]))) && args[1].equals("quoted \\\"text\\\" \\\\ tail")); } }');
 const compileCp=Array(600).fill(unicode).join(delimiter);assert.ok(compileCp.length>32767);
 await runTool(c,{tool:'ghidra',role:'compile-fixture',executable:join(jdk,'javac.exe'),arguments:['-proc:none','-cp',compileCp,'-d',classes,source]});
 // java.exe itself cannot represent every Unicode character in a non-UTF-8 ACP.
 // Exercise a real non-ASCII path admitted by this host, and refuse lossy conversion.
 let supported:string|undefined;
 for(const name of ['Ж','é','漢','Ω']){try{await encodeJavaLauncherFile(name);supported=name;break;}catch{}}
 assert.ok(supported,'Expected a representable non-ASCII native path');
 const runtime=join(root,'native spaces-'+supported);await mkdir(runtime);
 for(const name of ['Echo.class','Helper.class'])await copyFile(join(classes,name),join(runtime,name));
 const cp=Array(600).fill(runtime).join(delimiter)+';C:\\missing "quote" #\\';
 const expected=join(root,'classpath.txt');await writeFile(expected,cp);
 const result=await runTool(c,{tool:'ghidra',role:'launch-fixture',executable:join(jdk,'java.exe'),arguments:['-cp',cp,'Echo',expected,'quoted "text" \\ tail']});
 assert.equal(result.stdout,'true');
});

test('argument-file preparation failure retains a failed launch receipt without spawning',{skip:process.platform!=='win32'||!process.env.INSIGHT_TEST_JDK},async t=>{
 const root=await fixture(t),id=randomUUID(),run=join(root,'runtime/runs',id);await mkdir(run,{recursive:true});
 const path=join(run,'java-classpath.args');await writeFile(path,'retained previous evidence');
 await assert.rejects(launchProcess(root,{tool:'ghidra',role:'fixture',installation:'fixture'},join(process.env.INSIGHT_TEST_JDK!,'java.exe'),['-cp','x'.repeat(40000),'Main'],{}, {id}),{code:'EEXIST'});
 const record=await processStatus(root,id);assert.equal(record.state,'failed');assert.equal(record.phase,'spawn_failed');assert.equal(record.pid,undefined);
 assert.equal(await readFile(path,'utf8'),'retained previous evidence');
});
