// Native backend feasibility only: this is not a public adapter or independent agent gate.
import assert from 'node:assert/strict';import {spawn} from 'node:child_process';import {readFile,mkdir,writeFile} from 'node:fs/promises';import {join,resolve} from 'node:path';import {pathToFileURL} from 'node:url';import {setTimeout as delay} from 'node:timers/promises';import {digest} from './public-fixture.mjs';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const [packageRoot,bareFixture,cfFixture,directory]=process.argv.slice(2);assert.ok(directory,'Arguments: reviewed-frida-npm-package owned-bare-fixture owned-cf-fixture disposable-directory');
const frida=await import(pathToFileURL(join(resolve(packageRoot),'build/src/frida.js')).href),metadata=JSON.parse(await readFile(join(packageRoot,'package.json'),'utf8'));assert.equal(metadata.version,'17.24.0');await mkdir(directory,{recursive:true,mode:0o700});
const source=`const module=Process.mainModule;send({kind:'exports',module:module.name,symbols:module.enumerateExports().filter(e=>e.name==='quote_total')});Interceptor.attach(module.getExportByName('quote_total'),{onEnter(args){this.count=args[0].toInt32();},onLeave(value){send({kind:'quote',count:this.count,result:value.toInt32()});}});send({kind:'ready'});`;
const results=[];
for(const [kind,file]of [['bare-c',bareFixture],['core-foundation',cfFixture]]){
 let child,session,script,timer,closed,launchError;const cancellable=new frida.Cancellable(),messages=[];let stdout='',stderr='';
 try{
  child=spawn(resolve(file),[],{stdio:['ignore','pipe','pipe']});closed=new Promise(ok=>{child.once('close',ok);child.once('error',error=>{launchError=error;});});child.stdout.on('data',b=>stdout=(stdout+b).slice(-65536));child.stderr.on('data',b=>stderr=(stderr+b).slice(-8192));
  for(let i=0;i<50&&!stdout.includes('READY');i++){if(launchError)throw launchError;assert.equal(child.exitCode,null);await delay(100);}assert.match(stdout,/READY/);
  timer=setTimeout(()=>cancellable.cancel(),10000);session=await frida.attach(child.pid,{},cancellable);script=await session.createScript(source,{},cancellable);
  script.message.connect(message=>{assert.ok(messages.length<1000);messages.push(message);});await script.load(cancellable);await delay(1600);await script.unload();script=undefined;await session.detach();session=undefined;
  const quotes=messages.filter(m=>m.type==='send'&&m.payload?.kind==='quote').map(m=>m.payload);assert.ok(quotes.length>=10);for(const q of quotes)assert.equal(q.result,q.count<11?13*q.count:8*q.count+21);
  results.push({fixture:kind,sha256:digest(await readFile(file)),state:'observed',quotes,targetAlive:child.exitCode===null,cleanDetach:true});
 }catch(error){results.push({fixture:kind,sha256:digest(await readFile(file)),state:'failed',error:String(error),targetAlive:child?.exitCode===null});}
 finally{if(timer)clearTimeout(timer);cancellable.cancel();if(script)await script.unload().catch(()=>{});if(session)await session.detach().catch(()=>{});if(child?.pid&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');await Promise.race([closed,delay(1000)]);if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await closed;}}}
}
const report={schema:1,scope:'Frida backend feasibility, not public CLI or agent acceptance',node:process.version,backend:'Official frida 17.24.0 Node NAPI v8',results,adapterAccepted:false};await writeFile(join(directory,'result.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(report));assert.ok(results.some(r=>r.fixture==='core-foundation'&&r.state==='observed'&&r.cleanDetach));
