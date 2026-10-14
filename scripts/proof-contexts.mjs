// Owned native context fixture. The public Factory command tree is a separate delivery gate.
import assert from 'node:assert/strict';
import {promisify} from 'node:util';
import {execFile} from 'node:child_process';
import {mkdtemp,realpath,mkdir,writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {Workspace} from '../skills/ghidra-coordinator/dist/src/workspace.js';
import {GhidraContexts} from '../skills/ghidra-coordinator/dist/src/contexts.js';
import {GhidraServer} from '../skills/ghidra-coordinator/dist/src/server.js';
import {nativeInputs,pinnedMcpJar} from '../skills/ghidra-coordinator/dist/src/native-inputs.js';
import {HttpBridge} from '../skills/ghidra-coordinator/dist/src/transport.js';
import {setTimeout as delay} from 'node:timers/promises';
const options={},argv=process.argv.slice(2);
for(let i=0;i<argv.length;i++){if(argv[i]==='--ack-disposable')options.ack=true;else if(argv[i].startsWith('--')&&argv[i+1])options[argv[i].slice(2)]=argv[++i];else throw Error('Invalid proof argument');}
assert.equal(options.ack,true);
assert.ok(!Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]),'Native proof is local only');
for(const key of ['ghidra-home','java','mcp-jar','clang','lld'])assert.ok(options[key],`Missing --${key}`);
const root=await realpath(await mkdtemp('/tmp/insight-context-proof-')),exec=promisify(execFile);
const workspace=new Workspace(join(root,'profile'),'default'),secrets=new Map();
const values={java:options.java,ghidraHome:options['ghidra-home'],mcpJar:options['mcp-jar'],maxContexts:4};
const context={profile:{name:'default',values},environment:{PATH:process.env.PATH},signal:new AbortController().signal,fetch,
  secrets:{get:async key=>secrets.get(key),set:async(key,value)=>{secrets.set(key,value);},delete:async key=>{secrets.delete(key);},
    require:async key=>{assert.ok(secrets.has(key),'Missing fixture credential');return secrets.get(key);}}};
let runtime,server,receipt;
try{
  const inputs=await nativeInputs(values);runtime=new GhidraContexts(workspace,inputs,context);server=new GhidraServer(workspace.directory,inputs,context);
  async function input(label,increment){const dir=join(root,label);await mkdir(dir);const c=join(dir,'fixture.c'),obj=join(dir,'fixture.obj'),exe=join(dir,'fixture.exe');
    await writeFile(c,`__declspec(noinline) int first(int x){return x+${increment};}\nint main(void){return first(2);}\n`);
    await exec(options.clang,['--target=x86_64-pc-windows-msvc','-O0','-c',c,'-o',obj]);
    await exec(options.lld,['/entry:main','/subsystem:console','/nodefaultlib','/export:first','/export:main','/out:'+exe,obj]);return workspace.importTarget(exe);}
  const target=await input('client',17),helper=await input('helper',23);assert.notEqual(target.id,helper.id);assert.equal(target.name,helper.name);
  const a=workspace.reserveOpen(target.id,'new',{autoAnalyze:true},'open-A').context;
  const b=workspace.reserveOpen(target.id,'new',{autoAnalyze:true},'open-B').context;
  const ah=workspace.reserveOpen(helper.id,a.session,{autoAnalyze:true}).context;
  const bh=workspace.reserveOpen(helper.id,b.session,{autoAnalyze:true}).context;
  const opened=await Promise.allSettled([runtime.open(a),runtime.open(b),runtime.open(ah),runtime.open(bh)]);
  for(const result of opened)if(result.status==='rejected')throw result.reason;
  const excess=workspace.reserveOpen(target.id,'new',{autoAnalyze:true}).context;
  await assert.rejects(runtime.open(excess),/capacity is occupied/);
  async function address(scope){const result=await runtime.call(scope,'/get_functions',{functions:'first',include_call_context:false});return result.functions.first.entry_point;}
  const aa=await address(a),ba=await address(b),ha=await address(ah);assert.equal(aa,ba);assert.equal(aa,ha);
  await runtime.call(a,'/set_comment',{address:aa,type:'eol',comment:'Private A'});
  const saved=await runtime.saved(a),before=workspace.context(a);
  workspace.saveContext(a,before.generation,{workingSnapshot:saved,scalars:[{address:aa.toLowerCase().replace(/^0x/,''),field:'comment.eol',original:null,local:'Private A'}]});
  assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A');
  assert.equal((await runtime.call(b,'/get_comment',{address:ba})).eol,null);
  assert.equal((await runtime.call(ah,'/get_comment',{address:ha})).eol,null);
  await runtime.close(ah);
  const wrongSource={...context,fetch:async(...args)=>{
    const response=await fetch(...args),url=new URL(args[0]);
    if(url.pathname!=='/get_program_options'||url.searchParams.get('program')!=='/program')return response;
    const result=await response.json();
    for(const item of result.options)if(item.name==='Executable SHA256')item.value='f'.repeat(64);
    return Response.json(result);
  }};
  await assert.rejects(runtime.fork(wrongSource).open(excess),/input bytes/);
  assert.equal(workspace.context(excess).state,'opening');
  assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A');
  await runtime.mode(a,'gui');assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A');
  await runtime.call(a,'/set_comment',{address:aa,type:'eol',comment:'Private A through GUI'});
  const gui=await runtime.saved(a),prior=workspace.context(a);
  workspace.saveContext(a,prior.generation,{workingSnapshot:gui,scalars:[{address:aa.toLowerCase().replace(/^0x/,''),field:'comment.eol',original:null,local:'Private A through GUI'}]});
  await runtime.mode(a,'headless');assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A through GUI');
  const owned=JSON.parse(await readFile(join(workspace.directory,'ghidra-native/context',a.id,'current.json'),'utf8'));
  assert.equal(owned.context,a.id);assert.equal(owned.target,target.id);assert.ok(owned.root.startsWith(workspace.directory+'/'));
  const http=new HttpBridge(owned.endpoint,fetch,undefined,await context.secrets.require(owned.tokenSecret));
  const identity=await http.instance();assert.equal(identity.pid,owned.pid);assert.equal(identity.tcp_port,Number(new URL(owned.endpoint).port));
  assert.ok(identity.project_path.startsWith(owned.root+'/'));
  process.kill(owned.pid,'SIGKILL');
  for(let i=0;i<100;i++){let live=true;try{process.kill(owned.pid,0);}catch(error){if(error.code==='ESRCH')live=false;else throw error;}
    if(!live)break;if(i===99)throw Error('Owned backend did not stop');await delay(50);}
  await runtime.open(a);assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A through GUI');
  await runtime.close(a);await runtime.open(a);assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A through GUI');
  await runtime.dispose();
  runtime=new GhidraContexts(workspace,inputs,context);await runtime.open(a);
  assert.equal((await runtime.call(a,'/get_comment',{address:aa})).eol,'Private A through GUI');
  const reopened=new Workspace(workspace.directory,'default');
  try{assert.equal(reopened.context(a).scalars[0].local,'Private A through GUI');assert.equal(reopened.context(b).scalars.length,0);}finally{reopened.close();}
  receipt={schema:1,scope:'owned native durable context lifecycle proof',targets:2,researchSessions:2,totalSessions:workspace.sessions().length,
    privateContexts:4,capacityRefusalReservations:1,equalBasenames:true,
    equalFunctionAddresses:true,privateReadOwnWrites:true,otherAgentUnchanged:true,otherTargetUnchanged:true,
    headlessGuiInterchange:true,closeReopen:true,replacementRuntimePreservesWork:true,unpublishedChangesRetained:true,capacityLimit:true,
    backendSigkillPreservesWork:true,wrongSourceStartupRejected:true,
    ghidra:inputs.ghidraVersion,java:'21',node:process.versions.node,mcpJarSha256:pinnedMcpJar,runtimeFingerprint:inputs.fingerprint,
    limitations:['direct context layer; public CLI/Factory and crash matrix remain separate gates','synthetic fixture credential interface']};
}catch(error){console.error(error.message);console.error('Owned fixture retained for diagnostics:',root);process.exitCode=1;}
finally{await runtime?.dispose();await server?.stop();workspace.close();}
if(receipt){await writeFile(join(root,'sanitized-receipt.json'),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));}
