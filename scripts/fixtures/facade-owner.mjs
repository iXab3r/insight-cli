// Installed facade acceptance wrapper. Fault barriers are absent from the shipped runtime.
import {readFileSync,writeFileSync,appendFileSync} from 'node:fs';
import {join} from 'node:path';
import {AppArguments,KeyringSecretStore} from '@eyeauras/cli-factory';
import {runHosted} from '@eyeauras/cli-factory-ipc';
import {createDefinition} from '@ixab3r/insight-cli';
import {GhidraContexts} from '@ixab3r/insight-cli/dist/src/contexts.js';
import {nativeInputs} from '@ixab3r/insight-cli/dist/src/native-inputs.js';

const config=JSON.parse(readFileSync(new URL('./fixture-config.json',import.meta.url),'utf8'));
const appArguments=new AppArguments(config.appArguments),directory=appArguments.AppDataDirectory;
const nativeSecrets=new KeyringSecretStore();
const secretStore={get:(...args)=>nativeSecrets.get(...args),delete:(...args)=>nativeSecrets.delete(...args),
  set(service,account,value){
    appendFileSync(join(directory,'secret-keys.jsonl'),JSON.stringify({service,account})+'\n',{mode:0o600});
    return nativeSecrets.set(service,account,value);
  }};
function barrier(workspace,phase,requestId) {
  let fault;try{fault=JSON.parse(readFileSync(join(directory,'fault.json'),'utf8'));}catch{return;}
  const request=workspace.request(requestId);
  if(fault.phase!==phase||fault.requestId!==request.callerId)return;
  writeFileSync(join(directory,'barrier.json'),JSON.stringify({phase,requestId:request.callerId,ownerPid:process.pid,
    session:request.intent.session,target:request.intent.target}),{mode:0o600});
  // Deliberately freezes this fixture owner until the runner kills its validated PID.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);
}
const backend=async(workspace,context)=>{
  const reserve=workspace.reserveRequest.bind(workspace);
  workspace.reserveRequest=(...args)=>{const result=reserve(...args);barrier(workspace,'accepted',result.request.id);return result;};
  const intent=workspace.publicationIntent.bind(workspace);
  workspace.publicationIntent=(...args)=>{const result=intent(...args);barrier(workspace,'publication_intent',result.request);return result;};
  const complete=workspace.completeSavedRequest.bind(workspace);
  workspace.completeSavedRequest=(...args)=>{const result=complete(...args);barrier(workspace,'local_ack',args[1]);return result;};
  const finish=workspace.finishPublication.bind(workspace);
  workspace.finishPublication=(...args)=>{const result=finish(...args);barrier(workspace,'verified',workspace.publication(args[0]).request);return result;};
  const wrap=real=>new Proxy(real,{get(object,name){
    if(name==='fork')return context=>wrap(object.fork(context));
    const value=object[name];if(typeof value!=='function')return value;
    return async(...args)=>{
      if(name==='publish'||name==='call'&&args[1]==='/set_comment') {
        const requests=name==='publish'?[workspace.request(args[0].request)]:workspace.unresolved(args[0]);
        for(const request of requests)appendFileSync(join(directory,'effect-calls.jsonl'),JSON.stringify({
          operation:name==='publish'?'publish':'set_comment',requestId:request.callerId,context:request.context})+'\n',{mode:0o600});
      }
      const result=await value.apply(object,args);
      if(name==='call'&&args[1]==='/set_comment'||name==='saved') {
        const pending=workspace.unresolved(args[0]);
        for(const request of pending)barrier(workspace,name==='saved'?'local_save':'local_effect',request.id);
      }
      if(name==='publish')barrier(workspace,'published',args[0].request);
      return result;
    };
  }});
  return wrap(new GhidraContexts(workspace,await nativeInputs(context.profile.values),context));
};
process.exitCode=await runHosted({entryPoint:import.meta.url,createDefinition:()=>{
  const definition=createDefinition({runtime:{appArguments,secretStore},backend});
  definition.applicationId=config.applicationId;return definition;
}});
