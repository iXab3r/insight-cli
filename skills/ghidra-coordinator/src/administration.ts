import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import type {ResearchBackend} from './research.js';
import {Workspace} from './workspace.js';
import {fail,id,text,object} from './model.js';
import {option,parsed,key,type Parameter} from './arguments.js';
import {administrationResult} from './administration-results.js';
const repository=(value:unknown)=>{const name=text(value,128);if(name!==name.trim()||/[\\/\0]/.test(name)||name.startsWith('.'))fail('invalid','Repository name must be a single bounded name.');return name;};
export function repositoryPath(value:unknown) {
  const path=text(value,4096);if(!path.startsWith('/')||path.includes('\\')||path.split('/').some(part=>part==='.'||part==='..')||path.includes('//'))fail('invalid','Use an absolute repository path without traversal.');
  return path.length>1?path.replace(/\/$/,''):path;
}
export class Administration {
  constructor(readonly workspace:Workspace,private readonly backend:()=>Promise<ResearchBackend>,private readonly tasks:Map<string,Promise<unknown>>){}
  private async ordered<T>(action:()=>Promise<T>) {
    const key='administration',previous=this.tasks.get(key),task=(previous?previous.catch(()=>{}):Promise.resolve()).then(action);this.tasks.set(key,task);
    try{return await task;}finally{if(this.tasks.get(key)===task)this.tasks.delete(key);}
  }
  async read(operation:string,parameters:Record<string,unknown>) {
    return this.ordered(async()=>{const backend=await this.backend();if(!backend.administration)fail('configuration','Selected backend has no repository administration adapter.');
      const value=administrationResult(operation,parameters,await backend.administration(operation,parameters));
      return operation==='status'?{...value,unresolvedRequests:this.workspace.unresolvedServer().map(request=>({operation:request.operation,state:request.state,...(request.callerId?{requestId:request.callerId}:{})}))}:value;});
  }
  async change(operation:string,parameters:Record<string,unknown>,callerId?:string) {
    const reserved=this.workspace.reserveAdministration('server.'+operation,parameters,callerId);
    return this.ordered(async()=>{
      const request=this.workspace.administration(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted') {
        if(request.state==='applied')return request.result;
        fail('unknown','Administration outcome is retained and is not re-executed.',request.result);
      }
      const backend=await this.backend();if(!backend.administration)fail('configuration','Selected backend has no repository administration adapter.');
      this.workspace.administrationState(request.id,'running');
      try {const value=administrationResult(operation,parameters,await backend.administration(operation,parameters));this.workspace.administrationState(request.id,'applied',value);return value;}
      catch(error){this.workspace.administrationState(request.id,'unknown',{state:'unknown',operation});throw error;}
    });
  }
}
const repo:Parameter={name:'repository',type:'string',required:true},path:Parameter={name:'path',type:'string',required:false,default:'/'};
const leaves:{names:string[];operation:string;gate:string;params:Parameter[]}[]=[
  {names:['status'],operation:'status',gate:Permission.ReadOnly,params:[]},
  {names:['connect'],operation:'connect',gate:Permission.Update,params:[]},
  {names:['disconnect'],operation:'disconnect',gate:Permission.Update,params:[]},
  {names:['repositories','list'],operation:'repositories',gate:Permission.ReadOnly,params:[]},
  {names:['repositories','create'],operation:'create_repository',gate:Permission.Update,params:[repo]},
  {names:['repositories','files'],operation:'files',gate:Permission.ReadOnly,params:[repo,path]},
  {names:['repositories','file'],operation:'file',gate:Permission.ReadOnly,params:[repo,{...path,required:true,default:undefined}]},
  {names:['history'],operation:'history',gate:Permission.ReadOnly,params:[repo,{...path,required:true,default:undefined}]},
  {names:['checkouts'],operation:'checkouts',gate:Permission.ReadOnly,params:[repo,path]},
  {names:['admin','users'],operation:'users',gate:Permission.ReadOnly,params:[]},
  {names:['admin','permissions'],operation:'permissions',gate:Permission.ReadOnly,params:[repo]},
  {names:['admin','set-permissions'],operation:'set_permissions',gate:'Destructive',params:[repo,{name:'user',type:'string',required:true},{name:'access',type:'string',required:true}]},
  {names:['admin','terminate-checkout'],operation:'terminate_checkout',gate:'Destructive',params:[repo,{...path,required:true,default:undefined},{name:'checkout_id',type:'string',required:false}]},
  {names:['admin','terminate-all-checkouts'],operation:'terminate_all_checkouts',gate:'Destructive',params:[repo,path]},
];
export function administrationCommands(service:(context:CommandContext)=>Administration):CommandDefinition[] {
  const children:CommandDefinition[]=[];
  for(const leaf of leaves) {
    const changing=leaf.gate!==Permission.ReadOnly;
    const definition=command(leaf.names.at(-1)!,'Operate on the configured server and explicit repository',({options:o},c)=>{
      const parameters:Record<string,unknown>={};
      for(const p of leaf.params){const value=o[key(p.name)];if(value!==undefined)parameters[p.name]=parsed(p,value);}
      if(parameters.repository!==undefined)parameters.repository=repository(parameters.repository);
      if(parameters.path!==undefined)parameters.path=repositoryPath(parameters.path);
      if(parameters.checkout_id!==undefined&&!/^\d+$/.test(String(parameters.checkout_id)))fail('invalid','Checkout ID must be an exact decimal integer.');
      if(parameters.access!==undefined){const level=String(parameters.access).toLowerCase().replaceAll('-','_'),access={read_only:0,readonly:0,read:0,write:1,admin:2,'0':0,'1':1,'2':2}[level];
        if(access===undefined)fail('invalid','Access must be read_only, write or admin.');parameters.access=access;}
      return changing?service(c).change(leaf.operation,parameters,o.requestId===undefined?undefined:id(o.requestId)):service(c).read(leaf.operation,parameters);
    },{permission:leaf.gate,options:[...leaf.params.map(option),...(changing?[{flags:'--request-id <id>',description:'Retrieve this administration outcome after a lost response'}]:[])]});
    if(leaf.names.length===1)children.push(definition);
    else {const group=children.find(item=>item.name===leaf.names[0]);if(group)(group.children as CommandDefinition[]).push(definition);else children.push(command(leaf.names[0]!,`${leaf.names[0]} administration`,[definition]));}
  }
  return [command('server','Configured server management',children)];
}
