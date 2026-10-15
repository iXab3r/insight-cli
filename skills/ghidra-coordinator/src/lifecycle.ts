import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Research,scope,type ResearchBackend} from './research.js';
import {Workspace,type Scope} from './workspace.js';
import {id,fail,object} from './model.js';
import {selectedOptions} from './arguments.js';
import type {Artifact} from './artifacts.js';
export class Lifecycle {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>){}
  async health(selected:Scope) {
    return this.research.ordered(selected,async()=>{
      const backend=await this.backend();await backend.open(selected);
      const connection=object(await backend.call(selected,'/check_connection')),health=object(await backend.call(selected,'/mcp/health'));
      if(connection.status!=='ok'||health.status!=='ok'||health.connected!==true||!['headless','gui'].includes(String(health.server_kind)))fail('partial','Tool health did not verify the selected context.');
      return {...this.research.status(selected),health:{connected:true,mode:health.server_kind,version:health.version,memory:health.memory_mb}};
    });
  }
  async change(selected:Scope,operation:'save'|'close',callerId?:string) {
    const reserved=this.workspace.reserveRequest(selected,'ghidra.'+operation,{},callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){if(request.state==='applied')return request.result;fail('unknown','This lifecycle outcome is retained; it is not re-executed.',request.result);}
      const backend=await this.backend();await backend.open(selected);const before=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:operation,generation:before.generation,workingSnapshot:before.workingSnapshot});
      let savedSnapshot:Artifact|undefined;
      try {
        if(operation==='close')await backend.close(selected);
        const current=this.workspace.context(selected),snapshot=operation==='save'?await backend.saved(selected):current.workingSnapshot;
        if(!snapshot)fail('partial','Lifecycle operation did not retain its private snapshot.');
        savedSnapshot=snapshot;
        const result={...selected,state:operation==='save'?'saved':'closed',pendingChanges:current.scalars.length+current.complexChanges.length};
        this.workspace.completeSavedRequest(selected,request.id,current.generation,{workingSnapshot:snapshot},result);return result;
      }catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',...(savedSnapshot?{savedSnapshot}:{})});throw error;}
    });
  }
}
export function lifecycleCommands(service:(context:CommandContext)=>Lifecycle):CommandDefinition[] {
  return [command('status','Verify tool health and inspect the selected private context',({options:o},c)=>service(c).health(scope(o)),{permission:Permission.ReadOnly,options:selectedOptions}),
    ...(['save','close'] as const).map(name=>command(name,name==='save'?'Save private work without publication':'Save and release the owned context; reopen retains local work',({options:o},c)=>service(c).change(scope(o),name,o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[...selectedOptions,{flags:'--request-id <id>',description:'Retrieve the lifecycle outcome after a lost response'}]}))];
}
