import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Workspace,type Scope} from './workspace.js';
import {Research,scope,address,number,type ResearchBackend} from './research.js';
import {id,text,object,fail} from './model.js';
import {selectedOptions} from './arguments.js';
export class UserInterface {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>){}
  async read(selected:Scope,operation:'cursor'|'tools',facet='all'){
    return this.research.ordered(selected,async()=>{const backend=await this.backend();await backend.open(selected);
      if(operation==='tools')await backend.mode(selected,'gui');if(!backend.ui)fail('configuration','Selected backend lacks the UI adapter.');
      const value=await backend.ui(selected,operation,{});
      return {...selected,value:operation==='cursor'&&facet!=='all'?{[facet]:value[facet],...(value[facet]===null?{reason:value[facet+'_unavailable']}:{})}:value};
    });
  }
  async change(selected:Scope,operation:'goto'|'prompt_policy',p:Record<string,unknown>,callerId?:string){
    const reserved=this.workspace.reserveRequest(selected,'ghidra.ui.'+operation,p,callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.request(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){if(request.state==='applied')return request.result;fail('unknown','UI effect is retained and is not repeated.',request.result);}
      const backend=await this.backend();await backend.open(selected);await backend.mode(selected,'gui');
      if(!backend.ui)fail('configuration','Selected backend lacks the UI adapter.');const context=this.workspace.context(selected);
      this.workspace.startRequest(request.id,{kind:'ui',operation,generation:context.generation});
      try{
        const value=await backend.ui(selected,operation,p);
        if(operation==='goto'){
          const cursor=await backend.ui(selected,'cursor',{}),location=object(cursor.address);
          if(location.session!==selected.session||location.target!==selected.target||address(location.address)!==address(p.address))fail('partial','Cursor did not reach the requested context and address.');
        }
        const result={...selected,state:'applied',value};this.workspace.completeSavedRequest(selected,request.id,context.generation,{},result);return result;
      }catch(error){this.workspace.recordRequest(request.id,'unknown',{...selected,state:'unknown',operation});throw error;}
    });
  }
}
export function uiCommands(service:(c:CommandContext)=>UserInterface):CommandDefinition[]{
  const request={flags:'--request-id <id>',description:'Retrieve the recorded UI result without repeating it'};
  return [command('ui','Inspect and control the selected context interface',[
    command('cursor','Read the focused address, function, selection and program',({options:o},c)=>{
      const type=text(o.type);if(!['all','address','function','selection','program'].includes(type))fail('invalid','Cursor type must be all, address, function, selection or program.');
      return service(c).read(scope(o),'cursor',type);
    },{permission:Permission.ReadOnly,options:[...selectedOptions,{flags:'--type <facet>',description:'Cursor facet or all',defaultValue:'all'}]}),
    command('tools','Read tools in the owned GUI context',({options:o},c)=>service(c).read(scope(o),'tools'),{permission:Permission.ReadOnly,options:selectedOptions}),
    command('goto','Navigate the owned browser and verify the cursor',({options:o},c)=>service(c).change(scope(o),'goto',{address:address(o.address)},o.requestId===undefined?undefined:id(o.requestId)),
      {permission:Permission.Update,options:[...selectedOptions,{flags:'--address <address>',description:'Explicit address',required:true},request]}),
    command('prompt-policy','Temporarily control the owned GUI prompt policy',({options:o},c)=>{
      const action=text(o.action);if(!['status','enable','disable'].includes(action))fail('invalid','Prompt policy action must be status, enable or disable.');
      return service(c).change(scope(o),'prompt_policy',{action,reason:text(o.reason,512),seconds:number(o.seconds,300,1)},o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...selectedOptions,{flags:'--action <action>',description:'status, enable or disable',defaultValue:'status'},
      {flags:'--reason <text>',description:'Recorded policy reason',defaultValue:'automation'},{flags:'--seconds <count>',description:'Requested duration (1–300 seconds)',defaultValue:120},request]}),
  ])];
}
