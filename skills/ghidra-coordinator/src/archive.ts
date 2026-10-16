import {command,Permission,type CommandContext,type CommandDefinition} from '@eyeauras/cli-factory';
import {Workspace,type Scope} from './workspace.js';
import {Research,scope,address,number,type ResearchBackend} from './research.js';
import {id,text,object,fail,digest} from './model.js';
import {selectedOptions} from './arguments.js';
import {archiveOrigin,archivePayload,archivePost} from './archive-contract.js';

export class Archive {
  constructor(private readonly workspace:Workspace,private readonly research:Research,private readonly backend:()=>Promise<ResearchBackend>,private readonly c:CommandContext){}
  async ingest(selected:Scope,operation:'function'|'program',p:Record<string,unknown>,callerId?:string) {
    const origin=p.dry_run?undefined:archiveOrigin(this.c.profile.values.archiveUrl);
    const reserved=this.workspace.reserveAdministration('ghidra.archive.'+operation,{...selected,...p,...(origin?{origin}:{})},callerId);
    return this.research.ordered(selected,async()=>{
      const request=this.workspace.administration(reserved.request.id);
      if(reserved.replay&&request.state!=='accepted'){
        if(request.state==='applied')return request.result;
        fail('unknown','Archive outcome is retained and no external requests are repeated.',request.result);
      }
      const backend=await this.backend();await backend.open(selected);
      if(!backend.archivePayloads)fail('configuration','Selected backend lacks archive payload support.');
      const snapshot=await backend.saved(selected),binary=this.workspace.target(selected.target).name,run='insight-cli-'+request.id;
      const token=origin?await this.c.secrets.get('archiveToken'):undefined;
      const result={...selected,state:'running',binary_name:binary,version:String(p.version),source_run_id:run,dry_run:Boolean(p.dry_run),
        total_functions:0,created:0,updated:0,conflicts_enqueued:0,skipped_default_named:0,errors:0,truncated:false,first_errors:[] as {address:string;state:string}[]};
      this.workspace.administrationState(request.id,'running',{...result,sourceSnapshot:snapshot});
      let offset=0,more=true;const seen=new Set<string>();
      try{
        const maximum=operation==='function'?1:Number(p.limit)||100000;
        while(more&&offset<maximum){
          const page=object(await backend.archivePayloads(selected,{...(operation==='function'?{function:p.function}:{}),binary_name:binary,version:p.version,run_id:run,
            skip_default_named:operation==='program'&&p.skip_default_named===true,offset,limit:Math.min(10,maximum-offset)}));
          if(!Array.isArray(page.payloads)||!Number.isSafeInteger(page.visited)||Number(page.visited)<0||Number(page.visited)>Math.min(10,maximum-offset)||!Number.isSafeInteger(page.skipped)||Number(page.skipped)<0||page.payloads.length+Number(page.skipped)!==page.visited||typeof page.more!=='boolean'||page.more&&page.visited===0)
            fail('partial','Archive payload inventory has inconsistent counts.');
          const payloads=page.payloads.map(raw=>archivePayload(raw,binary,String(p.version),run));
          for(const payload of payloads){const at=address(payload.address);if(seen.has(at))fail('partial','Archive inventory repeated a function.');seen.add(at);}
          if(operation==='function'&&(payloads.length!==1||address(payloads[0]!.address)!==address(p.function)))fail('binding','Archive selected another function.');
          result.skipped_default_named+=Number(page.skipped);result.total_functions+=Number(page.skipped);
          for(const payload of payloads){
            result.total_functions++;
            if(p.dry_run){result.created++;continue;}
            // Commit the exact outbound identity before a request can leave the process.
            this.workspace.administrationState(request.id,'unknown',{...result,sourceSnapshot:snapshot,pending:{address:payload.address,payloadSha256:digest(payload)}});
            try{const received=await archivePost(this.c.fetch,origin!,payload,token,this.c.signal);if(received.created)result.created++;else result.updated++;result.conflicts_enqueued+=received.conflicts_enqueued;}
            catch{result.errors++;if(result.first_errors.length<10)result.first_errors.push({address:String(payload.address),state:'unknown'});}
            this.workspace.administrationState(request.id,'unknown',{...result,sourceSnapshot:snapshot});
            if(this.c.signal.aborted)fail('unknown','Archive submission was cancelled; completed and uncertain outcomes are retained.');
          }
          offset+=Number(page.visited);more=page.more;
        }
        if(more&&Number(p.limit)===0)fail('limit','Archive selection exceeds 100000 functions; use an explicit bounded selection.');
        result.truncated=more;result.state=result.errors?'partial':p.dry_run?'preview':'applied';
        this.workspace.administrationState(request.id,result.errors?'unknown':'applied',result);
        if(result.errors)fail('partial','Some archive outcomes are unknown; retained counts are not retried.',result);return result;
      }catch(error){
        const current=this.workspace.administration(request.id);if(current.state!=='applied')this.workspace.administrationState(request.id,'unknown',{...result,state:'unknown',sourceSnapshot:snapshot});throw error;
      }
    });
  }
}
export function archiveCommands(service:(c:CommandContext)=>Archive):CommandDefinition[]{
  return [command('archive','Send selected private documentation to the configured archive',(['function','program'] as const).map(operation=>
    command('ingest-'+operation,'Prepare documentation and retain every external request outcome',({options:o},c)=>{
      const p:Record<string,unknown>={version:text(o.versionLabel,512),dry_run:Boolean(o.dryRun)};
      if(operation==='function')p.function=address(o.address);else{p.limit=number(o.limit,100000);p.skip_default_named=!o.includeDefaultNamed;}
      return service(c).ingest(scope(o),operation,p,o.requestId===undefined?undefined:id(o.requestId));
    },{permission:Permission.Update,options:[...selectedOptions,
      ...(operation==='function'?[{flags:'--address <address>',description:'Selected function entry point',required:true}]:[{flags:'--limit <count>',description:'Maximum visited functions (0 means all, at most 100000)',defaultValue:0},{flags:'--include-default-named',description:'Include auto-named functions'}]),
      {flags:'--version-label <name>',description:'Archive version label',defaultValue:'unknown'},{flags:'--dry-run',description:'Validate payloads without sending documentation'},
      {flags:'--request-id <id>',description:'Retrieve retained counts without repeating archive requests'}]})))];
}
