import {lstat,readFile,readdir,realpath} from 'node:fs/promises';
import {join} from 'node:path';

interface PeerOwner {target:string;context?:string}
interface PeerReceipt extends PeerOwner {path:string;state:'preparing'|'closed'}
type PeerStage={folder:string;reason:string}|{folder:string;receipt:PeerReceipt;input?:string};
const peerName=/^__insight_peer_[a-f0-9]{32}$/;
const missing=(error:unknown)=>(error as NodeJS.ErrnoException).code==='ENOENT';

/** Only the generated input of an exactly owned stage is disposable; its receipt stays. */
export async function peerStage(root:string,name:string,owner:PeerOwner):Promise<PeerStage>{
  const parent=join(root,'cross-peer'),folder=join(parent,name),keep=(reason:string):PeerStage=>({folder,reason});
  if(!peerName.test(name))return keep('Unrecognized cross-target stage.');
  try{
    const parentStat=await lstat(parent),stageStat=await lstat(folder);
    if(parentStat.isSymbolicLink()||!parentStat.isDirectory()||stageStat.isSymbolicLink()||!stageStat.isDirectory()||
      await realpath(folder)!==join(await realpath(root),'cross-peer',name))return keep('Cross-target stage left its owned directory or is a link.');
    let input:string|undefined;
    for(const entry of await readdir(folder,{withFileTypes:true})){
      if(!['receipt.json','input.gzf'].includes(entry.name))return keep('Cross-target stage holds unrecognized files.');
      if(!entry.isFile())return keep('Cross-target stage holds links or special entries.');
      if(entry.name==='input.gzf')input=join(folder,entry.name);
    }
    const receipt:PeerReceipt=JSON.parse(await readFile(join(folder,'receipt.json'),'utf8'));
    if(!receipt||typeof receipt!=='object'||!owner.context||receipt.path!=='/'+name||receipt.target!==owner.target||receipt.context!==owner.context)
      return keep('Cross-target cleanup receipt belongs to another context or is malformed.');
    if(receipt.state!=='closed'&&receipt.state!=='preparing')return keep('Unknown cross-target cleanup stage.');
    return {folder,receipt,...(input?{input}:{})};
  }catch(error){
    if(missing(error)||error instanceof SyntaxError)return keep('Cross-target cleanup receipt or stage is missing or malformed.');
    return keep('Cross-target stage could not be verified: '+String((error as NodeJS.ErrnoException).code??'unavailable'));
  }
}

export async function peerStages(root:string,owner:PeerOwner):Promise<PeerStage[]>{
  const parent=join(root,'cross-peer');
  try{
    const st=await lstat(parent);
    if(st.isSymbolicLink()||!st.isDirectory())return [{folder:parent,reason:'Cross-target stage inventory is a link or special entry.'}];
    const stages:PeerStage[]=[];
    for(const name of await readdir(parent))stages.push(await peerStage(root,name,owner));
    return stages;
  }catch(error){
    if(missing(error))return [];
    return [{folder:parent,reason:'Cross-target stage inventory could not be verified: '+String((error as NodeJS.ErrnoException).code??'unavailable')}];
  }
}
