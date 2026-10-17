import {readFileSync,existsSync,realpathSync} from 'node:fs';
import {join,isAbsolute,resolve} from 'node:path';
import {fail,object} from './model.js';
export interface RuntimeSelection {schema:1;mode:'managed'|'external';id?:string;ghidraHome:string;java:string;fingerprint:string;selectedAt:string;uninstalledAt?:string}
export const runtimeRoot=(directory:string)=>join(directory,'runtime');
export function runtimeSelection(directory:string):RuntimeSelection|undefined {
  const path=join(runtimeRoot(directory),'selection.json');if(!existsSync(path))return;
  const value=object(JSON.parse(readFileSync(path,'utf8')));
  if(value.schema!==1||!['managed','external'].includes(String(value.mode))||typeof value.java!=='string'||!isAbsolute(value.java)||typeof value.ghidraHome!=='string'||!isAbsolute(value.ghidraHome)||!/^[a-f0-9]{64}$/.test(String(value.fingerprint)))fail('binding','Runtime selection receipt is invalid.');
  if(value.mode==='managed'){
    const id=String(value.id),recordedProfile=resolve(value.ghidraHome,'../../../..');
    if(!/^[a-f0-9]{64}$/.test(id)||value.ghidraHome!==join(runtimeRoot(recordedProfile),'installations',id,'ghidra'))fail('binding','Managed runtime moved outside its owned installation.');
    // Workspace resolves AppData physically; older install receipts can retain a profile
    // alias such as /tmp -> /private/tmp. Accept that same profile, never an inner escape.
    let profile:string,recorded:string,home:string|undefined;
    try{profile=realpathSync.native(directory);recorded=realpathSync.native(recordedProfile);if(existsSync(value.ghidraHome))home=realpathSync.native(value.ghidraHome);}
    catch{fail('binding','Managed runtime profile ownership could not be verified.');}
    if(recorded!==profile||home!==undefined&&home!==join(runtimeRoot(profile),'installations',id,'ghidra'))fail('binding','Managed runtime moved outside its owned installation.');
  }
  return value as unknown as RuntimeSelection;
}
export function runtimeValues(directory:string,values:Record<string,unknown>):Record<string,unknown> {
  const selected=runtimeSelection(directory);
  if(!selected)return values;
  if(selected.uninstalledAt)fail('configuration','Selected Ghidra runtime was uninstalled. Run insight-cli ghidra install.');
  if(selected.mode==='managed'&&!existsSync(join(runtimeRoot(directory),'installations',selected.id!,'ready.json')))fail('configuration','Selected managed Ghidra is not installed. Run insight-cli ghidra install.');
  return {...values,java:selected.java,ghidraHome:selected.ghidraHome};
}
