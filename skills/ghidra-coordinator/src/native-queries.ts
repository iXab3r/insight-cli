import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import type {HttpBridge} from './transport.js';
import {object,fail} from './model.js';

export async function nativeQuery(http:HttpBridge,program:string,operation:string,parameters:Record<string,unknown>,write=false) {
  const base=operation==='/research_view'?'InsightResearchView':operation.startsWith('/sdk/')?'InsightSdkScript':operation.startsWith('/emulate_')?'InsightEmulation':'InsightResearchQueries';
  const name=base+'_'+randomUUID().replaceAll('-','');
  const source=await readFile(new URL('../../references/native/'+base+'.java',import.meta.url),'utf8');
  const response=object(await http.call('/run_script_inline',{program,code:source.replace('public class '+base+' ','public class '+name+' '),
    args:Buffer.from(JSON.stringify({operation,parameters,...(write?{write:true}:{})}),'utf8').toString('base64')}));
  if(response.success!==true||typeof response.console_output!=='string')fail('partial','Native research helper did not complete.');
  const matches=[...response.console_output.matchAll(/^INSIGHT_QUERY:(.+)$/gm)];
  if(matches.length!==1)fail('partial','Native research helper omitted its unique result.');
  let result;try{result=object(JSON.parse(matches[0]![1]!));}catch{fail('partial','Native research helper returned malformed JSON.');}
  if(result.error){const error=object(result.error),code=String(error.code);fail(['invalid','unsupported','limit',...(operation.startsWith('/sdk/')?['rejected']:[])].includes(code)?code:'partial',
    typeof error.message==='string'?error.message.slice(0,500):'Native research failed.');}
  if(!Object.hasOwn(result,'value'))fail('partial','Native research helper omitted its value.');
  return result.value;
}
