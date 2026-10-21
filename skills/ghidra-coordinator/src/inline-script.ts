import {createHash,randomUUID} from 'node:crypto';
import {mkdir,writeFile,readFile,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {object,fail} from './model.js';
import type {HttpBridge} from './transport.js';

export const inlineSourceHash=(code:string)=>createHash('sha256').update(code,'utf8').digest('hex');
/** Native facts come from the fixed helper's receipt, never from caller console output. */
export function inlineReceipt(raw:unknown,expected:{attemptId:string;requestId:string;sourceSha256:string}) {
  const r=object(raw),execution=object(r.execution),build=object(r.compilerOutput);
  if(r.protocol!=='insight-inline-v1'||r.attemptId!==expected.attemptId||r.requestId!==expected.requestId||r.sourceSha256!==expected.sourceSha256||
    typeof r.success!=='boolean'||!['prepare','compile','load','initialize','construct','execute'].includes(String(execution.stage))||
    !['not_started','may_have_started'].includes(String(execution.userCode))||![false,null].includes(execution.entrypointInvoked as false|null)||
    typeof build.text!=='string'||Buffer.byteLength(build.text)>32772||typeof build.truncated!=='boolean'||
    typeof r.console_output!=='string'||Buffer.byteLength(r.console_output)>32772||typeof r.outputTruncated!=='boolean')
    fail('partial','Native inline-script receipt is absent, malformed or belongs to another attempt.');
  if(r.success===false){const d=object(r.diagnostic);if(typeof d.kind!=='string'||typeof d.message!=='string'||d.message.length>2048)fail('partial','Native inline-script failure omitted its diagnostic.');}
  if(r.success===true&&(execution.userCode!=='may_have_started'||execution.stage!=='execute'))fail('partial','Native inline-script completion contradicts its execution facts.');
  const safe=r.success===false&&execution.userCode==='not_started'&&execution.entrypointInvoked===false&&['prepare','compile','load'].includes(String(execution.stage));
  if(execution.userCode==='not_started'&&!safe)fail('partial','Native inline-script non-execution facts contradict their stage.');
  return {response:r,safe};
}

export async function runInline(http:HttpBridge,program:string,root:string,parameters:Record<string,unknown>,requestId:string) {
  if(typeof parameters.code!=='string'||Buffer.byteLength(parameters.code)>1048576||parameters.code.includes('\0'))fail('invalid','Inline Java source must contain at most one MiB of UTF-8 text without NUL.');
  const attemptId=randomUUID(),sourceSha256=inlineSourceHash(parameters.code),directory=join(root,'inline-attempts',attemptId);
  await mkdir(directory,{recursive:true,mode:0o700});const request=join(directory,'request.json');
  await writeFile(request,JSON.stringify({attemptId,requestId,sourceSha256,code:parameters.code,args:parameters.args??''}),{mode:0o600,flag:'wx'});
  const name='InsightInlineScript_'+randomUUID().replaceAll('-',''),source=await readFile(new URL('../../references/native/InsightInlineScript.java',import.meta.url),'utf8');
  // Only this fixed shim enters the upstream provider. User source is compiled separately.
  const ack=object(await http.call('/run_script_inline',{program,code:source.replace('public class InsightInlineScript ','public class '+name+' '),args:Buffer.from(request,'utf8').toString('base64')}));
  if(ack.success!==true||typeof ack.console_output!=='string'||!ack.console_output.includes('INSIGHT_INLINE_COMPLETE'))fail('partial','Native inline-script executor did not acknowledge its completed attempt.');
  const handle=await open(join(directory,'receipt.json'),constants.O_RDONLY|(constants.O_NOFOLLOW??0));let raw:unknown;
  try{
    const maximum=1048576,stat=await handle.stat();if(!stat.isFile()||stat.size>maximum)fail('partial','Native inline-script receipt exceeds its bound.');
    const bytes=Buffer.alloc(maximum+1);let length=0;
    while(length<bytes.length){const next=await handle.read(bytes,length,bytes.length-length,null);if(!next.bytesRead)break;length+=next.bytesRead;}
    if(length>maximum)fail('partial','Native inline-script receipt exceeds its bound.');raw=JSON.parse(bytes.subarray(0,length).toString('utf8'));
  }finally{await handle.close();}
  return inlineReceipt(raw,{attemptId,requestId,sourceSha256});
}
