import {object,fail} from './model.js';
/** Strip transport versioning from the existing logical observation and its identity digest. */
export function researchView(raw:unknown){
  const r=object(raw);
  if(r.protocol!=='insight-research-view-v1'||typeof r.modification!=='string'||!/^\d{1,20}$/.test(r.modification)||
    !['language','compiler'].every(k=>typeof r[k]==='string'&&r[k].length>0&&r[k].length<=256&&!r[k].includes('\0')))
    fail('partial','Native research-view observation is malformed or unsupported.');
  return {modification:r.modification,language:r.language,compiler:r.compiler};
}
