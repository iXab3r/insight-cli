import {fail} from './model.js';

/** Execution policy, deliberately separate from immutable program load settings. */
export function ghidraBudget(values:Record<string,unknown>,phase:'import'|'save'):number {
  const field=phase==='import'?'initialImportSeconds':'saveSeconds';
  const fallback=phase==='import'?3600:120;
  const value=values[field]===undefined?fallback:values[field];
  if(typeof value!=='number'&&(typeof value!=='string'||!/^\d+$/.test(value)))fail('configuration',field+' must be an integer number of seconds.');
  const seconds=Number(value),max=phase==='import'?86400:3600;
  if(!Number.isSafeInteger(seconds)||seconds<1||seconds>max)fail('configuration',field+' must be between 1 and '+max+' seconds.');
  return seconds*1000;
}
