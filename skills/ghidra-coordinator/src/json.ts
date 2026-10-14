/** Preserve exact integer values that cannot be represented by a JavaScript number. */
export function parseDomainJson(source:string):unknown {
  return JSON.parse(source,(_key:string,value:unknown,context?:{source?:string})=>{
    if(typeof value==='number'&&Number.isInteger(value)&&!Number.isSafeInteger(value)&&context?.source&&/^-?\d+$/.test(context.source))
      return context.source;
    return value;
  });
}
