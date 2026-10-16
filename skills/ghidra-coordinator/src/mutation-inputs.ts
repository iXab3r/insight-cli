import {object,fail,text} from './model.js';
import {address} from './research.js';
/** Validate nested domain input before reserving or dispatching a changing intent. */
export function mutationInputs(path:string,p:Record<string,unknown>) {
  if(path==='/apply_data_classification') {
    if(!['PRIMITIVE','STRUCTURE','ARRAY','STRING'].includes(String(p.classification)))fail('invalid','Classification must be PRIMITIVE, STRUCTURE, ARRAY or STRING.');
    const type=object(p.type_definition);
    if(p.classification==='PRIMITIVE')text(type.type,512);
    if(p.classification==='STRUCTURE'){text(type.name,512);if(!Array.isArray(type.fields)||!type.fields.length)fail('invalid','A structure requires fields.');
      for(const raw of type.fields){const field=object(raw);text(field.name,512);text(field.type,512);}}
    if(p.classification==='ARRAY'){text(type.element_type??type.element_struct,512);
      if(!Number.isSafeInteger(Number(type.count))||Number(type.count)<1||Number(type.count)>1048576)fail('invalid','Array count must be 1–1048576.');}
  }
  if(path==='/set_global'&&(!Number.isSafeInteger(p.array_length??0)||Number(p.array_length??0)<0||Number(p.array_length??0)>1048576))
    fail('invalid','Global array length must be 0–1048576.');
  if(path==='/apply_function_documentation') {
    const document=object(p.json_body);address(document.target_address);
    for(const key of ['function_name','return_type','calling_convention','plate_comment'])if(document[key]!==undefined&&document[key]!=='')text(document[key],key==='plate_comment'?16000:512);
    const array=(key:string)=>{const value=document[key]??[];if(!Array.isArray(value))fail('invalid','Documentation '+key+' must be an array.');return value;};
    const ordinals=new Set<number>();
    for(const raw of array('parameters')){const parameter=object(raw),ordinal=parameter.ordinal;
      if(!Number.isSafeInteger(ordinal)||Number(ordinal)<0||Number(ordinal)>65535||ordinals.has(Number(ordinal)))fail('invalid','Parameter ordinals must be unique integers from 0 to 65535.');
      ordinals.add(Number(ordinal));for(const key of ['name','type'])if(parameter[key]!==undefined&&parameter[key]!=='')text(parameter[key],512);}
    for(const key of ['comments','labels']){
      const offsets=new Set<string>();for(const raw of array(key)){const item=object(raw);let offset:bigint;
        try{if(!/^\d+$/.test(String(item.relative_offset)))throw Error();offset=BigInt(String(item.relative_offset));}catch{fail('invalid','Relative offset must be a nonnegative integer.');}
        if(offset>0x7fffffffffffffffn||offsets.has(offset.toString()))fail('invalid','Documentation offsets must be unique signed 64-bit integers.');offsets.add(offset.toString());
        for(const field of key==='labels'?['name']:['eol_comment','pre_comment'])if(item[field]!==undefined&&item[field]!=='')text(item[field],field==='name'?512:16000);
        if(key==='labels')text(item.name,512);
      }
    }
  }
}
