import {command,Permission,type CommandDefinition} from '@eyeauras/cli-factory';
import {fail,text} from './model.js';
/** Equivalent of the pinned unsigned 64-bit number conversion, without a tool process. */
export function convertNumber(input:unknown,size:unknown=4) {
  const source=text(input,128),width=Number(size);if(!Number.isSafeInteger(width)||width<1||width>8)fail('invalid','Size must be 1–8 bytes.');
  let value:bigint,inputType:string;
  try {
    if(/^0[xX][a-fA-F0-9]+$/.test(source)){value=BigInt(source);inputType='hexadecimal';}
    else if(/^0[bB][01]+$/.test(source)){value=BigInt(source);inputType='binary';}
    else if(/^0[0-7]+$/.test(source)&&source.length>1){value=BigInt('0o'+source);inputType='octal';}
    else if(/^\+?\d+$/.test(source)){value=BigInt(source);inputType='decimal';}
    else throw Error();
    if(value<0n||value>0xffffffffffffffffn)throw Error();
  }catch{fail('invalid','Number must be an unsigned 64-bit decimal, hexadecimal, binary or octal integer.');}
  const bits=BigInt(width*8),masked=value&((1n<<bits)-1n),signed=masked>=(1n<<(bits-1n))?masked-(1n<<bits):masked,hex=masked.toString(16).toUpperCase();
  return {input:source,input_type:inputType,size:width,decimal_unsigned:masked.toString(),decimal_signed:signed.toString(),
    hexadecimal:'0x'+hex,binary:'0b'+masked.toString(2),octal:'0'+masked.toString(8),hex_padded:'0x'+hex.padStart(width*2,'0')};
}
export function utilityCommands():CommandDefinition[] {return [command('utility','Stateless research utilities',[
  command('convert-number','Convert an unsigned 64-bit integer at an explicit byte width',({options:o})=>convertNumber(o.text,o.size),
    {permission:Permission.ReadOnly,options:[{flags:'--text <number>',description:'Decimal, 0x hexadecimal, 0b binary or leading-zero octal',required:true},
      {flags:'--size <bytes>',description:'Output width, 1–8 bytes',defaultValue:4}]})])];}
