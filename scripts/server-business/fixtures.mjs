// Controlled PE32+ image: explicit section/address oracle, no compiler or OS execution.
export function fixtureFor(id){
 const memory=['GS-23','GS-25','GS-26'].includes(id);
 if(!memory){const bytes=Buffer.alloc(0x400,0xc3);bytes.write(id,0x300);return {bytes,name:id+'.bin',options:['--loader','ghidra.app.util.opinion.BinaryLoader','--language','x86:LE:64:default','--image-base','1000','--loader-options','{"Base Address":"0"}']};}
 const bytes=Buffer.alloc(0xa00),u16=(at,v)=>bytes.writeUInt16LE(v,at),u32=(at,v)=>bytes.writeUInt32LE(v,at);
 bytes.write('MZ');u32(0x3c,0x80);bytes.write(id,0x60);bytes.write('PE\0\0',0x80);
 const coff=0x84;u16(coff,0x8664);u16(coff+2,3);u16(coff+16,0xf0);u16(coff+18,0x22);
 const optional=coff+20;u16(optional,0x20b);u32(optional+4,0x400);u32(optional+8,0x400);u32(optional+16,0x1000);u32(optional+20,0x1000);
 bytes.writeBigUInt64LE(0n,optional+24);u32(optional+32,0x1000);u32(optional+36,0x200);u16(optional+40,6);u16(optional+48,6);
 u32(optional+56,0x4000);u32(optional+60,0x200);u16(optional+68,3);
 bytes.writeBigUInt64LE(0x100000n,optional+72);bytes.writeBigUInt64LE(0x1000n,optional+80);bytes.writeBigUInt64LE(0x100000n,optional+88);bytes.writeBigUInt64LE(0x1000n,optional+96);u32(optional+108,16);
 const sections=[['.text',0x1000,0x400,0x200,0x400,0x60000020],['.region0',0x2000,0x20,0x600,0x200,0x40000040],['.region1',0x3000,0x20,0x800,0x200,0x40000040]];
 for(const [i,[name,address,size,offset,rawSize,flags]]of sections.entries()){const at=optional+0xf0+40*i;bytes.write(name,at,8,'ascii');u32(at+8,size);u32(at+12,address);u32(at+16,rawSize);u32(at+20,offset);u32(at+36,flags);}
 bytes.fill(0xc3,0x200,0x600);
 return {bytes,name:id+'.exe',options:['--language','x86:LE:64:default','--image-base','0']};
}
