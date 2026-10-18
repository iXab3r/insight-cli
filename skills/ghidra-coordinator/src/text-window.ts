import {createHash} from 'node:crypto';
/** Public text coordinates are Unicode code points, never native bytes or UTF-16 halves. */
export function textWindow(source:string,limit:number,offset:number,sourceTruncated=false){
 const characters=Array.from(source);
 return {content:characters.slice(offset,offset+limit).join(''),textSha256:createHash('sha256').update(source).digest('hex'),totalCharacters:characters.length,limit,offset,sourceTruncated,truncated:sourceTruncated||offset+limit<characters.length,coordinates:'Unicode characters in the returned native text; hash binds that text, which may itself be a truncated prefix'};
}
