import {realpathSync,statSync} from 'node:fs';
import {dirname,join} from 'node:path';

/** Windows packaged apps can expose one directory through distinct real paths. */
export function sameDirectory(left:string,right:string):boolean {
  const a=realpathSync.native(left),b=realpathSync.native(right);
  if(a===b)return true;
  const x=statSync(a,{bigint:true}),y=statSync(b,{bigint:true});
  return x.isDirectory()&&y.isDirectory()&&x.ino!==0n&&x.dev===y.dev&&x.ino===y.ino;
}

/** Resolve inner links before checking the owner: an inner escape is never an alias. */
export function ownedDirectory(path:string,owner:string,parts:string[]):boolean {
  const physical=realpathSync.native(path);
  let anchor=physical;for(const _ of parts)anchor=dirname(anchor);
  return physical===join(anchor,...parts)&&sameDirectory(anchor,owner);
}
