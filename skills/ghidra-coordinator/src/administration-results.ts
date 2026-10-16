import {object,fail} from './model.js';
const integer=(value:unknown,min=0)=>{if(!Number.isSafeInteger(value)||Number(value)<min)fail('partial','Administration returned an invalid integer.');};
const names=(value:unknown)=>{if(!Array.isArray(value)||value.some(item=>typeof item!=='string'||!item))fail('partial','Administration name inventory is absent.');return value;};
const array=(value:unknown)=>{if(!Array.isArray(value))fail('partial','Administration item inventory is absent.');return value.map(object);};
const file=(value:unknown)=>{const row=object(value);for(const field of ['name','path','type'])if(typeof row[field]!=='string')fail('partial','Repository file identity is incomplete.');integer(row.version,1);return row;};
export function administrationResult(operation:string,p:Record<string,unknown>,raw:unknown) {
  const value=object(raw);if(JSON.stringify(value).length>1048576)fail('limit','Administration result exceeds one MiB.');
  if(['status','connect','disconnect','stop'].includes(operation)) {
    if(typeof value.connected!=='boolean'||!['local','external'].includes(String(value.mode)))fail('partial','Server status is incomplete.');
    if(value.connected&&typeof value.repository!=='string')fail('partial','Connected server omitted its repository.');
  }else if(operation==='repositories'){const values=names(value.repositories);integer(value.count);if(value.count!==values.length)fail('partial','Repository count is inconsistent.');}
  else if(operation==='create_repository'){if(value.state!=='created'||value.repository!==p.repository)fail('partial','Created repository identity changed.');}
  else if(operation==='users'){const users=array(value.users);integer(value.count);if(users.length!==value.count||users.some(user=>typeof user.name!=='string'))fail('partial','Server user count is inconsistent.');}
  else {
    if(value.repository!==p.repository)fail('binding','Administration returned another repository.');
    if(operation==='files'){names(value.folders);array(value.files).forEach(file);if(value.path!==p.path)fail('binding','Repository folder changed.');}
    else if(operation==='file'){const row=file(value.file);if(row.path!==p.path)fail('binding','Repository file path changed.');}
    else if(operation==='permissions'){array(value.users).forEach(user=>{if(typeof user.name!=='string')fail('partial','ACL username is absent.');integer(user.access);if(Number(user.access)>2)fail('partial','Invalid ACL level.');});if(typeof value.anonymous!=='boolean')fail('partial','ACL anonymous flag is absent.');}
    else if(operation==='set_permissions'){const users=object(value.users);if(value.state!=='applied'||users[String(p.user)]!==p.access||typeof value.anonymous!=='boolean')fail('partial','Permission update lacks exact readback.');}
    else if(operation==='history'){if(value.path!==p.path)fail('binding','History selected another file.');array(value.versions).forEach(version=>{integer(version.version,1);if(typeof version.user!=='string'||typeof version.comment!=='string')fail('partial','Version history is incomplete.');});}
    else if(operation==='checkouts'){if(value.path!==p.path)fail('binding','Checkout selection changed.');array(value.checkouts).forEach(item=>{if(typeof item.id!=='string'||!/^\d+$/.test(item.id)||typeof item.path!=='string'||typeof item.user!=='string')fail('partial','Checkout identity is incomplete.');integer(item.version);});}
    else if(operation==='terminate_checkout'||operation==='terminate_all_checkouts'){if(value.path!==p.path)fail('binding','Termination selected another path.');integer(value.terminated);}
    else fail('schema','Administration operation lacks a result contract.');
  }
  return value;
}
