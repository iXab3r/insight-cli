import type {ScalarChange} from './workspace.js';
import {fail} from './model.js';

export const fieldKey=(change:Pick<ScalarChange,'address'|'field'>)=>change.address+'@'+change.field;
export interface SharedScalar {value:string|null;compatible:boolean}
export interface FieldConflict {
  address:string;field:ScalarChange['field'];original:string|null;local:string|null;shared:string|null;
  reason:'overlap'|'dependency_changed';
}
export interface MergePlan {
  state:'publish'|'conflict'|'already_shared';
  apply:ScalarChange[]; conflicts:FieldConflict[]; fullSnapshot:boolean;
}

/** Three-way decisions only; backend effects happen after the entire plan passes. */
export function scalarMerge(changes:ScalarChange[],complex:boolean,baseRevision:number,sharedRevision:number,
  values:Record<string,SharedScalar>):MergePlan {
  if(sharedRevision<baseRevision)fail('binding','Shared history regressed below the private baseline.');
  // A verified complete private result can include fields changed by structural edits.
  // Retained refresh conflicts still require their original/local/shared comparison.
  if(complex&&baseRevision===sharedRevision&&!changes.some(change=>change.conflict))
    return {state:'publish',apply:[...changes],conflicts:[],fullSnapshot:true};
  const apply:ScalarChange[]=[],conflicts:FieldConflict[]=[];
  for(const change of changes) {
    const observed=values[fieldKey(change)];
    if(!observed)fail('partial','Shared comparison omitted a local field.');
    if(!observed.compatible)conflicts.push({...change,shared:observed.value,reason:'dependency_changed'});
    else if(observed.value===change.local)continue;
    else if(observed.value===change.original)apply.push(change);
    else conflicts.push({...change,shared:observed.value,reason:'overlap'});
  }
  if(complex&&baseRevision!==sharedRevision)return {state:'conflict',apply:[],conflicts,fullSnapshot:true};
  if(conflicts.length)return {state:'conflict',apply:[],conflicts,fullSnapshot:false};
  return {state:apply.length||complex?'publish':'already_shared',apply,conflicts:[],fullSnapshot:baseRevision===sharedRevision};
}

export interface RefreshPlan {
  receive:ScalarChange[]; preserve:ScalarChange[]; conflicts:FieldConflict[];
}
/** Incoming safe fields update a private view; conflicting local values remain explicit. */
export function scalarRefresh(local:ScalarChange[],incoming:ScalarChange[],
  values:Record<string,SharedScalar>):RefreshPlan {
  const locals=new Map(local.map(change=>[fieldKey(change),change]));
  const preserve=local.map(change=>({...change})),receive:ScalarChange[]=[],conflicts:FieldConflict[]=[];
  for(const change of incoming) {
    const key=fieldKey(change),pending=locals.get(key),observed=values[key];
    if(!observed)fail('partial','Incoming comparison omitted a field.');
    if(!observed.compatible) {
      if(pending)conflicts.push({...pending,shared:observed.value,reason:'dependency_changed'});
      continue;
    }
    if(!pending){receive.push({...change,local:observed.value});continue;}
    if(observed.value===pending.local) {
      const index=preserve.findIndex(item=>fieldKey(item)===key);preserve.splice(index,1);
    } else if(observed.value!==pending.original)conflicts.push({...pending,shared:observed.value,reason:'overlap'});
    else {
      const preserved=preserve.find(item=>fieldKey(item)===key);if(preserved)delete preserved.conflict;
    }
  }
  for(const conflict of conflicts) {
    const preserved=preserve.find(change=>fieldKey(change)===fieldKey(conflict));
    if(preserved)preserved.conflict={shared:conflict.shared};
  }
  return {receive,preserve,conflicts};
}
