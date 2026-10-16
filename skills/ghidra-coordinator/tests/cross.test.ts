import test from 'node:test';
import assert from 'node:assert/strict';
import {createCliFixture} from '@eyeauras/cli-factory/testing';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createInsightCli} from '../src/cli.js';
import {SessionBackend} from './fixtures/session-backend.js';
import {Research} from '../src/research.js';
import {crossResult,transferResult,transferCategories,logicalPrograms} from '../src/cross-results.js';
test('opposing cross-context callers complete without overlapping either selected context', {timeout:3000},async t=>{
  const f=await createCliFixture(t,{applicationId:'insight-cli',profiles:[{name:'default',permissions:['ReadOnly','Update']}]});let backend:SessionBackend;
  const app=f.createApplication(runtime=>createInsightCli({runtime,backend:workspace=>(backend=new SessionBackend(workspace))}));
  const exe=join(f.root,'fixture.exe');await writeFile(exe,'owned synthetic input');
  const a=await f.json(app,['ghidra','open',exe,'--session','new']) as {session:string;target:string},b=await f.json(app,['ghidra','open',exe,'--session','new']) as typeof a;
  const research=new Research(backend!.workspace,async()=>backend!),seen:string[]=[];let active=0;
  const action=(name:string)=>async()=>{assert.equal(active,0);active++;await new Promise<void>(ok=>setImmediate(ok));seen.push(name);active--;};
  await Promise.all([research.paired(a,b,action('A→B')),research.paired(b,a,action('B→A'))]);assert.equal(seen.length,2);
});
test('cross-target output checks actual counts and preserves arbitrary function names while hiding routing',()=>{
  assert.throws(()=>crossResult('/compare_programs_documentation',{}, {programs:[{total_functions:2,documented:2,undocumented:1},{total_functions:0,documented:0,undocumented:0}],count:2}),/inconsistent/);
  const value={dry_run:false,errors:0,...Object.fromEntries(transferCategories.map(key=>[key,{planned:1,applied:1}]))};
  assert.equal(transferResult(value,false).total,17);assert.throws(()=>transferResult({...value,equates:{planned:1,applied:0}},false),/skipped/);
  const scope={session:'s',target:'t'};assert.deepEqual(logicalPrograms({function_a:{name:'program',program:'program'},source_path:'/internal'},new Map([['program',scope]])),{function_a:{name:'program',program:scope}});
});
