import assert from 'node:assert/strict';
import {readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {rows,summarize} from './compare.mjs';
import {verifyResults} from './verify-results.mjs';
import {gate} from './gate.mjs';
import {coverage} from './coverage.mjs';
import {settledTraceReport,traceCoverage} from './trace-report.mjs';
export async function phasedRows(root){const all=[];for(const e of await readdir(root,{withFileTypes:true})){if(!e.isDirectory())continue;for(const r of await rows(join(root,e.name)))all.push({...r,evidencePhase:e.name});}return all;}
export function nativeProofs(reports){const expected=['undefinedDecodeAndNoPendingChanges','savedSnapshotUnchanged','rpcDiagnostic','bulkNativePagingAndManifest','changedView','independentSavedFunctionAndReplay','inputUnchanged','unsupportedLanguage','ownedCleanup'],proofs={};for(const phase of ['candidate-bounded-proof','candidate-trace-bounded-proof']){const r=reports[phase];proofs[phase]={checks:Object.fromEntries(expected.map(k=>[k,r?.checks?.[k]===true])),cleanupEmpty:Array.isArray(r?.cleanup)&&r.cleanup.length===0};proofs[phase].passed=proofs[phase].cleanupEmpty&&Object.values(proofs[phase].checks).every(Boolean);}return {schema:1,passed:Object.values(proofs).every(p=>p.passed),proofs};}
export async function finalize(root,minimum=30,cold=5){
 assert.ok(Number.isSafeInteger(minimum)&&minimum>0);
 const all=await phasedRows(root),byPhase={},warmByPhase={};for(const phase of new Set(all.map(r=>r.evidencePhase))){byPhase[phase]=summarize(all.filter(r=>r.evidencePhase===phase));warmByPhase[phase]=summarize(all.filter(r=>r.evidencePhase===phase&&r.sample!==undefined&&(r.coldTrial===undefined||r.coldTrial===0)));}
 const equivalence=verifyResults(all.filter(r=>!r.label.includes('trace')&&!r.evidencePhase.endsWith('-cold-rpc')),{includeFirst:true}),families=Object.fromEntries(['read.','persistence.','concurrency.'].map(family=>[family,gate(summarize(all.filter(r=>r.label==='baseline'&&r.stage.startsWith(family)&&r.sample!==undefined)),summarize(all.filter(r=>r.label==='candidate'&&r.stage.startsWith(family)&&r.sample!==undefined)),{minimum})]));
 const result={passed:Object.values(families).every(r=>r.passed),families},inventory=coverage(all,{warm:minimum,cold}),traces=await settledTraceReport(join(root,'trace')),tracing=traceCoverage(traces),proofs=nativeProofs(Object.fromEntries(await Promise.all(['candidate-bounded-proof','candidate-trace-bounded-proof'].map(async phase=>[phase,JSON.parse(await readFile(join(root,phase,'report.json'),'utf8'))]))));
 for(const [name,value]of Object.entries({'summary.json':summarize(all),'summary-by-phase.json':byPhase,'summary-warm-by-phase.json':warmByPhase,'equivalence.json':equivalence,'coverage.json':inventory,'native-proofs.json':proofs,'trace-summary.json':traces,'trace-coverage.json':tracing,'gate.json':result}))await writeFile(join(root,name),JSON.stringify(value,null,2)+'\n');
 return {passed:equivalence.passed&&result.passed&&inventory.passed&&tracing.passed&&proofs.passed,equivalence,gate:result,coverage:inventory,tracing,proofs};
}
if(process.argv[1]===new URL(import.meta.url).pathname){const r=await finalize(process.argv[2],Number(process.argv[3]??30),Number(process.argv[4]??5));console.log(JSON.stringify({passed:r.passed,equivalence:r.equivalence.passed,gate:r.gate.passed,coverage:r.coverage.passed,tracing:r.tracing.passed,nativeProofs:r.proofs.passed}));if(!r.passed)process.exitCode=1;}
