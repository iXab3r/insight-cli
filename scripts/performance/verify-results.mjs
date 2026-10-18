import {rows} from './compare.mjs';
export function verifyResults(records){
 const groups=new Map(),failures=[];
 for(const r of records.filter(r=>r.stage.startsWith('read.')&&!r.warmup)){
  const key=[r.fixture,r.analysis?'analysis':'no-analysis',r.stage].join('/'),g=groups.get(key)??new Map(),route=r.label+'/'+r.route,a=g.get(route)??[];a.push(r);g.set(route,a);groups.set(key,g);
 }
 for(const [key,routes]of groups){let expected;for(const [route,values]of routes){const digests=new Set(values.map(v=>v.resultHash));if(values.some(v=>!v.ok)||digests.has(undefined)||digests.size!==1){failures.push({case:key,route,reason:'failed, missing or changing useful result'});continue;}const actual=[...digests][0];if(expected&&expected!==actual)failures.push({case:key,route,reason:'useful output differs'});expected??=actual;}}
 if(!groups.size)failures.push({reason:'empty evidence'});
 return {schema:1,passed:failures.length===0,checkedCases:groups.size,failures,normalization:'Only documented transport/profile/view metadata is omitted; useful code, comments, field counts, addresses and memory bytes remain bound.'};
}
if(process.argv[1]===new URL(import.meta.url).pathname){const results=verifyResults((await Promise.all(process.argv.slice(2).map(rows))).flat());console.log(JSON.stringify(results,null,2));if(!results.passed)process.exitCode=1;}
