import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,relative,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {workflow,outcomes} from './workflows.mjs';
import {scenarioManifest} from './isolation.mjs';
import {PublicCli} from '../business/public-cli.mjs';
const o={};for(let i=2;i<process.argv.length;i+=2)o[process.argv[i].slice(2)]=process.argv[i+1];
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.ok(!process.env.CI);assert.match(o.case,/^GS-(?:0[1-9]|[12]\d|3[0-2])$/);
const parent=JSON.parse(await readFile(o.manifest,'utf8')),expected=scenarioManifest(parent,o.case),m=JSON.parse(await readFile(join(expected.directory,'manifest.json'),'utf8')),hash=b=>createHash('sha256').update(b).digest('hex');
assert.deepEqual(m,expected,'Scenario configuration changed');
assert.equal(m.schema,1);assert.equal(m.profile,'sb');assert.equal(m.environment.APPDATA,join(m.directory,'r'));assert.equal(m.environment.LOCALAPPDATA,join(m.directory,'l'));
for(const path of [...Object.values(m.environment),m.workspace]){assert.ok(isAbsolute(path)&&!path.toLowerCase().includes('ec2-native'));const r=relative(m.directory,path);assert.ok(r&&!r.startsWith('..')&&!isAbsolute(r),'Control/data path escapes owned fixture');}
assert.equal(hash(await readFile(m.archive)),m.archiveSha256);await mkdir(o.output,{recursive:true});
const report={schema:1,id:o.case,fixtureDirectory:relative(parent.directory,m.directory),outcome:outcomes[Number(o.case.slice(3))-1],state:'running',publicCliOnly:true,cleanupComplete:false,serviceCleanupComplete:false,checks:[],archiveSha256:m.archiveSha256};
await writeFile(join(o.output,'case.json'),JSON.stringify({id:o.case}));
const setup=new PublicCli(m,join(o.output,'setup'));let failure;
try {await setup.setup();await setup.call(['permissions','grant','Destructive']);await workflow(o.case,m,o.output,report);}
catch(e){failure=e;}
finally {
 const errors=[];
 // Even an unresolved private operation must not occupy another scenario's service.
 // Preserve its saved project/journals and stop only this scenario's owned processes.
 for(const [args,options]of [[['ghidra','server','disconnect'],{}],[['ipc-server','stop'],{global:true}]])try{await setup.call(args,options);}catch(e){errors.push(e);}
 report.serviceCleanupComplete=errors.length===0;
 if(report.inputFile)try{assert.equal(hash(await readFile(join(m.directory,report.inputFile))),report.inputSha256,'Immutable fixture changed');report.inputUnchanged=true;}catch(e){errors.push(e);}
 if(errors.length)failure=new AggregateError([...(failure?[failure]:[]),...errors],'Scenario or owned-service teardown failed');
 report.state=failure?'failed':'passed';
 if(failure){const detail=e=>({message:e.message,stack:e.stack,...(e.errors?{errors:e.errors.map(detail)}:{})});report.error=detail(failure);process.exitCode=1;}
 await writeFile(join(o.output,'result.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}
