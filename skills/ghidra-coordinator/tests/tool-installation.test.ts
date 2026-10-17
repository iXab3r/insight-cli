import test from 'node:test';
import assert from 'node:assert/strict';
test('shared installation staging preserves selection on failure and reserves active software',async t=>{
 const {mkdtemp,rm,readFile,readdir,writeFile}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const {atomicWrite,withToolLock,withToolUse,assertUnused,installationStage,removeInstallation}=await import('../src/tool-runtime/store.js');
 const directory=await mkdtemp(join(tmpdir(),'tool-install-'));t.after(()=>rm(directory,{recursive:true,force:true}));const root=join(directory,'runtime'),id='a'.repeat(64);
 await atomicWrite(join(root,'selection.json'),{selected:'old'});
 await assert.rejects(installationStage(root,id,async stage=>{await writeFile(join(stage,'partial'),'retained');throw Error('interrupted');},async()=>{}),/prior selection/);
 assert.equal(JSON.parse(await readFile(join(root,'selection.json'),'utf8')).selected,'old');assert.equal((await readdir(join(root,'stages'))).length,1);
 const receipt=await installationStage(root,id,async stage=>{await writeFile(join(stage,'tool'),'software');return {state:'verified'};},async()=>{});assert.equal(receipt.state,'verified');
 let prepares=0;await installationStage(root,id,async()=>{prepares++;return receipt;},async value=>assert.equal(value.state,'verified'));assert.equal(prepares,0);
 const lease=await withToolUse(directory,'fixture',async()=>receipt);await assert.rejects(assertUnused(directory,'fixture'),/reserved/);lease.release();lease.release();await assertUnused(directory,'fixture');
 const order:number[]=[];await Promise.all([withToolLock(directory,'fixture',async()=>{order.push(1);await withToolLock(directory,'fixture',async()=>order.push(2));}),withToolLock(directory,'fixture',async()=>order.push(3))]);assert.deepEqual(order,[1,2,3]);
 await removeInstallation(root,id);assert.equal(JSON.parse(await readFile(join(root,'selection.json'),'utf8')).selected,'old');
});
test('queued lifecycle cancellation does not bypass the current owner operation',async()=>{
 const {withToolLock,toolProfileBusy}=await import('../src/tool-runtime/store.js');let release!:()=>void;const gate=new Promise<void>(ok=>release=ok),controller=new AbortController();let mutated=false;
 const first=withToolLock('synthetic-profile','fixture',()=>gate);const cancelled=withToolLock('synthetic-profile','fixture',async()=>{mutated=true;},controller.signal);
 assert.equal(toolProfileBusy('synthetic-profile'),true);assert.equal(toolProfileBusy('another-profile'),false);controller.abort(new Error('cancelled fixture'));await assert.rejects(cancelled,/cancelled fixture/);assert.equal(mutated,false);release();await first;
 await withToolLock('synthetic-profile','fixture',async()=>{});assert.equal(mutated,false);
});
test('standard archive installer verifies reuse, external selection, tampering and safe uninstall',async t=>{
 const {mkdtemp,rm,mkdir,writeFile,readFile,stat,symlink}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const tar=await import('tar');
 const {ToolInstaller}=await import('../src/tool-runtime/installer.js');const {fileSha256}=await import('../src/tool-runtime/archives.js');
 const root=await mkdtemp(join(tmpdir(),'tool-standard-'));t.after(()=>rm(root,{recursive:true,force:true}));const source=join(root,'source');await mkdir(join(source,'bundle'),{recursive:true});await writeFile(join(source,'bundle/run'),'fixture tool');
 const archive=join(root,'fixture.tgz');await tar.c({cwd:source,file:archive,gzip:true},['bundle']);
 const artifact={name:'fixture',url:'https://example.invalid/not-used',sha256:await fileSha256(archive),size:(await stat(archive)).size,format:'tgz' as const,root:'bundle',license:'Synthetic'};
 const context={appArguments:{AppDataDirectory:join(root,'profile')},cwd:root,signal:new AbortController().signal,fetch:async()=>{throw Error('Offline fixture must not use network');}} as unknown as import('@eyeauras/cli-factory').CommandContext;
 let probes=0;const descriptor={noticeFiles:{'notices/LICENSE.TXT':'Full owned fixture license'},id:'fixture',primary:'tool',components:()=>({tool:artifact}),launch:(roots:Record<string,string>)=>({executable:join(roots.tool!,'run'),arguments:[],environment:{}}),probe:async(launch:{executable:string})=>{probes++;assert.equal(await readFile(launch.executable,'utf8'),'fixture tool');return {version:'fixture'};}};
 const installer=new ToolInstaller(context,descriptor);assert.equal((await installer.status()).state,'not_ready');
 const installed=await installer.install({archive,offline:true});assert.equal(installed.state,'installed');assert.equal(probes,1);
 await installer.install({offline:true});assert.equal(probes,1);const selected=await installer.selected();assert.equal(selected.mode,'managed');assert.equal(await readFile(join(selected.root,'notices/LICENSE.TXT'),'utf8'),'Full owned fixture license');
 await writeFile(selected.executable,'tampered');await assert.rejects(installer.selected(),/differs/);await installer.uninstall();assert.equal((await installer.status()).state,'not_ready');
 const external=join(root,'external');await writeFile(external,'fixture tool');await installer.install({executable:external,offline:true});await installer.uninstall(true);assert.equal(await readFile(external,'utf8'),'fixture tool');
 // Replacing an owned directory with a link cannot turn uninstall into external deletion.
 const value=await installer.install({archive,offline:true}),{removeInstallation}=await import('../src/tool-runtime/store.js');
 const owned=join(installer.root,'installations',value.installation);await rm(owned,{recursive:true});await symlink(source,owned,process.platform==='win32'?'junction':'dir');
 await assert.rejects(removeInstallation(installer.root,value.installation),/external link/);assert.equal(await readFile(join(source,'bundle/run'),'utf8'),'fixture tool');
});

test('cancelling an acquisition already in progress cannot leak an installation reservation',async()=>{
 const {withToolUse,toolUseCount,toolProfileBusy}=await import('../src/tool-runtime/store.js');
 let ready!:()=>void,release!:()=>void;const entered=new Promise<void>(ok=>ready=ok),gate=new Promise<void>(ok=>release=ok),controller=new AbortController();
 const acquisition=withToolUse('cancelled-acquisition','fixture',async()=>{ready();await gate;return 'selected';},controller.signal);
 await entered;controller.abort(new Error('cancel during verification'));release();await assert.rejects(acquisition,/cancel during verification/);
 assert.equal(toolUseCount('cancelled-acquisition','fixture'),0);assert.equal(toolProfileBusy('cancelled-acquisition'),false);
});

test('external family binding detects sibling changes and selects a new identity without deleting external files',async t=>{
 const {mkdtemp,rm,mkdir,writeFile,readFile}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const {ToolInstaller}=await import('../src/tool-runtime/installer.js');const {fileSha256}=await import('../src/tool-runtime/archives.js');
 const root=await mkdtemp(join(tmpdir(),'tool-family-'));t.after(()=>rm(root,{recursive:true,force:true}));const executable=join(root,'primary'),sibling=join(root,'sibling');await writeFile(executable,'stable primary');await writeFile(sibling,'version one');
 const context={appArguments:{AppDataDirectory:join(root,'profile')},cwd:root,signal:new AbortController().signal} as unknown as import('@eyeauras/cli-factory').CommandContext;
 const descriptor={id:'family',primary:'family',components:()=>{throw Error('External selection must not download');},launch:()=>({executable,arguments:[],environment:{}}),probe:async()=>({version:'fixture'}),externalInputs:async()=>({sibling:await fileSha256(sibling)})};
 const installer=new ToolInstaller(context,descriptor),first=await installer.install({executable});await installer.selected();
 await writeFile(sibling,'version two');await assert.rejects(installer.use(async()=>assert.fail('Changed external family must not run')),/family differs/);
 const second=await installer.install({executable});assert.notEqual(second.installation,first.installation);await installer.selected();
 await installer.uninstall();assert.equal(await readFile(executable,'utf8'),'stable primary');assert.equal(await readFile(sibling,'utf8'),'version two');
});

test('an adapted external runtime executes only its verified owned copy and uninstall preserves the original',async t=>{
 const {mkdtemp,rm,mkdir,writeFile,readFile,stat}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{join,dirname}=await import('node:path');const {ToolInstaller}=await import('../src/tool-runtime/installer.js');
 const root=await mkdtemp(join(tmpdir(),'tool-external-copy-'));t.after(()=>rm(root,{recursive:true,force:true}));const original=join(root,'vendor');await writeFile(original,'original vendor bytes');const context={appArguments:{AppDataDirectory:join(root,'profile')},cwd:root,signal:new AbortController().signal} as unknown as import('@eyeauras/cli-factory').CommandContext;
 const installer=new ToolInstaller(context,{id:'adapted',primary:'adapted',preparationId:'v1',components:()=>{throw Error('No download');},launch:()=>{throw Error('Not managed');},probe:async()=>({version:'fixture'}),prepareExternal:async(_input,stage)=>{const executable=join(stage,'execution/tool');await mkdir(dirname(executable),{recursive:true});await writeFile(executable,'adapted owned bytes');return {executable,arguments:['typed'],environment:{}};}});
 await installer.install({executable:original});const selected=await installer.selected();assert.equal(selected.executable,original);assert.ok(selected.execution);assert.ok(selected.execution.executable.startsWith(selected.root));await installer.use(async execution=>assert.equal(await readFile(execution.executable,'utf8'),'adapted owned bytes'));
 await writeFile(selected.execution.executable,'corrupt copy');await assert.rejects(installer.use(async()=>assert.fail('Corrupt owned copy must not run')),/execution copy differs/);await installer.uninstall();assert.equal(await readFile(original,'utf8'),'original vendor bytes');await assert.rejects(stat(selected.root),{code:'ENOENT'});
});
