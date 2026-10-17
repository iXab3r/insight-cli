import assert from 'node:assert/strict';import {mkdir,readFile,writeFile} from 'node:fs/promises';import {join,resolve} from 'node:path';import {fileURLToPath} from 'node:url';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {createHash} from 'node:crypto';
const execute=promisify(execFile),[directory,clang,lldLink,ldLld]=process.argv.slice(2);assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');assert.ok(ldLld,'Arguments: owned-output clang lld-link ld.lld');
await mkdir(directory,{recursive:true,mode:0o700});const root=fileURLToPath(new URL('../../',import.meta.url)),source=join(root,'tests/acceptance/fixtures/toolbox/native.c'),library=join(root,'tests/acceptance/fixtures/toolbox/library.c');
const run=async(exe,args)=>execute(exe,args,{cwd:directory,timeout:120000,maxBuffer:1024**2});
const debug=['-g','-gcodeview','-O0','-fno-builtin','-fdebug-compilation-dir=fixture-source','-ffile-prefix-map='+root+'=fixture-source'];
await run(clang,['--target=x86_64-pc-windows-msvc',...debug,'-c',library,'-o','library.obj']);
await run(lldLink,['/dll','/noentry','/timestamp:0','/out:PolicyNative.dll','/implib:PolicyNative.lib','library.obj']);
await run(clang,['--target=x86_64-pc-windows-msvc',...debug,'-c',source,'-o','program.obj']);
await run(lldLink,['/entry:main','/subsystem:console','/nodefaultlib','/timestamp:0','/debug','/pdb:program.pdb','/out:program.exe','program.obj','PolicyNative.lib']);
await run(clang,['-g','-O0',source,'-o','program.macho']);
await run(clang,['--target=x86_64-unknown-linux-gnu','-O0','-fPIC','-c',library,'-o','linux-library.o']);
await run(ldLld,['-shared','-soname','libpolicy.so','linux-library.o','-o','libpolicy.so']);
await run(clang,['--target=x86_64-unknown-linux-gnu','-O0','-fPIC','-c',source,'-o','linux-program.o']);
await run(ldLld,['-e','_start','-dynamic-linker','/lib64/ld-linux-x86-64.so.2','linux-program.o','-L.','-lpolicy','-o','program.elf']);
const names=['program.exe','program.pdb','PolicyNative.dll','program.macho','program.elf','libpolicy.so'],files=[];
for(const name of names){const bytes=await readFile(join(directory,name));files.push({name,path:resolve(directory,name),size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')});}
await writeFile(join(directory,'inputs.json'),JSON.stringify({schema:1,files,producer:{clang:(await run(clang,['--version'])).stdout.split('\n')[0],lldLink:(await run(lldLink,['--version'])).stdout.trim(),ldLld:(await run(ldLld,['--version'])).stdout.trim()},sourceSha256:createHash('sha256').update(await readFile(source)).digest('hex')},null,2)+'\n');console.log('Owned PE/PDB/Mach-O/ELF inputs prepared:',directory);
