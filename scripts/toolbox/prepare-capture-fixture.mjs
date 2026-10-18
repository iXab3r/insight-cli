import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');const [directory,clang]=process.argv.slice(2);assert.ok(clang);await mkdir(directory,{recursive:true,mode:0o700});const program=resolve(directory,'owned-capture');execFileSync(clang,['-O0','-g0','tests/acceptance/fixtures/capture/program.c','-o',program]);await writeFile(join(directory,'fixture.json'),JSON.stringify({schema:1,program,sha256:createHash('sha256').update(await readFile(program)).digest('hex')},null,2)+'\n');console.log('Owned capture subject prepared');
