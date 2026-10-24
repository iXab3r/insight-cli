// Maintainer-only: installed CLI uses the packaged helper, never a host compiler.
import {execFileSync} from 'node:child_process';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
assert.equal(process.platform,'darwin');
const compiler=process.argv[2]??'/usr/bin/clang',root='skills/ghidra-coordinator/runtime/native/',source=root+'process-identity-darwin.c',binary=root+'process-identity-darwin-'+process.arch;
const flags=['-arch',process.arch==='arm64'?'arm64':'x86_64','-mmacosx-version-min=13.0','-O2','-g0','-Werror','-Wno-deprecated-declarations'];
execFileSync(compiler,[...flags,source,'-o',binary],{stdio:'inherit'});
const sha=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
await writeFile(root+'process-identity.provenance.json',JSON.stringify({schema:1,license:'MIT',platform:process.platform,architecture:process.arch,compiler:execFileSync(compiler,['--version'],{encoding:'utf8'}).trim(),sourceSha256:await sha(source),sha256:await sha(binary),flags},null,2)+'\n');
