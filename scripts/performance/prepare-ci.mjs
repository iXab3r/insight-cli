import assert from 'node:assert/strict';
import {appendFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runNpm} from '../npm-command.mjs';
assert.ok(process.env.RUNNER_TEMP&&process.env.GITHUB_ENV);
const result=await runNpm(['run','test:package','--','--keep-installed'],{maxBuffer:4*1024**2});
await writeFile(join(process.env.RUNNER_TEMP,'candidate-package-proof.log'),result.stdout+'\n'+result.stderr,{mode:0o600});
const installed=result.stdout.match(/^Retained owned installed package: (.+)$/m)?.[1];assert.ok(installed,'Package proof did not retain candidate');
await appendFile(process.env.GITHUB_ENV,'INSIGHT_CANDIDATE_BIN='+join(installed,'node_modules/@eyeauras/insight-cli/dist/src/bin.js')+'\n');
