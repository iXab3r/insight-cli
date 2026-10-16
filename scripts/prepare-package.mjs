import {writePackageBuildManifest} from '@eyeauras/cli-factory-ipc/build';
import {chmod} from 'node:fs/promises';
// TypeScript's output mode otherwise depends on whether the file already existed.
await chmod('dist/src/bin.js',0o755);
await writePackageBuildManifest(process.cwd());
