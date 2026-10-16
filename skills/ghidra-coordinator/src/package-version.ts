import {readFileSync} from 'node:fs';

// The installed manifest is also covered by Factory's package build identity.
export const packageVersion: string = JSON.parse(readFileSync(new URL('../../package.json',import.meta.url),'utf8')).version;
