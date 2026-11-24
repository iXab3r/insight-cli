import assert from 'node:assert/strict';
import {join} from 'node:path';

// Each scenario owns its Factory control root, server, repository and frozen lanes.
export function scenarioManifest(parent,id){
 assert.match(id,/^GS-(?:0[1-9]|[12]\d|3[0-2])$/);
 assert.equal(parent.profile,'sb');assert.equal(parent.isolation,'per-scenario');
 const directory=join(parent.directory,id.slice(3));
 const environment={APPDATA:join(directory,'r'),LOCALAPPDATA:join(directory,'l'),HOME:join(directory,'h'),XDG_CONFIG_HOME:join(directory,'c'),TEMP:join(directory,'t'),TMP:join(directory,'t'),TMPDIR:join(directory,'t')};
 return {...parent,parentDirectory:parent.directory,caseId:id,directory,environment,workspace:join(environment.APPDATA,'insight-cli',parent.profile,'workspace')};
}
