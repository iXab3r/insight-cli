import assert from 'node:assert/strict';
/** Native tests own every input/process. CI requires an explicit manual disposable-fixture job. */
export function nativeProofGuard(ack){
 assert.equal(ack,true,'Native acceptance requires --ack-disposable');
 const ci=Object.keys(process.env).some(key=>/^(CI|GITHUB_ACTIONS|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]);
 if(ci)assert.ok(process.env.GITHUB_ACTIONS==='true'&&['workflow_dispatch','push'].includes(process.env.GITHUB_EVENT_NAME??'')&&process.env.GITHUB_WORKFLOW==='disposable-native-p2'&&process.env.INSIGHT_DISPOSABLE_NATIVE_CI==='1','Native CI is allowed only in the explicitly selected disposable-fixture workflow');
}
