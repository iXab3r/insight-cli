import assert from 'node:assert/strict';
/** Native tests own every input/process. They never run in CI. */
export function nativeProofGuard(ack){
 assert.equal(ack,true,'Native acceptance requires --ack-disposable');
 const ci=Object.keys(process.env).some(key=>/^(CI|GITLAB_CI|TF_BUILD|BUILD_BUILDID)$/i.test(key)&&process.env[key]);
 assert.ok(!ci,'Native acceptance never runs in CI');
}
