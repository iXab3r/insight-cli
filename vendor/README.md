# Prepared Factory dependencies

`provenance.json` and `factory-ipc-fcb793f.json` pin the current IPC artifact;
`factory-core-fcb793f.json` pins its matching Core 0.5.2 artifact. Both are prepared Factory
package builds from commit `fcb793f2b2ffacddd68be56815ca59fa89afbcf0`, consumed by immutable
content URLs. They contain compiled Factory packages and MIT notices, not copied source or a
product-specific host. This candidate combines upstream main `8b7a01a74180aee0a5f55252caa115d0ea4a7290`
with the external IPC branch `a4ed74ddbf5da1ca06fd0f9b7273f1dd88d74894`.

The npm Core 0.5.2 release alone lacks the external-consumer changes needed here: package build
manifests, nested profile-independent discovery, parser-owned IPC routing, denied-access handling
and resource vetoes before profile persistence. The prepared pair retains these changes from
Factory PRs #51, #53, #55 and #57 while adopting the current platform secret store.
It is not byte-identical to registry Core 0.5.2. No npm publication is part of this update.

On Windows, Factory now stores DPAPI CurrentUser ciphertext under each profile's AppData
`secrets/` directory. It does not read, delete or automatically migrate Credential Manager entries.
See [upgrade instructions](../skills/ghidra-coordinator/references/setup.md#windows-secret-store-upgrade)
before using existing Windows profiles. macOS/Linux retain their system keyring behavior.

Reproduce from the pinned Factory commit: `npm ci --ignore-scripts`, build Core and IPC, then
`npm pack --ignore-scripts --workspace <package>`. Compare SHA256 before updating provenance.
Never replace bytes under an existing filename. Use new commit-qualified filenames and update
the immutable URL, lockfile and isolated offline package proof together. Core and IPC must
resolve to the same prepared Core dependency; the installed consumer proof checks this graph.
Historical artifacts remain addressable at their immutable source commits.
