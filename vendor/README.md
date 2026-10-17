# Prepared Factory dependencies

`provenance.json` pins the current IPC artifact; `factory-core-74e7a64.json` pins its matching
Core artifact. Both are official Factory package builds from the recorded commit, consumed by
immutable content URLs. They contain compiled Factory packages and MIT notices, not copied
source or a product-specific host. Factory PR #51 owns packed external consumers; PR #53 adds
nested profile-independent discovery and parser-owned IPC routing. PR #55 distinguishes denied
IPC access from an absent owner and retires only an unready startup child; it reuses the matching
Core artifact from PR #53. No registry publication
occurred for these candidates or for insight-cli.

Reproduce from the pinned Factory commit: `npm ci --ignore-scripts`, build Core and IPC, then
`npm pack --ignore-scripts --workspace <package>`. Compare SHA256 before updating provenance.
Never replace bytes under an existing filename. Use new commit-qualified filenames and update
the immutable URL, lockfile and isolated offline package proof together. Core and IPC must
resolve to the same prepared Core dependency; the installed consumer proof checks this graph.
Historical artifacts remain addressable at their immutable source commits.
