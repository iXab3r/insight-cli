# Native checkout path in the primary CLI

The primary `Research` / `GhidraContexts` path uses real Ghidra Server checkouts and
native Update/check-in. `scalarMerge`, `scalarRefresh`, detached candidates and the
raw snapshot publisher are absent from this command path. The historical engine and
[lifecycle prototype](NATIVE-CHECKOUT-LIFECYCLE.md) remain separate evidence.

## Working context and authority

One `(session, target)` owns one active native project, file ID, normal checkout ID
and base version. `checkout.json` records creation intent before the service contacts
the repository. An interrupted creation reuses that root; it does not allocate
another project on retry. A server checkout whose local creation cannot be proved
stays retained for reconciliation.

The service creates the checkout with publisher authority. A private headless or
GUI worker opens that same saved project with an authenticator that refuses server
authentication. Its environment contains the scoped bridge token and no repository
password. Restarting the worker or Factory owner reuses the native project and its
ancestry/change sets. Factory still owns IPC, profiles, secrets, permissions and
process lifecycle. This is cooperative process credential separation, not an OS
sandbox against hostile code running as the same OS user.

Ordinary save writes the native DB and a small immutable `native` receipt describing
the saved buffers and checkout. The legacy internal field name `workingSnapshot`
can hold this receipt; it is not a packed program and is not used to recreate a
working copy. Shared view receipts name an immutable server version/file ID.
`.gzf` is retained for first import and explicit export/cross-program/VT consumers;
save, reopen, merge and refresh do not export another full program.

## Native refresh and publication

`ghidra refresh` saves and stops the private worker, then a service-only native client
opens that exact project and calls `DomainFile.merge(false, monitor)`. Ghidra owns
resolver selection, object identity/dependency handling and merge semantics. A dirty
Update advances the original checkout/base without publishing. A clean Update uses
Ghidra's fast path. Ghidra's `.keep` backup belongs to this project; a successful
publication disposes it with the project.

A native conflict rejects the whole Update. The original saved program, checkout ID
and base remain; status exposes the bounded native conflict description. There is no
TypeScript object merger, partial scalar receive, category whitelist or automatic
winner. The old scalar `--resolve-conflict` option cannot decide native conflicts.
Native conflict choice/resume transport is not implemented. Work may be adjusted
privately and submitted to native Update again under a new request, or explicitly
transferred to a fresh context; scripts are not replayed as a merge algorithm.

`ghidra merge` first performs native Update. For a modified checkout it persists the
application publication intent and the native candidate/check-in intent, then invokes
`DomainFile.checkin`. The prepared candidate must still match its saved buffers and
server base. A known head race refuses publication. The headless factory also refuses
a new divergent merge inside check-in: a race must not silently replace the already
journaled candidate.

Check-in retains the owned checkout until an independent **read-only** process finds
the unique request marker in history and verifies the exact published version's
complete saved buffers and source identity. The workspace atomically records verified
publication. Only then does the service release that checkout, close native handles
and delete the owned project through `ProjectManager.deleteProject`. Release/drop
receipts make cleanup independently recoverable. Continuing work creates a fresh
checkout from the server; the session/target selectors remain the same.

An unchanged checkout is independently compared with its server base, released and
dropped without creating a new repository version. A conflict or unknown publication
never authorizes project deletion. The service never retries check-in from an unknown
result: it reconciles history and independent exact-version buffers. An interrupted
Update needs its native completion journal plus matching saved checkout/readback;
the old detached-candidate rule cannot declare it `not_updated`.

`receivedChanges` on native refresh counts a received program revision transition,
not a reconstructed number of field setters. Pending scalar/opaque records remain
diagnostics for acknowledged CLI edits; the native DB's actual modified state decides
whether check-in is needed, including changes made outside those diagnostic categories.
The legacy `applied` count also describes acknowledged CLI diagnostic edits, not the number
of all native objects changed. A native publication may advance the server with `applied: 0`.
Automatic publication after Save enters this same native path even when the diagnostic
count is zero. An unchanged native checkout completes without a server version.

## Existing data and other lifecycle operations

Detached legacy contexts are rejected with an explicit migration error and retained.
Shared models must carry the native publication protocol marker established during
fresh import. There is no automatic history conversion, no mixed legacy/native writer
fallback and no automatic adoption of existing detached private work. Operators must
exclude older snapshot writers from any chosen native item. Cross-profile shared-item
discovery remains a separate design scope.

Native discard retains Ghidra's `.keep` for dirty work, releases the old checkout and
checks out the current server version in the same project. It does not publish or
restore a detached DB over native ancestry. A lost discard acknowledgment is reconciled
from its completed operation journal, the new checkout ID/base, saved buffers and
independent server readback; it never repeats discard. An incomplete journal stays blocked.
Unknown arbitrary-script outcomes stay
blocked on their original project; the old snapshot-based `abandon` rollback is
unsupported for native contexts. Memory layout/language operations remain subject
to Ghidra's exclusive-access rules.

Closing an unchanged context releases its checkout, and [`ghidra gc`](GHIDRA-STORAGE-COLLECTION.md)
collects redundant copies. Existing-profile migration and `ec2-native` data are excluded
from this acceptance. Empty diagnostic
containers, journals and server history remain; deleting the successful private native
project does not delete the shared analysis.

## Verification boundary

`scripts/proof-native-cli.mjs --ack-disposable` executes the actual primary command
definition and default native backend. `--installed --faults` packs/installs the same
CLI in an isolated directory and runs independent client processes through Factory
IPC. The wrapper supplies only disposable profile/secret-store locations; it does not
inject a backend or replace merge operations.

The [integration report](verification/native-cli-integration.json) identifies the original
isolated-package source/package hashes, native outputs and limits. The subsequent
[global delivery report](verification/native-global-cli-delivery.json) records local 0.5.9,
the real global entrypoint with disposable environment/profile, complete installed/archive
identity and its own new native execution. These are separate evidence revisions.
Cases include independent agent
edits to functions/types, type creation/deletion, worker and owner restart, dirty/clean
Update, check-in/readback/drop, repeated publication, native conflict preservation and
owner loss after native check-in without replay. The raw-binary fixture checks that
its functions are inside initialized memory. Earlier malformed fixture and environment
failures remain diagnostics, not acceptance.

The packaged headless adapter uses the same pinned upstream entry/display seams and
separately documented memory-comment compatibility correction as the prototype.
Generated classes/provenance stay in owned storage, and installed Ghidra JARs remain
unchanged. The retained native license/notice identifies the derived orchestration.
This does not claim unmodified upstream headless support, every possible native
conflict decision, hostile-user isolation or a whole-catalog GUI/debugger acceptance.
