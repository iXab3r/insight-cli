# Ghidra working storage and collection

One native checkout holds the private work of a session/target. Ordinary edits and saves
write into that project and record a small receipt; they do not export or copy the
database. `ghidra gc` removes redundant copies, including those left by engines that
exported a packed program for every saved change.

## Release on close

`ghidra close` first saves and stops the worker. The close outcome never depends on what
follows. When the saved receipt equals its server base, no edits, conflicts, traces,
unresolved or abandoned-unknown operations, or publication are recorded, and a credentialed native status call
independently reports an unmodified checkout at the same file ID, checkout ID, base
version and fingerprint, without Ghidra recovery data or other local files at any folder
depth, and no unresolved operation of another context references it, the checkout is released and its
project dropped. The result reports `checkout: released` or `checkout: retained`. A refused
or unavailable verification only retains the checkout. The next open of the same selectors
checks out the **current** shared revision. Changed contexts keep their original checkout.

### Ghidra's own rewrite on open

Opening a checkout lets Ghidra rewrite its saved buffers before any caller runs (the
headless bridge saves inside `open_program`). Such a checkout reports itself modified and
its bytes no longer equal the server base, although it holds no work. Before a worker's
first launch, independent native status must prove the saved base bytes and checkout identity,
with no recovery data or additional local files. Only after that proof may the coordinator
capture the opened buffers as a no-work receipt. When they differ from the base, it records them under
`ghidra-native/shared-views/<target>/opened/v<version>-<fingerprint>.json` as a proved
no-work state of that version and file ID. Later edits are compared with that receipt.

Close and `gc` accept saved buffers that equal either the base or one of these recorded
states, byte for byte. Only then may the native status report a modification. The release
passes the observed fingerprint, and Ghidra's `undoCheckout(false)` is invoked only for
exactly those bytes; any other modified checkout stays retained. Copies left by earlier
releases become reclaimable once any context opens a pristine checkout of the same version
with a release containing this rule. A reference binds the server origin, repository,
version, file ID, base fingerprint and independently observed pre-open checkout. Older references
without this provenance cannot authorize disposal of an active checkout. `gc --dry-run` judges saved receipts only; execution
verifies the observed bytes and may still retain a copy the dry-run counted.
Equal bytes are the proof; the rule does not depend on which records Ghidra rewrote.

## `ghidra gc [--dry-run]`

Collection covers the selected profile. Dry-run needs ReadOnly and changes nothing;
execution needs ReadOnly and Destructive. It uses the migration admission gate: no research
task, live or unverified Ghidra worker, or native helper may overlap it, and it never stops
one. Each run writes `workspace/gc/<id>.json`; repeating the command after an interruption
continues safely because every decision is recomputed from retained state.

| Removed | Condition |
| --- | --- |
| Unchanged native checkouts | Released only through the close verification above |
| Snapshot and native receipt artifacts | No live row, unfinished/failed request, reported result, unverified publication, retained native project or version-tracking owner needs them; unverifiable native metadata stays retained |
| `saved.gzf`, `exports/saved-*`, `shared`, `recovered`, captured explicit-export stages | Owned stopped root; the captured artifact is the durable copy. Candidate roots also require every context of their target to be settled |
| Completed `cross-peer/*/input.gzf` comparison inputs | Owned stopped root, matching closed stage receipt and recognized inventory, with no unresolved operation owning the input or referencing that checkout. Ownership receipts and journals stay retained |
| Detached `view.rep`/`view.gpr` projects | Positively identified legacy worker bound to that root, matching stop receipt (a GUI root only after an explicit close), one imported program and `saved.gzf` matching a verified full snapshot; migration uses its original full snapshot. A completed explicit legacy discard authorizes cleanup without that capture |
| Ghidra `*.cache` files | Owned stopped root or completed server helper |

An applied request keeps its inputs and results; its superseded before-image is not a
recovery input. Failed or unknown requests keep every artifact they name.

A missing native ownership file does not make a project detached. Current checkout rows,
historical checkout receipts and creation intents keep their native roots under the checkout
lifecycle. Missing or unverifiable ownership retains the project with a reason. A native JSON
receipt describes saved buffers but cannot replace them. Closed comparison inputs retain their
separate stage-ownership checks; project retention does not authorize deleting their evidence.
An interrupted detached-project cleanup keeps its full capture and canonical snapshot verification
until both the project and duplicate capture have been removed, including after migration.

The following are always retained and reported: contexts that are opening, need recovery,
hold unresolved or abandoned-unknown effects, debugger traces, an unverified private
snapshot or an unfinished publication; live or unproved workers; changed ownership
receipts; modified or conflicted checkouts; projects with additional files; links and
unrecognized files; checkouts whose project directory is missing; unrecorded captures less than a day old. Binary inputs, server repositories and their history, migration and
initial-import journals, receipts and logs are never collected.

`bytes` counts a hard-linked file only when its last name is removed. Packed programs of
dirty detached contexts remain until that work is merged with the engine that created it.
A migrated unchanged context no longer owns its packed snapshot: the journal keeps its
identity, and the equal content remains in the server version it was proved against.

## Upgrade and runtime changes

A checkout records the runtime that created it as provenance and stays usable after a
compatible runtime or extension change. A Ghidra version that must upgrade the program
database refuses to open it; the project is retained. Deletion after a proved release never
reopens the project, so an interrupted deletion resumes on the next close, open or `gc`.

## Giving up detached work

`ghidra changes discard-legacy --session <id> --target <id> --acknowledge-lost-work`
(Destructive) drops one stopped detached context of an older engine, including operations
whose outcome is unknown. It starts no Ghidra, replays nothing and publishes nothing. A
journal `legacy-migrations/<target>/<context>-discarded-<request>.json` first keeps the original
context and its unresolved requests; the requests then become terminal `failed / discarded`
and cannot run again; their previous outcomes stay in the journal. The journal records intent: a
refused discard may leave one without effect. The next `ghidra gc` removes the stopped detached projects, even
without a capture receipt, and the snapshots that only this context's unfinished or failed
requests named. Reported results of applied requests and artifacts named elsewhere stay.
The next open of the same session and target takes a native checkout once the target is
migrated. Native checkouts,
pending checkout creations, live workers, connected debuggers and unresolved publications
are refused.

## Giving up a lost checkout

`ghidra changes discard-missing --session <id> --target <id> --acknowledge-lost-work`
(Destructive) ends a native checkout whose project directory no longer exists. Unpublished
edits of that context are already lost and cannot be merged. It is refused while the project or
any data beyond its own receipts remains in the context directory, while a project of the
context exists under another name in owned context storage, while any Ghidra worker or native helper of the profile runs or
is unverified, with an unresolved publication, or when another context's unresolved operation
names the checkout. A journal `native-discards/<target>/<context>-<request>.json` first keeps the
original context and its unresolved requests. Then only the recorded server checkout ends,
after its file ID, checkout ID, owner, base version and project path match; a mismatch
changes nothing. Server versions and history are never changed. Requests of the
context become terminal as above, and the next open makes a new checkout. Remaining receipts move beside the
journal. Saved debugger
traces stay. A refusal is terminal for its request ID and changes nothing; after an
interruption repeat the command with the same ID. A copy moved outside owned storage cannot
be detected: restore it first, because it loses its checkout.

## Upgrading with detached work

Finish detached work with the release that created it: merge or discard pending edits,
reconcile unknown operations and close workers before upgrading. The current engine never
saves into a detached worker. An interrupted snapshot publication can still be reconciled by
readback; other unresolved detached operations stay retained.

Publishing a context disposes its checkout even when another context's unresolved transfer
used it as a source; that transfer stays unresolved. Reconcile it before merging its source.
