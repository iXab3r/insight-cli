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

## `ghidra gc [--dry-run]`

Collection covers the selected profile. Dry-run needs ReadOnly and changes nothing;
execution needs ReadOnly and Destructive. It uses the migration admission gate: no research
task, live or unverified Ghidra worker, or native helper may overlap it, and it never stops
one. Each run writes `workspace/gc/<id>.json`; repeating the command after an interruption
continues safely because every decision is recomputed from retained state.

| Removed | Condition |
| --- | --- |
| Unchanged native checkouts | Released only through the close verification above |
| Snapshot and native receipt artifacts | No live row, unfinished/failed request, reported result, unverified publication or version-tracking owner names them |
| `saved.gzf`, `exports/saved-*`, `shared`, `recovered`, captured explicit-export stages | Owned stopped root; the captured artifact is the durable copy. Candidate roots also require every context of their target to be settled |
| Detached `view.rep`/`view.gpr` projects | Non-native root with a matching stop receipt (a GUI root only after an explicit close), holding only its one imported program, with a verified saved snapshot or migration journal |
| Ghidra `*.cache` files | Owned stopped root or completed server helper |

An applied request keeps its inputs and results; its superseded before-image is not a
recovery input. Failed or unknown requests keep every artifact they name.

The following are always retained and reported: contexts that are opening, need recovery,
hold unresolved or abandoned-unknown effects, debugger traces, an unverified private
snapshot or an unfinished publication; live or unproved workers; changed ownership
receipts; modified or conflicted checkouts; projects with additional files; links and
unrecognized files; unrecorded captures less than a day old. Binary inputs, server repositories and their history, migration and
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

## Upgrading with detached work

Finish detached work with the release that created it: merge or discard pending edits,
reconcile unknown operations and close workers before upgrading. The current engine never
saves into a detached worker. An interrupted snapshot publication can still be reconciled by
readback; other unresolved detached operations stay retained.

Publishing a context disposes its checkout even when another context's unresolved transfer
used it as a source; that transfer stays unresolved. Reconcile it before merging its source.
