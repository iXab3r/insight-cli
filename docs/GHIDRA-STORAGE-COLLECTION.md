# Ghidra working storage and collection

One native checkout holds the private work of a session/target. Ordinary edits and saves
write into that project and record a small receipt; they do not export or copy the
database. `ghidra gc` removes redundant copies, including those left by engines that
exported a packed program for every saved change.

## Release on close

`ghidra close` first saves and stops the worker. The close outcome never depends on what
follows. When the saved receipt equals its server base, no edits, conflicts, traces,
unresolved operations or publication are recorded, and a credentialed native status call
independently reports an unmodified checkout at the same file ID, checkout ID, base
version and fingerprint with no other project files, the checkout is released and its
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
| `saved.gzf`, `exports/saved-*`, `shared`, `recovered`, captured explicit-export stages | Owned stopped root; the captured artifact is the durable copy |
| Detached `view.rep`/`view.gpr` projects | Stopped non-native root holding only its one imported program, with a verified saved snapshot |
| Ghidra `*.cache` files | Owned stopped root or completed server helper |

An applied request keeps its inputs and results; its superseded before-image is not a
recovery input. Failed or unknown requests keep every artifact they name.

The following are always retained and reported: contexts that are opening, need recovery,
hold unresolved or abandoned-unknown effects, debugger traces, an unverified private
snapshot or an unfinished publication; live or unproved workers; changed ownership
receipts; modified or conflicted checkouts; projects with additional files; links and
unrecognized files. Binary inputs, server repositories and their history, migration and
initial-import journals, receipts and logs are never collected.

`bytes` counts a hard-linked file only when its last name is removed. Packed programs of
dirty detached contexts remain until that work is merged with the engine that created it.
A migrated unchanged context no longer owns its packed snapshot: the journal keeps its
identity, and the equal content remains in the server version it was proved against.
