# Selected native SDK workflows

These commands extend the pinned MCP catalog. All program calls select both `--session` and
`--target`; API callers use the same Factory command paths. Use generated help for flags.
Programs remain private until explicit `ghidra merge`. Every new program edit is a complex
change: saved-state verification is required, and a diverged shared base retains a conflict.
`refresh` does not silently overwrite either complex version. Program edits require Destructive
permission. File/database creation and VT decisions require Update; reads require ReadOnly.

## Compare and edit a private program

`ghidra changes compare --other-target <id> --other-session <id>` compares immutable saved
contexts with native ProgramDiff. Choose `--categories '["bytes","comments","symbols"]'`;
other supported categories are code_units, functions, references, context and properties.
Results retain address ranges and completion flags. This does not run a universal DB merger.

`ghidra memory patch-bytes --address 0x180000000 --expect-hex 9090 --bytes-hex 9091`
requires equal lengths of 1–4096 bytes and clears overlapping listing. `assembly preview` takes
`--instructions '["NOP"]'`; `assembly apply` also requires exact `--expect-hex`. Assembly uses
the selected program's language and processor context. It does not rebuild executable files.

`memory block-state --name <block>` returns current layout and a full digest for initialized
blocks up to 16 MiB. `split-block` and `move-block` require that digest, size and original start;
`join-blocks` requires both sizes/digests and compatible adjacent blocks. No uninitialized or
oversized-block edit is implied. `processor-context read|set|clear` addresses a named register
and a range of at most 65536 bytes. Read distinguishes explicit state from compiler defaults.

`namespaces list|create|update|delete` supports ordinary namespaces/classes; deletion requires
an empty container. `externals` supplies create/update/delete-library and create/update/delete-location.
Deletion refuses retained dependencies. It does not recursively erase referenced program state.

`decompiler ir --address <function> --simplification normalize --max-ops 1000` returns typed SSA
operations, varnodes, address spaces, sizes and block IDs. Options are known Boolean keys:
eliminate_unreachable, respect_read_only, infer_constant_pointers, split_structures, split_arrays.
Native timeout is 1–120 seconds. `completed` describes decompilation; `ir_complete` separately
reports a truncated operation list. The result is a bounded view, not a serialized HighFunction graph.

## Loader, exporter and type archives

`ghidra formats loaders --input <file>` consumes immutable bytes and lists actual installed
loader IDs, supported language/compiler specifications and native option definitions.
`ghidra open <file> --session new --loader BinaryLoader --language x86:LE:64:default
--loader-options '{"Base Address":"0x10000","File Offset":"0x2","Length":"0x6"}'`
selects a loader explicitly. Primitive options, native address and HexLong options are converted
and validated; unsupported complex option classes fail explicitly. One program belongs to a target.

`formats exporters` lists compatible native exporters and their options. `formats export
--exporter 'Raw Bytes' --ranges '[{"start":"0x10001","end":"0x10003"}]'
--output-directory <new-directory>` requires a format supporting restricted address sets.
All output/companion files are hashed and retained. Existing destinations are not overwritten.
Native completion receipts permit a repeated request ID to recover completed bytes without
another export. An incomplete/uncertain export cannot be replayed blindly.

`types define-layout --path /Owned/Record --packing 1 --fields
'[{"name":"flags","type":"uint","bit_size":3},{"name":"value","type":"ushort"}]'`
uses native structures and bitfields. Packing/alignment accept -1, zero or powers of two through
64; explicit byte offsets require packing -1. There are at most 256 fields. `types layout` returns
native source archive/universal IDs and bounded field/setting records. `types set-settings --path
/Owned/Number --settings '{"Format":1}'` uses actual definition names and native enum choices;
null clears an explicit setting. Inventory the type first; definitions differ between native types.

`types archive-export --types '["/Owned/Record"]' --output-directory <new-directory>` creates a
real GDT. `types archive-import --input <file.gdt> --types '["/Owned/Record"]'` consumes an
immutable archive up to 64 MiB and checks saved layout/source identity. A conflicting existing
layout is rejected. `types create-struct --replace-placeholder` replaces only an empty structure.

## Version porting and library identification

`version-tracking create --source-target <id> --source-session <id>` creates a persistent native
VT session inside the destination research scope. The returned tracking ID owns the exact saved
source/destination snapshots. `list`, `matches --tracking <id>` and `markup --tracking <id>
--source-address <address> --destination-address <address>` retain native correlator/score/markup
provenance. Exact function bytes and duplicate instruction correlators are selected; instruction
matching can ignore operands. Ambiguity is retained. Unmatched means no association in these
selected policies, not proof of no equivalent function. Inputs are limited to 10000 functions;
correlation has a 60-second monitor budget, match pages have at most 1000 rows.

`decide` explicitly accepts, rejects or resets an association; native one-to-one constraints apply.
Decisions survive owner replacement. Markup is inspected before ordinary facade edits transfer
selected changes. No automatic markup application/publication is performed. Context-changed flags
warn when current programs differ from the VT snapshots. Unknown decisions block further decisions
on that object until reconciliation; the same request ID never blindly repeats a native effect.

`libraries build-fid --library <name> --library-version <version> --output-directory <new-directory>`
creates a genuine native FID database. `libraries fid-query --database <file.fidb> --function <entry>
--threshold 1` reports native scores, library/version/variant, database digest and no-match semantics.
`build-bsim --library <name> --output-directory <new-directory>` creates embedded native BSim/H2;
`bsim-query --database <database.mv.db> --function <entry> --similarity 0.9` reports signature version,
similarity and significance. Required SDK components are supplied by the pinned Ghidra install;
there is no external database service to provision for these local workflows. Inputs are bounded to
1000 functions, output is bounded, and scores are not calibrated probabilities. Query databases
are consumed into private immutable storage; the caller's file is unchanged.

## Live target and retained trace

`debugger write-memory --address <dynamic-address> --expect-hex <bytes> --bytes-hex <bytes>`
and `write-register --register <name> --expect-value <hex> --value <hex>` require a stopped,
selected live target at its current live time. They refresh from the target before and after the
write. Preconditions are read-before-write checks, not atomic compare-exchange. Register width
is exact. These live effects do not enter program publication. A lost write response remains
uncertain and is never replayed, even when trace bytes subsequently show the requested value.
The owned copy of Ghidra 12.1.2's Python adapter corrects its SBProcess memory-write call; the
installed SDK/wheel remains unchanged and runtime fingerprint checks still apply.

`debugger timeline --limit 100` returns snapshot keys/times/schedules and continuation.
`objects --limit 100 --max-scan 10000` returns persistent object IDs, schema, path and lifespan
at a selected snap. `object-values --object-id <id> --key <exact-key>` reads one key, optionally
over at most 1000 snapshot keys. Values preserve address/object-reference types and 64-bit integers;
unknown Java value kinds are explicit. Object iteration is budgeted, paths replace the owned
staging root with `@target`, and IDs remain scoped to the selected trace. `schedule --schedule <time>`
parses/validates native schedules and reports `executed: false`. It does not execute emulation.
Saved trace queries remain available after disconnect; live execution is never resurrected.
