# Research with a private context

Open input with `insight-cli ghidra open ./client.exe --session new --json`. Store the returned
`session` and `target` as the explicit scope for every later research call. Names are display
labels; equal filenames or addresses in different inputs do not select the same object.

Use `ghidra strings search --contains config.json`, then `ghidra xrefs to --address <string>`.
Reference results include a containing function address when available. Pass that address to
`ghidra functions get` or `ghidra functions decompile`. Add the same session/target selectors and
`--json` to each command; consult generated help for paging and exact flags.

Use `ghidra functions rename` and `ghidra comments set` for private edits. `--clear` (or empty
text) represents a null/absent comment. Successful edits are checked by readback and saved before
`applied`. A later read sees the local result; another session remains independent. These edits
do not publish themselves. Use `ghidra merge` to publish the selected context explicitly.

Another session retains its view until `ghidra refresh`. Refresh receives safe shared changes and
preserves local work. An overlapping field retains original/local/shared values; merge publishes
nothing while any conflict remains. Resolve that field with its ordinary setter,
`--resolve-conflict --expect-shared <observed value>` (or `--expect-shared-null` for an absent
comment). A later shared change invalidates the decision and preserves your work.

Types, signatures and memory edits are saved as complete private program state. They publish
when the shared base is unchanged. After divergence, unproved structural categories remain a
conflict: retain the old session, open a new session on the current target, and transfer the desired
work through ordinary operations. A script is not replayed as a merge algorithm.

Additional read groups expose analysis, listings, types, documentation, memory, symbols and
emulation through typed flags. `functions inspect`, `comments inspect`, `strings list` and
`strings search-regex` cover broader selection than the convenient walkthrough commands.
Boolean options take explicit `true`/`false`; complex inputs take bounded JSON. Result variants
are under `value` with the same session/target identifiers. Generated help lists domain arguments;
the caller supplies no program/instance routing. For P-code dataflow choose an actual operation
address from `analysis get-function-pcode`; a function prologue may have no high P-code operation.

Opening a second input in the same session preserves the first context. Different processes using
the same session/target share one ordered context. Independent agents choose separate sessions.
Calls return explicit scope so parallel outputs can be associated with the intended input.
