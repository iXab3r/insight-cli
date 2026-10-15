# Research with a private context

See [query semantics and work limits](query-semantics.md) for completion/truncation, actual type
resolution, qualified heuristics, supported emulation ABIs and memory/signature input variants.

`ghidra save-all --session <id>` saves every Ghidra context in that session and reports a
separate outcome for each input. It does not publish. A partial result preserves completed saves;
repeating the same request ID retrieves those outcomes without another pass.

`ghidra changes discard --session <id> --target <id>` explicitly removes that context's pending
program edits, retains its former private snapshot and restores its own opening base. It requires
Destructive permission. Other sessions and the shared revision remain unchanged; use explicit
refresh to receive a newer shared base afterward. Close a live debugger before discarding static
edits. The saved trace remains separate from the program's opening snapshot.

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

The editing groups include types/categories/layouts, labels/references, properties/bookmarks,
memory flags, functions/variables/tags and batch comments/documentation. Factory's `Destructive`
gate covers deletion and replacement operations separately from ordinary Update. These broader
edits currently use complete saved-state publication; their grouping does not grant scalar merge
semantics. Boolean fields use explicit values; the no-return setter calls its flag `--non-returning`
to keep it distinct from CLI negation syntax.

`ghidra scripts list` returns stable `installation:` and `context:` script IDs. Pass an exact ID to
`ghidra scripts run --script-name <id>`, or source to `ghidra scripts run-inline --code <source>`.
Script arguments follow the pinned whitespace-splitting convention. Execution output is returned
with the saved private state. Script file/network/process effects are immediate and are not undone
by program rollback or replayed by merge. An uncertain script remains unresolved even when some
program changes can be observed.

Additional read groups expose analysis, listings, types, documentation, memory, symbols and
emulation through typed flags. `functions inspect`, `comments inspect`, `strings list` and
`strings search-regex` cover broader selection than the convenient walkthrough commands.
Boolean options take explicit `true`/`false`; complex inputs take bounded JSON. Result variants
are under `value` with the same session/target identifiers. Generated help lists domain arguments;
the caller supplies no program/instance routing. For P-code dataflow choose an actual operation
address from `analysis get-function-pcode`; a function prologue may have no high P-code operation.

For comparisons, keep `--session`/`--target` as the first side and provide `--other-target`.
`--other-session` defaults to the first session; specify it to compare another agent's private
context. `documentation compare`, `functions diff` and the fuzzy matching commands use these
selectors. Fuzzy matching excludes candidates shorter than eight instructions. Results return
both logical scopes and preserve the selected private views.

`documentation transfer` instead selects the private receiver with `--session`/`--target` and the
source with `--source-target` and optional `--source-session`. It copies documentation at matching
addresses; it does not publish. Use `--dry-run` to preview counts. The operation requires
Destructive because transferred definitions/annotations can replace existing receiver data.
After an applied result, publish through ordinary `ghidra merge`. Retried request IDs retrieve
their recorded outcome; recovery retains the source revision actually used by that request.

Opening a second input in the same session preserves the first context. Different processes using
the same session/target share one ordered context. Independent agents choose separate sessions.
Calls return explicit scope so parallel outputs can be associated with the intended input.
`sessions status <session> --limit <n> --offset <n>` pages saved contexts; `--target` selects one.
Its `externalRequests` reports uncertain archive/session-save outcomes without conflating them
with unpublished program edits. A truncated result indicates that another page may exist.

`ghidra status` verifies the selected tool and reports saved pending work. `ghidra save` retains
private changes without publishing. `ghidra close` saves and releases the owned process; continue
with the same open selectors to retain local work. Save/close accept the optional request ID.

The `ghidra ui` commands use the same explicit scope. `cursor --type all` reads address, function,
selection and focused program; headless facets return null with an explicit reason. `tools` starts
the owned GUI when needed and lists its tools using logical program scope. `goto --address <at>`
navigates the owned browser and verifies the cursor. `prompt-policy --action enable --seconds <n>`
temporarily handles the backend's known prompts in that owned GUI for 1–300 seconds; status and
disable inspect or end the policy. Changing UI commands accept request IDs. These actions do not
publish program work. Switching modes retains private edits and other sessions keep their views.
