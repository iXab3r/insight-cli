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
do not publish themselves. This checkpoint has not yet delivered merge/refresh.

Opening a second input in the same session preserves the first context. Different processes using
the same session/target share one ordered context. Independent agents choose separate sessions.
Calls return explicit scope so parallel outputs can be associated with the intended input.
