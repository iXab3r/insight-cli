# Research with a private context

See [query semantics and work limits](query-semantics.md) for completion/truncation, actual type
resolution, qualified heuristics, supported emulation ABIs and memory/signature input variants.

`ghidra save-all --session <id>` saves every Ghidra context in that session and reports a
separate outcome for each input. It does not publish. A partial result preserves completed saves;
repeating the same request ID retrieves those outcomes without another pass.

`ghidra changes discard --session <id> --target <id>` requires Destructive permission.
For native contexts it retains Ghidra's `.keep` when work is dirty, releases the old checkout
and checks out the current server version in the same project. It does not publish. Close a
live debugger first. Legacy detached contexts require explicit migration and are retained.

Open input with `insight-cli ghidra open ./client.exe --session new --json`. Store the returned
`session` and `target` as the explicit scope for every later research call. Names are display
labels; equal filenames or addresses in different inputs do not select the same object.

If the database has missing strings/xrefs, one-byte function bodies or no Listing instructions,
use [sparse navigation](sparse-navigation.md) before following the metadata-only route below.
It distinguishes existing entries, undefined code and undefined literals. For raw literals,
use `strings anchors --text Widget --encodings ascii,utf16le --scan-from START --scan-through END`,
then explicit batched code references and function inspection. Candidate context remains
separate from exact match addresses; coverage, decoding, caps and cursor are explained there.

Use `ghidra strings search --contains config.json`, then `ghidra xrefs to --address <string>`.
Reference results include a containing function address when available. Pass that address to
`ghidra functions get` or `ghidra functions decompile`. Add the same session/target selectors and
`--json` to each command; consult generated help for paging and exact flags.

An exported object can also have an external-entry metadata reference. That item has
`from: null`, `kind: "EXTERNAL"` and `source: "entry-point"`; it counts in the returned
page but has no source address to navigate. Ordinary references retain their hexadecimal
`from` address and containing function when available.

Use `ghidra functions rename` and `ghidra comments set` for private edits. `--clear` (or empty
text) represents a null/absent comment. Successful edits are checked by readback and saved before
`applied`. A later read sees the local result; another session remains independent. These edits
do not publish themselves. Use `ghidra merge` to publish the selected context explicitly.

Another session retains its saved native checkout until `ghidra refresh`. The service stops the
worker and calls native Update on that same project: checkout identity survives, the base advances,
and local changes merge through Ghidra. Native conflicts reject the whole Update and retain the
original working copy/base. Status reports the native conflict description. The legacy scalar
`--resolve-conflict` option is unsupported for native decisions; no coordinator winner is invented.

Types, signatures, structures and other analysis edits use Ghidra's stock resolvers and native
checkout change sets. Divergence alone is not a category conflict. `ghidra merge` performs native
Update, then journaled check-in. Independent read-only history/exact-version buffer verification
precedes release/drop of the successful native project. Continued work receives a fresh checkout;
worker/owner restart before publication reopens the same project without packed-snapshot import.

Ordinary saves retain the native DB and lightweight saved-view receipts. Full packed exports are
for initial import and explicit consumers such as export, cross-program comparison and VT.
`receivedChanges` on native refresh counts a received program revision transition; pending scalar
and opaque operation records are diagnostic, not merge semantics. Memory layout and language
changes still require native exclusive access. The editing groups include types/categories/layouts,
labels/references, properties/bookmarks, memory flags, functions/variables/tags and documentation.
Factory's Destructive gate remains separate from ordinary Update.

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
Closing a verified unchanged checkout also releases it (`checkout: released`); the next open uses
the current shared revision. Any pending or unproved work keeps its checkout (`retained`).

The `ghidra ui` commands use the same explicit scope. `cursor --type all` reads address, function,
selection and focused program; headless facets return null with an explicit reason. `tools` starts
the owned GUI when needed and lists its tools using logical program scope. `goto --address <at>`
navigates the owned browser and verifies the cursor. `prompt-policy --action enable --seconds <n>`
temporarily handles the backend's known prompts in that owned GUI for 1–300 seconds; status and
disable inspect or end the policy. Changing UI commands accept request IDs. These actions do not
publish program work. Switching modes retains private edits and other sessions keep their views.

Selected native SDK commands and their effect/budget contracts are described in
[native workflows](native-workflows.md).

`functions get/decompile` failures include `selector`, stable `reason` and, when supplied by
native, a sanitized diagnostic of at most 500 Unicode characters. Reasons distinguish
`function_not_found`, `native_function_failure`, `selector_mismatch`, `invalid_native_shape`,
`missing_signature` and `missing_decompiler_text`. Missing definitions remain failures; reads
never create functions or run analysis. JSON-RPC `cli.execute` preserves the same error data.
If executable bytes are known but the function is absent, use the read-only `functions decode`
command below at the explicit address. A containing function with a one-byte body and missing
stored xrefs can also indicate sparse metadata. Decode reveals bounded local instruction flow;
it does not repair function boundaries or establish whole-function callers/callees. Defining
functions or disassembling the listing requires a separate explicit Update operation.
For a known existing entry, try compact `functions inspect` first; use
`functions force-decompile --function <entry>` to refresh stale/failed decompiler output.
Its result is `value.decompiled`, and its pinned upstream work bound is not guaranteed.
Successful transient decompilation can coexist with an empty Listing and missing stored xrefs.
It does not create an absent function or repair its saved body. Avoid repeating it merely to
populate `functions disassemble`; use bounded `decode` for local instruction corroboration.
Per-item inspection failures retain the facade recovery message in `error` and the bounded
native explanation separately in `nativeDiagnostic`; use stable `reason` for classification.

The existing `functions inspect` accepts 1–20 distinct names/addresses. Existing `--fields`
remain valid; unknown fields fail before dispatch. Decompiled text uses per-item
`--offset-chars` (default 0), `--limit-chars` (default 16000, maximum 32768), and a shared
`--total-chars` budget (default 64000, maximum 128000), allocated in selector order.
Each item retains success/not-found/failure and `text` metadata: full returned-native-text
SHA-256, Unicode code-point length, window, next offset and native truncation. A zero-length
window can mean the total budget was exhausted. A last CLI page does not establish native
completeness. Use fewer selectors to advance a starved item. The one MiB response cap still
applies to all fields. These are text/result bounds, not a native decompiler CPU budget.

Keep `value.view.identity` and supply `--expect-view <identity>` on continuation. An observed
context generation, snapshot or revision change rejects continuation with `changed_view`.
Hashes bind each observed native text; compare them across pages as well. A view identity is
conservative across lifecycle changes and does not assert determinism of the decompiler.

For compact evidence, use `--save-owner-directory <absolute-new-path>`. The elected CLI owner
writes full returned native text (at most four MiB per function, at most 20 functions) to numbered
hash-named `.c` files and writes `manifest.json` last. The response omits inline code and gives
absolute paths, coverage, hashes, lengths and native truncation. This directory is on the owner
host, including through JSON-RPC; it is never silently a client-host path. An existing directory
is rejected. A filesystem failure can leave a partial new directory without a completed manifest;
retain it for inspection and choose a fresh directory for another explicit save.

For sparse interior addresses, opt in to
`functions inspect --functions <hex-addresses> --resolve-address containing-or-preceding --max-entry-distance 4096`.
The distance is required (1–65536 bytes), applies only to fallback and is rejected without the
mode. Names/address-space prefixes are not accepted in this mode. Exact entries and recorded
body containment take precedence in valid default-space memory, including non-executable or
uninitialized blocks. Otherwise the nearest previous known entry is considered only inside
the same initialized executable memory block as the query.
No byte search, analysis or function creation is performed.

Every resolved row retains `entry_point` and `resolution`, even if `--fields` omits entry metadata
or the function read fails. Kinds are `exact-entry`, `recorded-containing` and
`preceding-entry-candidate`. `recordedBodyContainsAddress` is actual stored body membership,
not semantic proof. `distanceBytes` is zero for exact entries and the positive offset for
preceding candidates; it is omitted for recorded containment, whose body can precede its entry.
`status: success` means the selected function was read, not that the query belongs to it.

`--functions` preserves original selector spelling as keys, including hexadecimal aliases.
Selected entries are deduplicated for native reads, but inline text is charged for every
original row in selector order. Each saved row keeps its mapping; owner-save paths remain
per-selector. `--function` retains the existing single-row result/error behavior. Policy misses
are per-item `not_found` with `address_out_of_range`,
`address_not_in_initialized_executable_block`, `no_preceding_entry`, `entry_outside_block` or
`entry_distance_exceeded`; these do not claim that code or an unknown function is absent.
The before/after guard covers both lookup and inspection, and native selector/entry mismatches
fail. Existing view continuation/text hashes, text windows and result/file bounds still apply.

`functions decode --address <address> --max-bytes 64 --max-instructions 16` uses Ghidra pseudo
instructions without defining listing instructions, functions or xrefs, running analyzers or
saving state. It requires initialized executable memory and currently supports x86 language
variants; other languages return an explicit unsupported capability error. Bounds are 1–4096
bytes in one executable block and 1–256 instructions. Results bind input bytes/hash, language,
compiler and context view to instructions, consumed bytes and stop reason. Direct targets are
computed from instruction bytes, not proof of function membership or stored xrefs. Indirect
flow has no invented target. Decoding stops at terminal/unconditional flow, input/instruction
bounds, undecodable/truncated bytes or unavailable context. Existing `disassemble-bytes` remains
an Update operation with its original guards.

## Navigation and lifecycle diagnostics

`analysis navigation` uses the selected session/target and ReadOnly permission. It reports
`initialAnalysis` (`none` or `requested`) as the original facade import policy, separately from
the current metadata observations. Prior analysis history is unknown, including saved/imported
databases. `ready` means the context opened; it does not establish analysis completeness.

The diagnostic samples at most 128 functions, instructions, stored references and defined-data
units per category, in address order, sharing `--max-scan` (default 10000, 1–200000) and a fixed
five-second native deadline. Each category reports its own completion; top-level `scan` reports
the visited sum, sample bound, completion and reason. Defined-string counts cover only sampled
defined data. One-byte bodies together with missing entry instructions in at least 80% of the
sample yield `sparse-metadata`; this is an explicit heuristic, not proof that a specific analysis
pass failed. Normal instruction-bearing one-byte leaf functions alone do not trigger it.
Follow [sparse navigation](sparse-navigation.md): known function entries can use compact inspection
and cache refresh; executable bytes without an entry use bounded decode, undefined literals use
byte search and explicit continuation. The diagnostic does
not run analyzers, define data, repair boundaries, save a snapshot or certify semantic completeness.

`diagnostics lifecycle` reads retained start/restore/stop events and the current process receipt
without starting or probing Ghidra. At most the latest 128 observations are retained. A stopped
receipt can identify `explicit_close`, `view_replaced`, `mode_changed`, `startup_failed` or
`owner_dispose`; historical receipts without reasons remain `unknown`. Owner disposal does not
establish whether Factory exited due to idle, explicit stop, a signal or another cause. A current
receipt without a matching stop receipt reports `unobserved`, not a claim that the PID is live.

Internal correlated timing diagnostics live under profile workspace `diagnostics/timings.jsonl`,
with one previous segment and an eight-MiB rotation threshold. They contain operation names,
timestamps, correlation/parent IDs, duration and success/failure, not argv, source, payloads or
exception text. They are an internal troubleshooting format, not a public trace API. Nested spans
must not be added to their parents. `facade.command` starts at the handler and ends before Factory
serializes the response; client startup, IPC and response overhead are not separately measured.
Tracing is best-effort and cannot change program outcomes. Empty runtime readiness checks still
avoid creating a research workspace. The Factory idle policy remains unchanged.

For sparse PE32+/AMD64 interior addresses, `functions inspect --resolve-address
containing-or-pe-runtime --max-unwind-bytes 4194304` uses fully validated current mapped runtime
regions and independent recorded-body facts. Conflicting or missing entries remain partial with
evidence; incomplete/malformed/unavailable metadata prevents automatic selection. This is not
semantic function reconstruction; see [sparse navigation](sparse-navigation.md).
