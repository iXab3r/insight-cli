# Query semantics and work limits

Read operations return observations with their scope. A successful command can report a **partial
scan** or a **stopped emulation**: inspect the completion fields before drawing conclusions.
A backend placeholder/unavailable status is an error, including when nested in an otherwise
successful response. Generated help describes the facade's implementation, not an upstream stub.

## Static reachability and constants

`analysis find-dead-code --function-name <name-or-entry>` walks the selected function's decoded
basic blocks. `complete`, `unresolved_flow`, `scan` and `findings` distinguish a completed static
CFG result from a budget stop or unresolved indirect flow. Incomplete/unresolved analysis does
not classify blocks as unreachable. This is not a runtime-execution proof or an analysis of
undecoded bytes outside the function body.

`analysis detect-crypto-constants` searches initialized memory for the versioned exact signatures
listed under `database`. Matches identify constant-table candidates, not proof of cryptographic
execution. `--max-bytes` defaults to 1 MiB and is capped at 16 MiB. `complete: false` returns
`next_address`; continue with `--scan-from`, or increase the budget if the remaining lookahead
cannot fit. `search-byte-patterns` has the same byte budget/continuation behavior. Wildcard byte
pairs use `??`; an explicit mask uses `x`/`?`. Several signatures at one address are grouped in
`signatures`, with a primary `signature`.

## Types, prototypes and entries

`types get-valid-data-types` lists actual program types and successfully resolved builtins,
including category/path, size, alignment and source. It does not advertise a hard-coded list of
Windows names as installed types. `types validate-data-type` reports `resolved` and `diagnostics`.
Resolution is distinct from whether a particular memory location can accept that type.

`types validate-function-prototype` uses Ghidra's signature parser and an isolated temporary type
manager. It returns `valid`, `signature`, `diagnostics` and `persisted_changes: false`. Unsupported
compiler conventions and parse failures cannot pass as valid. The parser supports Ghidra's C
signature syntax; it is not a general C++ compiler. Validation checks the program modification
counter and does not persist types or mutate the function.

`listing get-entry-points` separates `entry_points` with Ghidra external-entry metadata from
`candidates` inferred from names or image base. An external entry designation is metadata;
the image base and a conventional `main` name are not proof of an OS startup address.

## Structured and bounded reads

Globals are records containing `address`, `name`, `type`, `type_path`, `size`, `xrefs`, `named`,
`typed`, namespace and symbol provenance. Parsing display text is unnecessary.

Facade-owned global/string/type/instruction scans accept `--max-scan` (default 100000, maximum
200000 visited inputs), `--timeout-seconds` (1–30), `--limit` and `--offset`. Output paging does not
increase the work budget. `scan.complete: false`, `truncated: true` and `total_known: false` mean
`total` counts only the scanned prefix; absence from that prefix is not a negative whole-program
finding. Narrow the query or raise its budget within the declared bound. Oversized string units
also stop a scan rather than silently claiming complete coverage. Returned string values are
bounded; check truncation fields.

`strings list` and `strings search` visit **defined data**, not every possible literal in memory.
The visited-input budget includes non-string data. Zero matches with an incomplete scan means
the searched prefix contains no matches; it does not establish absence. Increasing `--offset`
only skips matching rows from that same scan and cannot reach a later unscanned string. These
scans have no continuation cursor. Increase `--max-scan` up to 200000 when that covers the
needed data. A narrower text filter alone does not skip earlier visited data or reach beyond
that bound; use an explicitly addressed memory search when the needed region is known.
For undefined ASCII/UTF-16 literals, encode the expected bytes and use
`analysis search-byte-patterns --pattern <hex> --max-bytes <bytes>`; that separate initialized-
memory search exposes `--scan-from`/`next_address` continuation. Byte matches still need
interpretation and do not define string data or prove a stored xref exists.

Bounded string/instruction regex search supports literals, escapes, anchors, character classes
and at most one `.*` wildcard. Branching/nested repetition and unsupported patterns are rejected.
Use the literal `strings search --contains` convenience when no regex is needed.

Other pinned upstream operations explicitly return `scanPolicy.workBound: not-guaranteed`:
their page/output limit may follow a full scan, and transport cancellation does not prove backend
work stopped. The generic accepted result limit is 1 MiB. This policy is distinct from the actual
work counters on facade-owned scans; narrow function/address/filter selectors for costly upstream
analyses. Scores, similarities, estimated bounds, name suggestions and malware/IOC patterns carry
`semantics` with their algorithm and limitations. Confidence labels are not calibrated probabilities.

## Emulation

Supported policies are little-endian `x86-cdecl` (32 bits), `windows-x64` and `sysv-x64`. `--abi auto`
recognizes the supported compiler specifications, including Windows Clang. Unknown architectures
or compiler policies are explicit errors. Inputs run in isolated emulator memory and cannot patch
the program database.

`emulation emulate-function --arguments '[2]' --registers '{}' --memory '[]'` supplies unsigned
integer/pointer arguments using the ABI's register/stack layout. Explicit register inputs can
override argument registers; PC/SP remain ABI-owned. Initial memory accepts at most 64 regions
and 64 KiB in total. The ABI creates an aligned stack, correctly sized return address and Windows
shadow space. Floating-point/aggregate ABI lowering, OS services and imported process behavior
are not modeled by this helper.

Read `completed`, `hit_return`, `stop_reason`, `steps_executed`, `abi` and `pointer_bytes`.
`completed: false` is not a function result. Budgets count instructions: at most 100000 steps per
candidate and a 1–30 second timeout. Hash batches accept at most 256 candidates and 200000 total
instructions; incomplete candidates cannot match a target hash. Batch `complete`, `truncated`
and individual `outcomes` report the actual scope checked. This is independent from live debugging.

## Memory and signature edits

`memory create-block` accepts hex/base64 initial bytes, optional size/fill byte, uninitialized
memory, overlay, volatile and comment inputs. Content determines omitted size; size is capped
at 16 MiB. Uninitialized memory cannot carry initial bytes or nonzero fill. Overlays retain their
distinct address-space identity. The saved database is independently checked for metadata and
the entire initialized-content digest before acknowledgment. `functions set-function-prototype`
also accepts `--calling-convention`; saved signature types and convention are verified.

These remain complex private edits. Request IDs retrieve retained outcomes; lost responses are
reconciled from saved effects, never blindly re-created. Publish with explicit merge on the
unchanged shared base; structural divergence still retains a conflict.
