# Navigate a sparse database

Function counts and `ready` do not establish decoded bodies, strings or xrefs. A one-byte
function entry without Listing instructions can still be useful to the decompiler. Choose
the route from the actual observation before building a script or requesting broad analysis.

All examples below need the same `--session S --target T --json`. Replace placeholder
addresses with observed addresses in that input; symbols and offsets never transfer implicitly.
Use generated help for exact flags.

| Observation | Next command | What it establishes |
|---|---|---|
|Empty navigation results / suspicious body sizes|`analysis navigation`|Bounded metadata samples and coverage; no analysis is started|
|Known function entries, even without Listing|`functions inspect --functions 0xENTRY_A,0xENTRY_B --fields decompiled_code,callees --include-call-context false`|Up to20 compact decompiler observations; inspect each status and truncation|
|Interior code addresses with sparse saved bodies|`functions inspect --functions 0xCODE_A,0xCODE_B --resolve-address containing-or-preceding --max-entry-distance 4096 --fields entry_point,decompiled_code --include-call-context false`|One guarded lookup+inspection; a preceding entry is explicitly a candidate, not established containment|
|Stale/failed decompilation at a known entry|`functions force-decompile --function 0xENTRY`|Fresh native decompiler output in `value.decompiled`; no function creation or Listing repair|
|Known executable bytes, no function entry|`functions decode --address 0xCODE --max-bytes 64 --max-instructions 16`|Bounded local instructions/direct targets, input hash and stop reason; no persistent definitions|
|Expected literal absent from defined strings|`strings anchors --text SPARSE --encodings ascii,utf16le --scan-from 0xREGION_START --scan-through 0xREGION_END`|Exact raw hits plus separate bounded NUL candidate context, explicit coverage and stateless cursor|

## Follow existing entries first

Start with a small set of independently known entries: exported symbols, retained project
evidence for this exact build or direct targets from bounded decode. Check the function selector;
an interior address is not automatically an entry. Compact inspection avoids unrelated metadata
and supports mixed outcomes, text paging and owner-host saves. For large output, use
`--save-owner-directory <new-absolute-directory>` and retain its hash manifest; see
[research](research.md) for Unicode windows, view guards and native truncation.
Empty `callees` or xrefs on a sparse database do not prove that the decompiled function
has no calls. Keep decompiler observations distinct from stored-reference coverage.

For known interior addresses, the explicit resolution mode avoids the separate name/prefix
search. It accepts addresses only and requires the distance bound. Inspect `resolution.kind`
for every result: `exact-entry`, `recorded-containing`, or `preceding-entry-candidate`.
Recorded containment is a database fact, not validated source membership. The fallback may
point into unrelated padding, split code or an incorrect prior function. It is not a repair.
Exact/recorded containment take precedence; the distance limit applies only to fallback.
See [research](research.md) for mixed outcomes, original selector keys and shared budgets.

Use `force-decompile` when a fresh decompiler pass is needed. It does not accept the inspect
text-window/save flags; its ordinary query response is capped at1MiB and reports the pinned
upstream work bound as not guaranteed. Selecting one entry narrows the request but is not a
hard instruction/CPU bound. A host running-session ID must be awaited, not retried as failure.
No successful decompile is proof of complete control flow, correct types or valid function bounds.

After transient decompilation, `functions disassemble`, instruction search and stored xrefs can
remain empty. Repeating cache refresh does not populate them. Corroborate an important store,
branch or call with bounded `decode` at its observed instruction address. Its direct targets are
local decoded flow, not a complete call graph. Neither route runs the target program.

## When entries or literals are absent

An absent function stays absent after `force-decompile`. Use bounded decode, retaining its
stop reason; do not silently create functions to make a read succeed. Decode stops at terminal
or unconditional flow and has byte/instruction limits; it is not whole-function reconstruction.
Persistent Listing/entry/body repair is a separate explicit Update operation in the owned
context, followed by saved readback. Consult `functions create`, `functions disassemble-bytes`
and their generated help rather than an unbounded all-function reconstruction script.

For literal search, prefer `strings anchors` with explicit encodings and both inclusive bounds.
It searches raw initialized bytes, merges adjacent initialized blocks, and never bridges a hole.
Read `matchAddress` as the exact target; a nullable candidate `start` is a separate observation.
NUL candidates are not semantic strings. `textFrom` is the preview address; `complete`,
boundary evidence and `decoding` qualify it. Invalid or capped context keeps the raw hit.
Continue using `value.cursor`; only page budgets can change. `scan.complete` refers to search
coverage, not complete candidate text. Context/prefetch/rereads consume `max-bytes` (minimum
32768), and the default payload cap is 1024 bytes. Retain all `(address,encoding)` pairs,
including overlaps and UTF-16 at odd addresses. It performs no definitions, analysis or save.
Then pass selected exact match addresses to one batched `analysis code-references`, and
selected code addresses to `functions inspect` with the explicit resolution mode above.

For arbitrary masked binary patterns, encode ASCII/UTF-16 as appropriate with the existing
`analysis search-byte-patterns`; for example `--pattern '53 50 41 52 53 45'` is ASCII `SPARSE`.
Quote spaced hex patterns. Read `complete`, `scanned_bytes`, `next_address` and the bounds;
continue with `--scan-from <next_address>`. `--offset` on defined-string results does not
advance memory coverage. A narrowed text filter does not skip earlier non-string defined data.
Use `memory list` to identify initialized/executable blocks; do not assume a guessed block name
or that the image-base address belongs to executable code.

Byte matches are not validated code references. Existing xrefs describe saved DB metadata.
For exact RIP-relative operands or direct CALL destinations, use the bounded ReadOnly candidate
scanner below. Arbitrary scripts remain potential writes with saved-state/recovery costs;
a compile/transport error must not be blindly replayed.

## Raw-byte code-reference candidates (V1)

```sh
insight-cli ghidra analysis code-references --session S --target T \
  --to 180080000,180080008 --forms call-rel32,lea-rip,mov-rip,call-rip-slot \
  --scan-from 180000000 --scan-through 18002101f --limit 100 --json
```

`value.matches` contains instruction bytes, full length, operand index/width, exact target,
form, native instruction text and boundary evidence. Example row:

```json
{"from":"180000060","to":"180080008","form":"call-rip-slot","bytes":"ff15a2ff0700","length":6,"operand_index":0,"operand_bits":64,"target_role":"pointer-slot","validation":"decoded","boundary":"unconfirmed","instruction":"CALL qword ptr [0x180080008]"}
```

Targets are
1–64 distinct default-space unsigned 64-bit addresses, comma separated; they share one pass.
Only x86 little-endian 64-bit languages with known 64-bit decode mode are supported. No code
executes, and no Listing instructions, functions or xrefs are created. This does not follow
register values, indirect callees, thunks, pointer contents or control flow.

| Form | Supported encoding | Target role |
|---|---|---|
| `call-rel32` | E8 + signed rel32 | `direct-call-target` |
| `lea-rip` | 8D, ModRM RIP-relative | `effective-address` |
| `mov-rip` | GPR MOV 88/89/8A/8B, ModRM RIP-relative | `effective-address` |
| `call-rip-slot` | FF /2, ModRM RIP-relative | `pointer-slot` |

Forms default to all four; `--forms` restricts them. Legacy 66/26/2E/36/3E and REX prefixes
are admitted only when the native full decode agrees with the constrained encoding/length.
REX before a later legacy prefix is reset. Widths are explicit: `lea eax` and `lea rax` remain
distinct. V1 excludes 67 address override, FS/GS, LOCK/REP, C6/C7 immediate MOV,
MOVSX/MOVZX/MOVSXD and SIMD/VEX/EVEX **at that candidate start**. A later byte inside any
instruction or immediate can independently decode as a supported candidate.

Each byte offset is tested, including overlapping and prefix-alternative starts; advancement
is one byte. `listing-confirmed` requires a matching stored instruction and compatible bytes,
length and operand display. `listing-conflict` means overlap/disagreement with a stored
instruction. `unconfirmed` means neither. Even listing-confirmed is not proof of execution,
function membership or a complete call graph. LEA is an effective address, not a memory read.

`--scan-through` is the inclusive final byte, and each match fits entirely inside the original
range. Only initialized executable default-space memory is visited. Adjacent eligible blocks
merge so an instruction may cross their boundary; holes, uninitialized blocks and non-executable
memory never bridge. A complete scan only exhausts this declared eligible input/form set.

`value.scan` reports `bytes_read` (including lookahead and rereads), `tested_starts`,
`visited_candidates` (selected-form encoding prefilter hits, including target/decode rejects),
`next_start` (first unchecked start), `complete`, `reason` and native `elapsed_ms`.
The frontier can skip ineligible gaps; it does not assert that gap bytes were decoded.
Reasons are `exhausted`, `byte_limit`, `candidate_limit`, `timeout` and `result_limit`.
The native cooperative deadline is checked even in no-match regions. Compile/dispatch/view
observation time is outside that deadline; it remains part of command wall time.

Defaults: 4MiB bytes, 200000 candidates, 5 seconds and 100 matches. Maxima: 16MiB,
1000000 candidates, 30 seconds and 1000 matches. Minimum byte budget is15, so a maximum-length
x86 start can progress with its lookahead. No semantic completeness is implied by these limits.

For an incomplete result, continue with the opaque stateless token:

```sh
insight-cli ghidra analysis code-references --session S --target T \
  --cursor TOKEN --limit 1000 --max-bytes 8388608 --json
```

Cursor excludes `--to`, `--forms`, `--scan-from` and `--scan-through`; omitted controls inherit
the previous page. It binds the normalized original query, frontier, algorithm version, selected
context/snapshot/generation, native modification observation and process incarnation. Scope,
format or version mismatch fails; view changes, including restoring the same snapshot in a new
JVM, fail with `changed_view`. Start a new query after such a change. Before/after observations
share the context's ordered action; a native modification guard additionally covers the scan.

Tokens are unsigned, untrusted continuation parameters, not evidence that earlier offsets were
scanned. There is no cursor registry, per-query snapshot or journal save. Retain page results
if coverage evidence is needed. The trusted helper still uses the existing inline-script
transport and incurs its compile/dispatch cost; arbitrary user scripts remain Update operations.

## PE runtime regions for sparse function inspection

Use `ghidra functions inspect --functions <addresses> --resolve-address containing-or-pe-runtime`
when PE32+/AMD64 runtime metadata can replace manual preceding-entry checks.
`--max-unwind-bytes` bounds returned header/table bytes across the batch (default4194304,
1–16777216); lookup has a fixed5-second cooperative deadline. It reads current mapped headers
at the actual image base and the whole declared Exception Directory, without a file fallback,
section-name assumption, analysis or function creation. Unavailable/malformed/incomplete lookup
blocks selection and retains DB facts; `boundary_conflict` and `runtime_entry_not_defined` retain
validated bounds. A runtime region does not prove instruction boundaries, semantic membership
or whole-function bounds; leaf routines may have no record. No preceding fallback is used.
Batch unresolved rows are partial; a single unresolved selector returns a partial CLI error
with lookup/view/evidence. Guards cover failed dispatch; existing text paging/save rules apply.
