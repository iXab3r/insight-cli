# Navigate a sparse database

Function counts and `ready` do not establish decoded bodies, strings or xrefs. A one-byte
function entry without Listing instructions can still be useful to the decompiler. Choose
the route from the actual observation before building a script or requesting broad analysis.

All examples below need the same `--session S --target T --json`. Replace placeholder
addresses with observed addresses in that input; symbols and offsets never transfer implicitly.
Use generated help for exact flags. These are existing commands, not a new analysis API.

| Observation | Next existing command | What it establishes |
|---|---|---|
|Empty navigation results / suspicious body sizes|`analysis navigation`|Bounded metadata samples and coverage; no analysis is started|
|Known function entries, even without Listing|`functions inspect --functions 0xENTRY_A,0xENTRY_B --fields decompiled_code,callees --include-call-context false`|Up to20 compact decompiler observations; inspect each status and truncation|
|Stale/failed decompilation at a known entry|`functions force-decompile --function 0xENTRY`|Fresh native decompiler output in `value.decompiled`; no function creation or Listing repair|
|Known executable bytes, no function entry|`functions decode --address 0xCODE --max-bytes 64 --max-instructions 16`|Bounded local instructions/direct targets, input hash and stop reason; no persistent definitions|
|Expected literal absent from defined strings|`analysis search-byte-patterns --pattern '53 50 41 52 53 45' --scan-from 0xREGION --max-bytes 1048576`|Initialized-memory byte matches and explicit coverage, not string definitions or code references|

## Follow existing entries first

Start with a small set of independently known entries: exported symbols, retained project
evidence for this exact build or direct targets from bounded decode. Check the function selector;
an interior address is not automatically an entry. Compact inspection avoids unrelated metadata
and supports mixed outcomes, text paging and owner-host saves. For large output, use
`--save-owner-directory <new-absolute-directory>` and retain its hash manifest; see
[research](research.md) for Unicode windows, view guards and native truncation.
Empty `callees` or xrefs on a sparse database do not prove that the decompiled function
has no calls. Keep decompiler observations distinct from stored-reference coverage.

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

For literal search, encode ASCII/UTF-16 as appropriate; the example searches ASCII `SPARSE`.
Quote spaced hex patterns. Read `complete`, `scanned_bytes`, `next_address` and the bounds;
continue with `--scan-from <next_address>`. `--offset` on defined-string results does not
advance memory coverage. A narrowed text filter does not skip earlier non-string defined data.
Use `memory list` to identify initialized/executable blocks; do not assume a guessed block name
or that the image-base address belongs to executable code.

Byte matches are not validated code references. Existing xrefs only describe saved DB metadata.
If this route cannot establish a needed RIP-relative or indirect reference, record that gap;
these commands do not provide a raw-memory whole-program code-reference scanner. A constrained
API for that would be a separate design decision. Arbitrary scripts remain potential writes
with saved-state/recovery costs; a compile/transport error must not be blindly replayed.
