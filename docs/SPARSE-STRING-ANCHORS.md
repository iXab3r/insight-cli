# Raw string anchors V1

The owner approved implementation conditional on independent API review. The reviewer
approved the narrow V1 with nonblocking notes; see [review](verification/string-anchors-api-review.md).
It searches initialized raw bytes when a sparse database has no defined string records.

```sh
insight-cli ghidra strings anchors --session S --target T \
  --text Widget --encodings ascii,utf16le \
  --scan-from 180030000 --scan-through 18003ffff \
  --max-string-bytes 1024 --max-bytes 1048576 --limit 20 --json
```

V1 accepts one case-sensitive literal of 1–256 UTF-16 units without NUL or unpaired
surrogates. Select `ascii`, `utf16le`, or both explicitly. ASCII rejects unrepresentable
text. There is no regex, case folding, normalization, or encoding detection. Encodings
are normalized to ASCII then UTF-16LE. Every byte can start a match, including odd-address
UTF-16LE and overlapping occurrences. A one-character ASCII needle can match the low byte
of UTF-16LE data. Each `(address, encoding)` remains a separate raw result.

Both inclusive range bounds are required: unsigned default-space addresses, at most 64
bits and representable in the selected program. Only initialized byte-addressed default-space
memory participates. Adjacent initialized blocks merge; holes and uninitialized blocks split
coverage. Every byte of the encoded needle must fit one clipped merged span. Context and
terminators also remain inside the original range and that span. A scan of an empty eligible
domain succeeds with no matches and zero read bytes. Completion describes eligible search
coverage, independently of candidate completeness or decoding.

Rows preserve the exact interior `matchAddress`, `matchByteLength`, and a nullable
`matchOffsetBytes` measured from a separately established candidate start. `literalCandidate`
contains nullable `start` and `terminatorAddress`, `byteLength` only when both NUL boundaries
were found, and a separate bounded preview: `textFrom`, `text`, `textBytes` (hex), and
`textByteLength`. No preview address is presented as a known candidate start. NUL-delimited
context is a byte observation, not a semantic string definition or canonical reference target.

Each side independently probes up to `cap - encodedNeedleBytes` payload bytes for a NUL;
the next code unit at that limit may still be the terminator and is checked. UTF-16LE steps
two bytes relative to the hit's phase. A complete candidate whose payload fits the cap is
therefore recoverable regardless of where the needle occurs. The cap is even, 16–8192 bytes,
defaults to 1024, and must fit every selected encoded needle. It bounds both the whole
candidate payload returned as complete and the total preview payload. Terminators are excluded.

Partial or oversized candidates allocate half the spare preview to the left, rounded down
to encoding units, and the remainder to the right. Unused room transfers first to the left,
then to the right. This deterministic preview always includes the raw match. Boundaries are
`nul`, `range_edge`, `memory_edge`, or `string_limit`. Strict ASCII/UTF-16LE decode failure
retains the raw match and returns `text: null`, `decoding: invalid`. `boundariesComplete`
and `complete` are separate; only two NUL boundaries, a payload within the cap and valid
decoding establish complete candidate text. Reasons are `complete`, `string_limit`,
`missing_boundary`, and `invalid_encoding`.

Page limits are independent:

| Flag | Default | Range |
| --- | ---: | ---: |
| `--max-bytes` | 4194304 | 32768–16777216 actual read bytes |
| `--max-candidates` | 10000 | 1–100000 raw matched pairs |
| `--timeout-seconds` | 5 | 1–30 cooperative seconds |
| `--limit` | 100 | 1–1000 returned raw pairs |

Every physical memory read counts, including prefetch, context, lookahead and rereads.
Absolute-aligned 4096-byte pages are clipped to spans and held in a bounded eight-page LRU
for this call only. A fresh maximum-cap candidate fits the minimum byte budget. Earlier
scan reads may force stopping before a hit; its continuation starts fresh at that hit.
Deadline expiry may legitimately yield no progress. The cooperative scan deadline and
`scan.elapsedMs` begin after native block enumeration/sort/merge; full endpoint wall time
includes that preparation and serialization. No unbounded no-match scan is hidden.
The complete serialized facade response, including cursor, is capped at one MiB, with a
conservative row reserve that always permits one valid maximum-size row.

`scan.from` and nullable `scan.next` are `(address, encoding)` frontiers. `scan.next` is the
first unchecked pair: a hit without a returned row has not been consumed. Rows are ordered
by numeric address then canonical encoding order. `scan.through` retains the requested end;
holes are skipped. Page-local `bytesRead`, `testedPairs`, `candidates`, and `elapsedMs` report
actual work. A matched pair counts toward candidates even when its context is invalid or
an atomic row cannot be finalized on this page. Reasons are `exhausted`, `byte_limit`,
`candidate_limit`, `timeout`, and `result_limit`. Exhaustion wins when no unchecked pair remains.

```sh
insight-cli ghidra strings anchors --session S --target T --cursor sa1.TOKEN \
  --max-bytes 4194304 --limit 100 --json
```

The stateless unsigned cursor binds normalized literal/encodings/range/cap, scope, algorithm
`raw-string-anchors-v1`, native view, snapshot/context generation, and process incarnation.
All token fields are untrusted and revalidated. A token is not proof of previous coverage;
editing it can choose a later valid frontier. Continuations forbid selectors but allow page
budget overrides; omitted budgets inherit. A changed view is rejected before scanning.

The authenticated ReadOnly `GET /insight/string-anchors/v1` service operates on an explicitly
already-open program. Ordered before/after source/PID/view observations and native modification
checks guard each call, including failed dispatch. A lost or malformed response is rejected,
never replayed. No runtime compilation, analysis, definitions, save, joins, persistent query
cache or Factory changes are involved. Existing defined strings, byte patterns and code-reference
commands keep their contracts. Use anchors → explicit batched code references → function
inspection; preserve exact match targets rather than silently replacing them with candidate starts.

Verification uses generated disposable sparse PE contexts. The matched baseline is two old
byte-pattern searches and bounded per-hit memory reads with independent context reconstruction;
the new route is one anchor call. Both use the identical retained persistent-client transport.
The timed domain is the same last single initialized 64-KiB block; adjacent-block and hole
semantics are correctness cases tested separately because the old scanner processes blocks
individually and has no inclusive end selector. Setup and warmup are excluded, order alternates,
and all raw pairs/context fields must match. The result measures the combined workflow and
native transport/precompilation change, not fusion alone or cold-start/agent reasoning costs.

The installed proof on 2026-10-21 passed all 16 correctness/read-only checks and 11 separate
guard controls, including actual native edits and restart. All 24 measured alternating pairs
returned the same six ordered raw hits and every candidate-context field.

| Per workload, warm persistent clients | Previous route | Anchor V1 |
| --- | ---: | ---: |
| CLI requests | 8 | 1 |
| Native HTTP requests | 72 | 19 |
| Search pages | 2 | 1 |
| Actual read bytes | 143324 | 65536 |
| Median client workflow | 538.22 ms | 52.65 ms |
| p95 client workflow | 1037.56 ms | 65.21 ms |

Median workflow time fell by 90.22% (10.22×). The new endpoint's native HTTP span had a
median of 2.54 ms, while the core scan took 0.78 ms. Most remaining request time is native
identity/schema/view checking and facade/transport work. These spans are nested in client
wall time and are not additional time to sum onto it. This is one synthetic corpus and
warm clients, with combined workflow/transport changes. See the
[verification receipt](verification/sparse-string-anchors.json) for paired timings, operation
breakdown, exact artifact/source hashes, review, limits and cleanup evidence. No Factory code
or policy changed.

```sh
# Opt-in native proof; each output directory must be new. Inputs and contexts are disposable.
node scripts/proof-string-anchors.mjs --before OLD_INSTALLED_PACKAGE \
  --after NEW_INSTALLED_PACKAGE --root NEW_OUTPUT --java JAVA --ghidra-home GHIDRA \
  --rounds 24 --ack-disposable
node scripts/proof-string-anchor-guards.mjs --package NEW_INSTALLED_PACKAGE \
  --root NEW_GUARD_OUTPUT --java JAVA --ghidra-home GHIDRA --ack-disposable
```
