# Sparse function-entry inspection

The owner authorized implementation conditional on independent API review. The reviewer
approved this opt-in V1 with nonblocking implementation notes on 2026-10-20. It addresses
interior-address inspection in databases with known entries but sparse saved function bodies.
It does not discover or repair unknown functions.

```sh
insight-cli ghidra functions inspect --session S --target T \
  --functions 18000108c,180010080 \
  --resolve-address containing-or-preceding --max-entry-distance 4096 \
  --fields entry_point,decompiled_code --include-call-context false --json
```

The mode accepts 1–20 hexadecimal default-space address literals through the existing
`--function`/`--functions` selectors. Names and address-space prefixes fail before native
opening; a stray distance option also fails. Fallback distance must be explicitly specified,
1–65536 bytes. Ordinary inspection without the opt-in remains unchanged.

For each valid default-space query address, choose an exact known entry first, then a
recorded containing function. Only when those fail, consider the nearest preceding known
entry, in the same initialized executable memory block and within the distance limit. Adjacent
blocks do not merge for this policy. Block eligibility and distance apply only to fallback:
exact entries and recorded containment also work in non-executable or uninitialized blocks.
Genuine recorded containment can be
farther away or in a discontiguous body before its own entry.

Every resolved row retains `entry_point` and `resolution`, independently of projected fields.
Original selector spelling remains the result key. Examples of resolution kinds:

```json
{"requestedAddress":"18000108c","kind":"preceding-entry-candidate","distanceBytes":140,"recordedBodyContainsAddress":false}
```

`exact-entry` has distance zero and recorded containment true. `recorded-containing` has
recorded containment true and omits distance. `preceding-entry-candidate` has a positive
bounded distance and recorded containment false. Even recorded containment is database
metadata, not independent proof of semantic membership. A successful decompile of a candidate
does not prove that it contains the original address. Padding, split code and incorrect prior
entries remain possible.

Policy misses are per-item `not_found`: `address_out_of_range`,
`address_not_in_initialized_executable_block`, `no_preceding_entry`, `entry_outside_block` or
`entry_distance_exceeded`. These do not establish absence of executable code or an unknown
function. Selected-entry inspection failures preserve their existing reasons plus resolution.
The ordinary single-selector command still fails on a missing/failed row; `--functions` keeps
mixed batch outcomes.

The authenticated precompiled `GET /insight/function-entries/v1` helper reads an explicitly
already-open program. Exact/body queries and an address-seeded reverse iterator consume at
most one preceding entry per input. No function/name-table scan, runtime script compilation,
analysis, Listing edit or save is performed. The existing source/PID verification and ordered
before/after view guard cover lookup and inspection. Selector/protocol/entry mismatch fails;
there is no unguarded or inline-script fallback.

Selected entries are deduplicated for backend inspection. Per-selector Unicode windows and
the shared total text budget still apply in original input order, including aliases. Owner
saves keep per-selector mapping, hashes and manifest-last semantics. Continuations retain the
existing `--expect-view` and text-hash checks. These result/lookup bounds do not introduce a
CPU deadline for the upstream decompiler.

Verification and matched timing results are recorded in
[the verification receipt](verification/sparse-function-entries.json). The opt-in proof runner
uses a generated PE with separately created sparse code blocks and known entries, not game
inputs. It compares the same address workload through the frozen previous and new installed
builds, using identical persistent-client bytes and alternating order. The baseline route is
batch miss → one same-prefix inventory search → exact-entry batch; the fused route is one
request. Setup, warmups, trace-file reads and external tool-approval latency are excluded.
Native/handler spans are nested and must not be added to the client wall time.

The installed before/after proof on 2026-10-20 matched selected entries, decompiled text,
hashes, lengths and truncation flags in all 24 alternating measured pairs:

| Per four-address workload | Previous route | Opt-in route |
| --- | ---: | ---: |
| CLI requests | 3 | 1 |
| Native HTTP requests | 47 | 24 |
| Bulk function reads | 2 (one misses) | 1 |
| Median elapsed time | 844.56 ms | 767.88 ms |
| p95 elapsed time | 1006.10 ms | 841.96 ms |

Median wall time fell by 9.08%; total measured time fell by 11.75%. The new indexed lookup
itself took a p50 of 1.81 ms (nearest rank). The selected-entry bulk read, including requested decompilation,
still took roughly 0.7 seconds; its HTTP span does not isolate native decompiler CPU time.
This is one prepared synthetic input and warm persistent clients, not a rerun of the PoE
research benchmark or a measurement of agent reasoning time. The native workload was ReadOnly:
context generation, saved snapshot and script-request journal were unchanged after setup.
The receipt retains paired timings and separate native-operation totals.

```sh
node scripts/proof-function-entries.mjs --ack-disposable \
  --before <previous-installed-package> --after <new-installed-package> \
  --root <new-fixture-directory> --java <jdk>/bin/java \
  --ghidra-home <ghidra> --rounds 24
```

Separate guard controls use a generated 32-bit PE and the official Factory testing/fetch
seam over a real isolated bridge. They exercise concurrent edits, lost/malformed lookup
replies, wrong selected entry, final PID/source/view failures, authentication, already-open
program routing, restart continuation and default-space address limits. Rejected reads must
not replay or create saved output; the saved context remains readable.

```sh
node scripts/proof-function-entry-guards.mjs --ack-disposable \
  --package <new-installed-package> --root <new-fixture-directory> \
  --java <jdk>/bin/java --ghidra-home <ghidra>
```
