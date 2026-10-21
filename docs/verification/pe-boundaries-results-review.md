# Independent saved-results sanity audit: PE boundaries V1

Date: 2026-10-21.

**Verdict: retained results are internally consistent and support the scoped reported benchmark improvement. No result/interpretation blocker found.** I performed read-only inspection and independent arithmetic/hash checks over saved artifacts. I did not start native programs/processes, rerun the benchmark or guards, or independently revalidate every raw output.

## Artifacts and identity

Read `<private verification directory>/insight-pe-boundaries-final-20261021/result.json`, `cleanup.json`, captured `harness.mjs`, both request indexes, five selected raw receipts, and `<private verification directory>/insight-pe-guards-final2-20261021/report.json` and `cleanup.json`.

The captured harness and current `scripts/proof-function-boundaries.mjs` independently hash to the same SHA-256:
`15b003e5b1ae9916ae1d3bb575d73385c17e861139409fc600a1a35b8f2122f8`.

Release preparation subsequently removed whitespace on one blank harness line. The hash above
binds the captured and audited measurement source; the whitespace-only cleanup does not rerun or
change those historical measurements.

The result manifest identifies baseline artifact `28243ecbcec0822f248978a2dc966bf87ffdda89773a60f55c2decdab1345778` and candidate artifact `7a92211cc577784d2272f818305716046be12e9275174a819af647871bb7aea6`. I did not recompute whole-package build artifact digests. At their retained installed paths I independently hashed:

| File | Baseline | Candidate |
| --- | --- | --- |
| persistent-client.js | `e6f0628dbe513fb568f3e7ad306bf5fe31757d403459dfb77363fb376c72d8e8` | identical |
| GhidraMCP-7.0.0.jar | `b21bb40165b89db6232160c50062e78977a2e511674d03c6caf6904c5a5c3eb9` | `f4a9272e911466ed774c8cf73bc1adf1daef6009d895fda57aa0b28522fcdf32` |

Both saved proof reports identify generated input SHA-256 `b2a55cf216b32e53a245b4ba18fe4d9cccff63cfbddd05dea708ce58fad62683`.

## Independent metadata/arithmetic checks

I checked all48 measured row records and both warmup records, not merely the summary:

- Exactly24 rounds contain one before and one after workload each, in before/after order for even rounds and after/before for odd rounds. All measured rows have phase measured.
- Every measured workload records1024 validated records and12496 header/table bytes:208+1024*12. Each side totals299904 bytes across24 workloads. Per-pair record counts, byte counts and content digests are equal.
- All measured and warmup content digests equal `2a9075aa1fa945a211dff8f16379c89381198c95aba45fbb4d03ca68843d4cee`.
- Recomputed request/native-HTTP/byte totals match summary. Request indexes contain192 measured baseline calls and24 candidate calls, with no recorded measured-call error.
- Every nativeHttp row count equals operations.length; sums of operation durationMs match retained nativeHttpMs. These are separate nested observations, not time to add to client wall time.
- I independently sorted client elapsed values and reproduced nearest-rank p50/p95 (ceil(n*q), with n24), elapsed sums and all summary workload counts. All24 paired candidate times are below their corresponding baseline times; paired savings range188.11–391.36ms.

| Per four-address workload | Baseline | Candidate |
| --- | ---: | ---: |
| CLI calls |8|1|
| Native HTTP calls |97|24|
| Current header/table bytes |12496|12496|
| Runtime records validated |1024|1024|
| p50 client elapsed |992.040833ms|761.349000ms|
| p95 client elapsed |1051.175375ms|775.110167ms|
| Sum over24 workloads |23898.210458ms|18244.240667ms|

Recomputed reductions: p50 **23.25%**, p95 **26.26%**, total measured elapsed **23.66%**. CLI calls fell192→24; native HTTP calls fell2328→576.

Operation inventory is consistent with the source: baseline has24 memory maps,120 memory reads (five per workload),24 old indexed entry lookups and48 get_functions calls (metadata plus exact text). Candidate has24 boundary lookups and24 get_functions calls. Repeated source/program/auth/view checks explain the remaining HTTP traffic. There is no basis here for attributing the entire gain to table-lookup CPU or fusion alone.

## Raw receipt spot checks

I checked five raw receipt files against their request-index SHA-256 values and parsed their actual successful responses:

- Round0 baseline exact text receipt before/27.json and candidate after/28.json.
- Round23 baseline exact text receipt before/235.json and candidate after/227.json.
- Round0 baseline old indexed metadata receipt before/26.json.

For both sampled A/B pairs, all four original selectors map to the same three entries; complete runtime evidence reports1024 records/12496 bytes. Selected decompiled text, text SHA-256, totalCharacters and sourceTruncated match the baseline exact-entry responses. I independently hashed the returned decompiled strings and reconstructed each candidate result's canonical evidence digest, matching the result-row digest above. The old-resolver receipt has four preceding-entry-candidate rows with recordedBodyContainsAddress:false and no decompiled_code, consistent with metadata-only DB fact lookup and discarding candidates.

Representative candidate evidence retains begin180100000, endExclusive180100020, table record180200000, database:null, semanticMembership:not-established, instructionBoundary:not-checked and unwindInfo:not-parsed. Returned text for that entry is51 characters and returns1. This spot check does not claim independent inspection of the other raw receipts or every full table byte.

## Correctness and cleanup receipts

The benchmark result state is passed and all nine saved checks are true, covering half-open adjacency/missing entry/conflict, leaf no-record without preceding membership, incomplete not absence, malformed candidate suppression with retained DB facts, valid absent-directory DB selection, equivalent evidence/text, both unchanged-state checks, and missing-header behavior without historical fallback.

The separate guard report has passed:true and all twelve checks true: explicit DB/runtime agreement, edit/lost/edit+lost/malformed lookup, wrong selected entry, PID/program/final-view faults, unchanged saved context, auth/explicit open-program routing, and stale view rejection after restart. I checked report shape and values, not every underlying injected response. Its stated limits correctly distinguish Factory testing/fetch-seam injected PID/source/reply facts from actual owned comment edit/restart, and metadata-only guard inspection from the separate decompile workload.

Both standalone cleanup.json files contain exactly `{"cleanup":[]}`; the guard report's embedded cleanup is also empty. This establishes no retained cleanup error was reported by those harnesses. It is not an independent live process/resource inventory, and I did not start or inspect native processes.

## Interpretation and remaining limits

The captured final source includes explicit per-workload recordCount==N and bytesRead==208+12*recordCount assertions outside the measured elapsed capture; this closes the optional counter-equivalence gate noted in the prior source audit. Receipt files flush after elapsed capture, and the extra baseline-only map write is absent.

The supported claim is a warm persistent-client improvement for one generated mapped-header AMD64 PE, four selectors/three selected sparse entries, full1024-record evidence workload, one complete bounded memory-map page, and this shared host. Setup, warmup, trace reads and raw-receipt disk persistence are excluded. JS parsing/validation/assertions and small in-memory receipt work remain inside the measured client workload. The result does not measure cold startup, agent reasoning, general game binaries, semantic function membership, decompiler CPU in isolation, or identical failure/deadline behavior of the two routes. p95 is an observed nearest-rank statistic over24 samples, not a population guarantee.

Within those limits, the saved outputs support the reported figures and are suitable evidence for the narrow V1 receipt. This audit does not replace implementation review or native acceptance and does not claim the proofs were rerun independently.
