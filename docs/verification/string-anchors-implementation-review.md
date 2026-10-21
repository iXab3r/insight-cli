# Independent string-anchor implementation review

Verdict: **APPROVE_WITH_NONBLOCKING_NOTES**. No remaining blockers were found. The native guard proof and the completed native correctness/matched A/B proof pass with clean cleanup. The earlier correctness/A/B pending status is closed for this recorded disposable fixture and installed build pair, subject to the explicitly recorded benchmark limits.

Scope: read-only source audit of the new raw scan core, native endpoint, facade request/result/cursor validation, ordered research integration, bridge patcher and bridge build registration, followed by inspection of available native guard evidence. Existing unrelated changes were preserved. The reviewer did not execute native tools, create fixtures, build, or run tests. Runtime evidence below was produced by the implementation owner and inspected independently.

## Resolved finding

### Resolved P2: Native modification-guard rejection bypassed `changed_view` classification

Locations: `skills/ghidra-coordinator/references/native/InsightStringAnchors.java:41` and `skills/ghidra-coordinator/src/string-anchors.ts:88–89`.

The endpoint correctly rejects a scan if the native modification number changed. However, it does so by throwing `IllegalStateException`. The HTTP bridge maps native rejection/error responses to a generic `remote` error. In `inspectAnchors`, the independent after-observation runs only after `await backend.call(...)` succeeds. Consequently the native guard's own failure skips that observation and never produces the promised `binding` error with `reason: changed_view`.

Concrete sequence:

1. The facade observes modification `7`.
2. A native edit occurs while the scan is running; final modification is `8`.
3. The native guard throws instead of returning rows.
4. `backend.call` rejects with a generic remote failure.
5. The facade exits before its after-observation, so the caller receives no `changed_view` reason.

The original implementation failed closed and did not expose mixed-view rows, but violated the explicit view-change contract and prevented callers from distinguishing the required restart from an unrelated remote failure.

Correction reviewed: `inspectAnchors` now catches rejection of the native call, performs an independent after-observation, returns `binding`/`changed_view` if its digest differs, and otherwise rethrows the original error. It does not parse exception text or replay the scan. This closes the finding. Two offline controls were added for changed versus unchanged after-observations; this audit read them but did not run them.

If `observe()` itself rejects in this catch path, its error propagates and no rows or cursor are returned. That is acceptably fail-closed: an unavailable after-observation cannot establish an unchanged view or justify inventing `changed_view`. Preserving the original call error as an error cause would improve diagnostics, but is not a source-acceptance blocker. The final source includes an offline control for a rejecting after-observer, making this behavior explicit.

## Other audit conclusions

- I found no raw-pair loss or duplication in the scan loop. The scanner page is retained separately from the context reader's current page; `(address, encoding)` remains the frontier until the pair's miss is established or its completed row is appended. Byte/deadline/output interruption during candidate work leaves the unreturned pair resumable. Limits checked at the next actual pair do not turn final-domain exhaustion into a false continuation.
- Numeric address order and canonical encoding order are maintained. Overlapping hits advance by one byte. A cursor between ASCII and UTF-16LE at one address resumes the second encoding rather than skipping it.
- The page reader clips every read to an initialized merged span and the original inclusive query range. Needle fit is checked before cross-page reads. NUL probes follow code-unit phase relative to the match, so odd-address UTF-16LE remains supported without arbitrary `00 00` alignment mistakes.
- Independent two-sided probes can recover an asymmetric full candidate within the total cap. The balanced preview and spare transfer preserve the needle and stay within that cap. Nullable full boundaries are separate from preview addresses. Strict ASCII/UTF-16LE decoding retains raw hits when context decoding fails. The current `string_limit`/`missing_boundary` reason expression agrees with the stated clarification.
- Every successful physical page read increments `bytesRead`; cache hits do not. A fresh maximum-cap candidate spans at most roughly 16 KiB of relevant addresses plus absolute-page edge overhead, comfortably inside the 32768-byte minimum with the bounded page cache. Reads already spent scanning may stop before a candidate; a fresh continuation can process that candidate. This source argument still needs the planned executable progress/accounting cases.
- Native program selection requires an explicit already-open path, rejects ambiguous matches, limits scanning to initialized byte-addressed default-space memory, and performs a modification guard around span selection and reads. Bridge registration retains the upstream annotated authentication and threading path. The facade adds no runtime compilation, definitions, analysis, or save on this route.
- Result validation independently checks algorithm/encoding/modification facts, counters and frontier ordering, exact encoded needle containment, preview range/cap/phase, absence of NUL code units inside the preview, candidate boundary arithmetic, strict decoding, and complete-candidate consistency. Unsigned cursor fields are revalidated and bound to scope, normalized selectors, algorithm and observed view; the token remains untrusted continuation input rather than proof of earlier work.
- The native row-cost estimate is conservative relative to hexadecimal bytes plus worst-case JSON string escaping. Its 900000-byte threshold leaves substantial space for scan facts, cursor and final envelope. The facade's independent envelope checks remain useful.

## Nonblocking follow-up notes

1. The core's `elapsedMs` and cooperative deadline begin after native memory-block enumeration/sorting/merging. Document that timing scope precisely and keep full endpoint/facade wall time separate in benchmark reporting.
2. Preserve tests for output-cap stopping before an unreturned row, resumes at both encoding slots, reads around maximum-cap candidates at page-edge placements, holes, range edges, invalid surrogate context, and the largest escaped JSON rows. Current source fixtures cover several of these, but their presence is not evidence they passed.
3. Native correctness/matched A/B evidence is now complete for the recorded disposable fixture and installed build pair. It does not establish cold-start performance, wider application performance, other operating systems, or fusion-only causation.

## Proof-runner review before native execution

The runner's timed workload is appropriately matched: its 65536-byte workload is the last contiguous initialized block, where the old byte-pattern command's start plus byte limit expresses the same domain; adjacent-block/hole/range cases are checked separately. Both paths use the same persistent-client bytes, exact ordered raw pairs and full reconstructed contexts are compared, runs alternate AB/BA, warmups are separate, and the report explicitly limits attribution to the combined workflow/transport/precompilation change. The wall-clock boundary includes receipt persistence and baseline reconstruction/assertion costs and declares those costs. This is an end-to-end retained-client workflow measurement, not an isolated scanner microbenchmark.

Two previously identified proof details are now resolved in source:

1. **Malformed UTF-16 fixture corrected.** The original helper encoded a Java string containing a lone surrogate, which would replace it during charset encoding. The final source instead writes raw hex `0000780000d85700690064006700650074000000` at the declared address. This retains the intended unpaired `d800` code unit and exact UTF-16LE needle with surrounding NUL boundaries. No charset encoder can silently repair the test input.

2. **Native read-only evidence strengthened.** Both fixture paths now call the public `functions inspect --fields entry_point` surface with the same fixed selector before and after the read-only phase and compare `view.identity`. That identity binds native modification/language/compiler/process incarnation and the immutable selected context inputs. These calls are outside workload timing. The original context/request checkpoint remains as a separate facade-state check. The selector need not resolve to a function for its guarded native view fingerprint to serve this purpose.

The proof runner was reviewed as source and was not executed by this reviewer.

## Final serialization and available native evidence

- The endpoint now owns a private static Gson configured with `serializeNulls()` and `disableHtmlEscaping()` and returns `Response.text(JSON.toJson(value))`. This is confined to the additive endpoint; it does not modify upstream serialization, upstream classes, or Factory. It preserves explicit nullable candidate facts and `scan.next: null`, while Gson still performs JSON string escaping. The existing HTTP bridge parses the response body as JSON independently of its text content type. The annotated authentication/read-only/threading path is retained. No new source blocker follows from this correction.
- the private guard-proof `report.json` was inspected: `passed: true`, all 11 named checks true, and `cleanup: []`. The separate `cleanup.json` also contains an empty cleanup-error list. Checks cover edit/rejection handling, lost/malformed replies, invalid frontier, PID/program/view failures, context availability, authentication/explicit already-open program, and restarted-incarnation cursor rejection. The report correctly states that several transport/failure conditions use an injected Factory/fetch seam over a real isolated bridge; it does not pretend they are all naturally occurring native failures.
- The completed the private matched-proof `result.json` was inspected: `state: passed`, all 16 named correctness/equivalence/native-view/facade-state checks true, 24 measured workloads per path, and exactly alternating AB/BA order across 24 rounds. Its `cleanup.json` contains an empty cleanup-error list. This closes the previous correctness/A/B pending status.
- The owner reports the expanded offline Java core harness passed 378 assertions, including randomized raw-byte oracle comparison, fresh minimum-budget resume, and output-limit atomic continuation. This reviewer read the relevant source and relies on the owner's execution report for that count rather than claiming a separate run.

## Completed matched A/B evidence

The 48 measured workload records have one identical full-result content digest. All after-path measured raw response `matches` arrays independently reproduce that same digest. The 202 before-path and 46 after-path retained command receipts have no command errors, and all 248 recorded receipt hashes independently match their raw files. Each path's initial and final public native-view fingerprints were independently compared from the raw receipts and match. These checks support the runner's assertions and report rather than relying on summary numbers alone.

Per measured workload:

| Metric | Before | After |
| --- | ---: | ---: |
| Facade calls | 8 | 1 |
| Workflow median | 538.224 ms | 52.647 ms |
| Workflow p95 | 1037.564 ms | 65.210 ms |
| Native HTTP requests | 72 | 19 |
| Accounted memory bytes | 143324 | 65536 |

The evidence is sufficient for the stated conclusion: this retained-client workflow returns equivalent exact raw pairs and full candidate fields with fewer calls/reads and lower measured warm workflow latency on the generated sparse PE. The implementation preserves the declared boundary/encoding/range/continuation behavior on the named native correctness controls, and the observed native views and facade state remain unchanged across the read-only phases.

The reported clock includes raw receipt persistence and test-side reconstruction/assertions, excludes setup, warmup and trace-file reads, and uses warm persistent clients on a shared host. The workload contains six exact address/encoding pairs in the same final contiguous 65536-byte initialized block; adjacent/hole/edge cases are separate correctness tests. The old helper's compile/transport costs and the new precompiled endpoint are part of the measured workflow difference. Consequently these measurements support a combined workflow/transport/precompilation improvement; they do not isolate fusion, prove a cold-start gain, measure agent reasoning time, or generalize to all binaries. The report states these limits adequately.

Machine-local proof paths are omitted from this tracked copy. Portable checks, artifact hashes and paired measurements are retained in [the public verification receipt](sparse-string-anchors.json); original receipts and the unedited review are archived privately outside Git.
