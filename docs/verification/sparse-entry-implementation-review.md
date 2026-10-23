# Sparse-entry V1 implementation review

Date: 2026-10-20

**Final source-review verdict: APPROVE. No open implementation blockers.**

The initial review requested one correction, B1. Independent source recheck confirms that correction and the corresponding native fixture assertions. Native execution, frozen-package identity and performance results are outside this static verdict and remain separately verifiable acceptance evidence.

This is a read-only static review against the independently approved opt-in V1. No repository files were edited, tests/native/game processes started, or additional agents used. Performance and native execution proof remain the root agent's separate work. The review concerns source correctness rather than a frozen installed artifact.

## Corrected blocking finding

### B1: Memory eligibility was checked before exact and recorded lookup — CLOSED

Initially observed in `skills/ghidra-coordinator/references/native/InsightResearchView.java`: `memory.getBlock(at)` and the initialized/executable gate ran before `getFunctionAt(at)` and `getFunctionContaining(at)`.

The approved order is exact entry → recorded containment → bounded preceding fallback. The initialized executable same-block requirement restricts fallback. In the initial implementation an existing exact entry or recorded body in a non-executable/uninitialized block instead returned `address_not_in_initialized_executable_block`. This was an observable contract discrepancy, including when only `entry_point` was requested and decompilation was irrelevant. The initial reference prose also imposed this broader precondition.

The requested correction was to perform exact/recorded function queries first, apply the memory eligibility check only when neither resolves, and add disposable native fixture assertions for exact entry and recorded containment in non-executable/uninitialized blocks using metadata-only field projection, retaining fallback misses in those blocks. TypeScript backend mocks cannot exercise this ordering defect.

Root was informed immediately and acknowledged the defect. Independent source recheck now confirms `getFunctionAt` and `getFunctionContaining` at native source lines 51–54, followed by the memory eligibility gate at lines 55–56. Thus exact and recorded branches bypass both fallback block eligibility and fallback distance limits. Research guidance and `docs/SPARSE-FUNCTION-ENTRIES.md` now state this explicitly.

`scripts/proof-function-entries.mjs` now creates recorded functions in both initialized non-executable memory and uninitialized memory. Its metadata-only inspection requests exact and interior addresses in both blocks with maximum fallback distance 1, then asserts exact/recorded resolution kinds. Separate assertions retain policy misses in those ineligible blocks when no recorded function resolves. These fixtures directly exercise the originally incorrect branch ordering; their native execution result remains the root's separate proof. B1 is closed for source correctness.

## Other reviewed invariants: no additional blockers found

- **Original selector mapping:** `functionSelectors` retains input spelling after existing whitespace trimming. `entryRequest` canonicalizes hexadecimal addresses only for native lookup and deduplicates those facts. `function-inspection.ts:34–42` resolves each original selector through its canonical key, emits the original selector as the output key and overwrites `resolution.requestedAddress` with that original spelling. Backend entry addresses are checked against the located entry before a row can be accepted or saved. Failure rows preserve selected-entry provenance.
- **Native work deduplication:** `function-inspection.ts:26–28` builds unique entry selectors, performs one bulk entry read, and skips that read entirely when every lookup missed. It does not deduplicate the original response rows. The mode forces native `entry_point` projection when fields are filtered, preserving identity verification and public selected-entry provenance even without the caller asking for it.
- **Text and saved output:** `function-inspection.ts:43–50` applies the existing per-row Unicode window and decrements the shared remaining budget for every original row, including aliases. Hashes still bind full observed native text; owner-save output stays per-selector with manifest-last behavior and existing limits. The aggregate response cap runs before writes. A guard or entry mismatch fails before a completed manifest can be written.
- **Failure distinctions:** policy misses are per-item `not_found`, with reasons describing bounded policy failure. Native inspection errors remain classified through `functionResult`, with resolution and original selector retained. Missing requested decompiler text stays `partial`. The ordinary single-selector failure behavior is preserved.
- **View guards:** `Research.inspectFunctions` retains one ordered context action and before observation. The new mode refuses unavailable guarded observations; the native lookup's modification string must match the observed counter. Final observation occurs after lookup and bulk reads, including all-miss batches, before normalization/save. `--expect-view` is checked before lookup dispatch; malformed/mismatched facts fail rather than triggering an unguarded fallback.
- **Indexed native lookup:** in the reviewed endpoint, exact lookup and recorded containment are followed by `functions.getFunctions(at, false)`, one `hasNext()` and at most one `next()`. There is no iterator from the first function, symbol/name inventory, byte scan, or whole-table materialization in the new endpoint. The fallback checks address space, strict preceding order, same block and maximum distance. The bound is inclusive; there is no address wrapping in the BigInteger distance check. This source review does not establish implementation complexity of Ghidra's internals or a native decompiler deadline.
- **Membership honesty:** native `recordedBodyContainsAddress` reads `function.getBody().contains(at)`. The TypeScript validator rejects candidate rows claiming containment, forward/zero-distance candidates, inconsistent distance, inconsistent exact-entry identity and unexpected resolution kinds. Recorded containment omits distance and can legitimately address a noncontiguous body before its entry. `status: success` remains an observation of the selected function; the `preceding-entry-candidate` kind and false recorded membership remain explicit.
- **Narrow scope:** options are facade-owned and opt-in, require an explicit valid distance, reject names/prefixed addresses and ambiguous dual selectors before native opening, and leave ordinary inspection on its previous backend route. The helper is annotated ReadOnly, uses explicit program routing and native read threading, and contains no transaction, analysis, disassembly or save call. Backend routing discovers the annotated endpoint descriptor; there is no inline compilation fallback for this mode.

## Targeted tests inspected, not executed

`tests/function-entry-inspection.test.ts` directly covers policy/input rejection, hexadecimal alias dedupe, native facts consistency, backwards recorded bodies, aliases sharing one native read while charging both output windows, field-projection provenance, misses without empty reads, native failure provenance, changed/lost observations, identity mismatch before save and saved alias mappings/continuation. `tests/research-cli.test.ts` covers ReadOnly CLI/RPC equivalence and malformed policy rejection before backend opening. Existing function-inspection/text-window/research-view tests continue to cover their shared primitives.

The important initial gap was native branch ordering, since mocked facts already assume the native selection policy is correct. The added native fixture assertions now target that gap. Runtime proof should establish their passing results and the new endpoint's actual schema/packaging; no tests or processes were executed during this review.

## Nonblocking notes and future conveniences

No additional API convenience is required for V1 acceptance. Multiple neighboring candidates, saved-file deduplication and richer count/coverage metadata can remain future work. The new mode avoids copying deduplicated backend `count`/`requested` fields into original-selector results, avoiding misleading batch counts. The current approved result shape does not require replacement counts.

No speedup or call-count ratio is inferred here. The root's matched-workload measurements must establish equivalent selected entries/content and report frontend calls separately from native reads and decompiler work.
