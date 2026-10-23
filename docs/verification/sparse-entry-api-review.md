# Independent API efficiency review: sparse-entry inspection V1

Date: 2026-10-20

**Verdict: APPROVE_WITH_NONBLOCKING_NOTES. No blocking design changes requested.**

This approves implementation of the proposed opt-in V1, not an unimplemented backend or a measured speedup. The proposed API is sufficiently narrow and can remove the adaptive `inspect → search → inspect` round trip without pretending that sparse database metadata establishes function boundaries. Neighboring candidates, reconstruction and broader navigation APIs are not prerequisites.

## Scope and evidence

Read repository `AGENTS.md`, `docs/DESIGN.md`, coordinator/skill maintainer guidance, recovery reference, current research/query/sparse-navigation contracts and the owning TypeScript/native-view implementation and focused tests. No repository code changed, tests or native processes started, game run, game RE findings read, or additional agents used. This file is the review artifact.

Relevant current contracts and implementation:

- `skills/ghidra-coordinator/references/research.md:107–147`: failure classification, read-only semantics, 1–20 selectors, per-item Unicode windows, shared selector-order text budget, text hashes, view continuation and owner-host saves.
- `skills/ghidra-coordinator/src/function-inspection.ts:13–52`: current selector validation, native result-key validation, per-item normalization, budget allocation, response cap and manifest-last writes.
- `skills/ghidra-coordinator/src/research.ts:258–265`: existing ordered scope and context/native observation-based identity.
- `skills/ghidra-coordinator/src/function-results.ts`: native errors, required name, optional requested entry metadata and stable failure reasons.
- `skills/ghidra-coordinator/references/query-semantics.md:70–75`: result limits do not establish bounded upstream work.
- `skills/ghidra-coordinator/references/sparse-navigation.md:19–38`: interior addresses are not automatically entries; decompilation does not prove valid boundaries or complete flow.
- `skills/ghidra-coordinator/references/native/InsightResearchView.java:7–21`: authenticated precompiled read of an explicitly selected open program, using native read threading.

## Assessment

**Efficiency and scope.** Combining deterministic address resolution with the existing batched inspector is useful because it eliminates caller-driven discovery between commands. Keeping it inside `functions inspect` reuses the established output, paging, save and view semantics. Requiring an explicit mode and explicit maximum fallback distance avoids changing ordinary name/address inspection. Twenty inputs and deduplicated selected entries limit the additional dispatch work. This is an improvement in frontend interaction count; native decompilation remains an independently costly operation.

**Boundary honesty.** `exact-entry`, recorded containment and `preceding-entry-candidate` are different facts. The proposed explicit fallback kind, original-address result key and `recordedBodyContainsAddress: false` preserve that distinction. `status: success` can continue to mean that the selected function was read successfully; it must not mean that the input address belongs to it. Containment is recorded DB membership, not independently validated semantic membership. No additional confidence score would improve that contract.

**Preceding is enough for V1.** The nearest earlier known entry is a deterministic navigation candidate, not necessarily the true enclosing entry. Padding, split/tail bodies, intervening stubs and incorrect entries remain possible. Returning the next entry or several alternatives might aid later investigations, but increases selection/output complexity and is unnecessary for the stated reduction of adaptive frontend calls. Absence of a candidate only means this bounded policy found none.

**Batch outcomes.** Preserving one row per original selector is appropriate. Resolution failure must remain local to that row; native/view/protocol integrity failures can still fail the operation. A selected function whose decompile fails needs its resolution retained alongside the current stable inspection failure. `partial` for missing requested decompiler text remains distinct from a successful full observation. Nothing in the existing contract requires all batch items to succeed or an atomic group of backend reads.

## Nonblocking implementation notes

These refine the already proposed invariants; they do not request a larger API or another approval gate.

1. **Dedupe native work, retain selector-order output accounting.** Two different addresses resolving to the same entry must cause one backend entry read/decompilation, then independent result rows. Allocate `--total-chars` across those original rows in input order, charging every inline character actually returned; copying a window to aliases without charging it would violate the existing shared budget. Hashes refer to the same full returned native source. Owner saves can retain the existing numbered per-selector files; file deduplication is optional. Each manifest row must preserve its original-address → selected-entry mapping.

2. **Resolution metadata survives field projection and failures.** Return the selected entry and resolution kind even when `--fields` omits `entry_point`. Otherwise compact calls cannot identify whose decompilation they received. Preserve exact original selector spelling in keys and use canonical addresses internally for dedupe. Expose actual body containment for all resolved kinds. Define `distanceBytes` as the nonnegative earlier-entry offset for fallback; do not assume the entry precedes every address in a recorded noncontiguous body. Omit that field for recorded containment if necessary rather than inventing a positive distance.

3. **Bound lookup by indexed access, not just output distance.** Implementation should perform exact lookup, recorded containment and an address-seeded reverse entry lookup in the selected address space, stopping after the nearest relevant entry. An iterator beginning at the first function, a symbol/name search, or materializing all functions is not acceptable merely because the returned candidate is within 65536 bytes. Check that query and candidate entry occupy the same initialized executable block, without wrapping address arithmetic. Reject crossing that block even when another entry is numerically close. Keep lookup bounds distinct from the existing unguaranteed native decompiler CPU work. This review has not verified an endpoint that does not exist yet.

4. **Keep one guard around the whole operation.** Observe before lookup and after all selected-entry reads, inside the existing ordered action. An observation failure must fail; never fall back to an unguarded new mode. `--expect-view` rejection should happen before dispatch. Validate native entry keys and returned entry identity against the resolver result rather than trusting that a backend selected the requested entry. Save only after successful final observation, preserving current manifest-last behavior.

5. **Describe policy misses precisely.** Stable per-item reasons should distinguish an ineligible address/block from no preceding known entry and distance rejection where practical. A generic policy miss must not claim that executable code or a function does not exist. State that the distance bound applies only to fallback; exact and recorded containment take precedence. Reject names, missing/out-of-range distance, and stray distance without the opt-in mode before native calls. Preserve the ordinary single-selector result/error behavior if the mode is allowed with `--function`; explicitly documenting use through `--functions` is also sufficient.

6. **Update public guidance with implementation.** Generated help, research and sparse-navigation references should show the opt-in route and its candidate warning. Current “interior address is not automatically an entry” remains true. The existing 1 MiB response cap, Unicode windows, native truncation, save limits and `changed_view` contract must continue to apply. A count/requested field copied from the deduplicated backend must be recomputed or clearly distinguished from original selector counts.

## Meaningful acceptance and measurements

Use disposable/offline fixtures to establish exact entry, real recorded containment, one-byte sparse bodies, two selectors aliasing one entry, gaps, block boundaries, maximum distance inclusive/exclusive, address-space separation, mixed misses/native failures, no requested entry field, shared-budget starvation, Unicode continuation, native truncation, saved mapping and view changes between lookup and inspection. Explicitly test that a candidate can be successfully decompiled while its queried address is outside the recorded body. Test that no analysis/disassembly/save operation is invoked by resolution. A lookup fixture or static native review should reject any start-of-table enumeration; larger function-table measurements alone cannot prove the algorithm is indexed.

For efficiency, replay **the same ordered query addresses, same database/view, same text fields/windows, same call-context setting and same frontend mode** through the old inspect/search/inspect workflow and the fused command. Record outer calls separately from internal bridge calls, resolution reads, unique entry reads and decompiler invocations. Compare selected entries and hashes/content of observed decompilation, report per-item outcomes and disagreement counts, then latency (warm repeated paired runs; median/tail, sample count and cold startup separately). Include all-exact/containing controls, sparse hits, bounded misses and aliases. Native lookup latency and decompiler time should be reported separately where observable.

The supplied 97 CLI versus 51 MCP outer calls came from different workloads, so it does not establish a mandatory call count or a performance ratio. The V1 can validly demonstrate fewer calls for the matched adaptive workload even if decompilation dominates elapsed time. Conversely, fewer outer calls without equivalent selected-entry/content and honest candidate labels would not demonstrate success.
