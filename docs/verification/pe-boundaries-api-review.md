# Independent API review: PE runtime boundaries, narrow V1

Date: 2026-10-21. Reviewer: independent read-only agent. Repository: `<repository>`.

## Verdict

**APPROVE after the conservative clarifications recorded below. No unresolved API blocker remains for implementation.** This approves the proposed contract, not an implementation or latency claim. I read the current working tree; it already contained unrelated/uncommitted changes. I changed no repository files and ran no game workers, native fixtures, builds, or tests.

The parent confirmed these choices during review: mapped current headers only, no FileBytes fallback; fail closed on unavailable/incomplete/malformed lookup while retaining DB facts; complete valid no-record permits a positive DB selection; runtime/DB conflicts prevent selection; fixed five-second cooperative lookup deadline; actual-read byte cap default 4 MiB and maximum 16 MiB; no UNWIND_INFO interpretation or chain merging; after-view guard also runs following failed dispatch.

## Scope and evidence read

Read AGENTS.md, docs/DESIGN.md, docs/roles/coordinator-maintainer.md, docs/SPARSE-FUNCTION-ENTRIES.md, owning `skills/ghidra-coordinator/src/function-entries.ts`, `function-inspection.ts`, relevant `research.ts`, `queries.ts`, `contexts.ts`, `research-view.ts`, `query-policy.ts`, native `InsightResearchView.java`, existing tests, and `scripts/proof-function-entries.mjs`.

Existing contract facts: old resolver prioritizes exact DB entry, recorded DB containment, then one indexed preceding entry; fallback alone has executable-block/distance gates. Existing inspection deduplicates selected entries, retains original selector spelling, verifies returned entry, guards one ordered context action, applies text budget in selector order, and writes saves only after normalization. These should remain true for their existing mode. The new mode must not accidentally apply its PE gates to the old mode.

Official supporting references: Microsoft describes image RVAs relative to image base and locates PE signature through DOS e_lfanew; data-directory entries identify data independently of section names ([PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)). Microsoft describes x64 RUNTIME_FUNCTION as three image-relative ULONG fields, sorted and DWORD-aligned, and separately describes chained unwind information ([x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)). Ghidra distinguishes current initialized memory, mapped memory types, execute sets, and stored original FileBytes ([Memory API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html)). These support a range-evidence API, not a semantic function-ownership claim.

## Blockers identified and resolution

1. **Unknown must not become no-record. Resolved.** Unavailable headers, exhausted bytes/deadline, read failure, or rejected table cannot produce a negative runtime membership fact. Retain positive DB observations independently, but do not auto-inspect in this new mode until runtime lookup completes successfully. No directory or an empty valid directory can be a complete zero-record observation.
2. **Header provenance was ambiguous. Resolved by mapped-only V1.** Start at selected Program's actual current image base and read current initialized default-space memory. If required header bytes are absent/uninitialized, report lookup unavailable. Do not search for a PE signature, infer from a `.pdata` name, use preferred OptionalHeader.ImageBase as current address base, read an external executable, or substitute original FileBytes. Sparse DB function bodies do not inherently require missing mapped headers. A disposable normal-import fixture should establish practical usability separately.
3. **Failed dispatch bypassed final view observation. Resolved by required pipeline change.** Current `function-inspection.ts:24/28/29` observes after successful awaits only. New ordered inspection must capture dispatch/parse error, perform final observation before returning/rethrowing or saving, then preserve original error only if final view is valid and unchanged. Changed view wins with binding/changed_view; failed final observation fails closed. No retry/replay. This common guard repair may cover old mode without changing its selection policy.
4. **Original benchmark route was not equivalent. Resolved by new baseline plan, subject to measurement verification.** Existing proof's batch-miss + regex inventory + nearest-preceding selection does not obtain or validate PE evidence. It cannot support a same-evidence PE performance claim. Parent's proposed baseline reads current headers/table through existing memory read CLI, obtains bounded current memory map and equivalent DB facts, validates the full table in JS, then exact-inspects selected entries; that can be equivalent for a declared positive workload.

## Recommended deterministic state machine

Validate CLI before native open: 1–20 hexadecimal default-space selectors as existing; canonicalize only for native work while preserving original output keys. Accept `containing-or-pe-runtime`; accept max-unwind-bytes only with that mode; reject max-entry-distance for it and max-unwind-bytes for old/no mode. Default 4194304, integer 1–16777216. Keep old required max-entry-distance unchanged.

Inside one ordered context action:

1. Open/verify existing context as usual, obtain authoritative before observation and view identity, enforce expect-view.
2. Dispatch one authenticated precompiled ReadOnly native batch. Capture exact-entry and recorded-containment DB facts separately for every requested address. Read and validate supported mapped PE32+ AMD64 headers. Locate exception directory using its directory entry, not section names.
3. Read table in bounded chunks, fully validate once per batch under shared actual-read cap and cooperative deadline. Keep candidate records internal until complete table acceptance. Bind result to modification/program/selector set. No per-query persistent state/cache.
4. Decide per selector with the table's final state. Deduplicate only selected exact entry addresses, invoke existing bulk inspection once, and verify returned entries match selected entries. Preserve boundary and DB facts even if downstream function inspection/decompilation fails.
5. Run after observation even after lookup/get_functions dispatch or protocol-validation failure. Reject changed/missing/failed identity, PID/source or modification observations. Only then normalize final result and permit save behavior.

Lookup states should be explicit and disjoint:

- `complete`: all declared records accepted; `complete:true`. This includes valid absent/empty directory with zero records.
- `unavailable`: unsupported format/architecture or required current memory unavailable; `complete:false`.
- `incomplete`: byte cap/deadline/read interruption prevented full validation; `complete:false`.
- `malformed` (or `rejected` with structured reason): observed bytes violate this V1 table policy; `complete:false`.

Do not use complete:true to mean merely that an attempt ended. `recordsValidated` counts fully accepted records before stopping, not records inspected and rejected; `bytesRead` counts actual native memory bytes copied, including header probes and rereads. A separate reason/counter may describe declared record count, validated prefix and rejected record address. These counters are diagnostics, not partial membership evidence.

Selection matrix after complete table validation:

| DB fact at request | Accepted covering runtime record | Action |
| --- | --- | --- |
| exact/recorded selected entry D | begin equals D | inspect D; retain DB kind and independent runtime boundary |
| exact/recorded selected entry D | begin differs from D | unresolved `boundary_conflict`; preserve D and boundary; no selected entry |
| exact/recorded selected entry D | no covering record | inspect D as DB fact; runtime fact is complete no-record, not semantic contradiction |
| no exact/body DB fact | covering record, getFunctionAt(begin) exists | inspect that exact entry, kind `pe-runtime-range` |
| no exact/body DB fact | covering record, entry undefined | unresolved `runtime_entry_not_defined`, preserve bounds |
| no exact/body DB fact | no covering record | unresolved `no_runtime_record`; semantic membership remains unknown |
| any DB fact | unavailable/incomplete/malformed lookup | unresolved with lookup reason; retain `resolution.database`; no inspection |

Conflict comparison does not depend on getFunctionAt(runtime begin) succeeding: DB selected entry D and an accepted covering begin R already conflict when D != R. No preceding fallback, closest-function fallback, chaining, fragment aggregation, repair, Listing creation, or save from native lookup.

For batch output, unresolved is a per-item structured outcome and must not become generic function_not_found. For a single selector, explicitly map unresolved to the existing partial CLI error envelope while preserving the entire structured row, or explicitly document successful unresolved return. Existing single-selector code checks only failed/not_found today, so new unresolved must be handled intentionally. Missing decompiler text is a separate downstream partial state.

## Response recommendation

Keep public existing entry_point/resolution and view conventions. Add independent DB and boundary lookup facts; neither relies on projected fields. Suggested successful shape:

```json
{
  "status": "success",
  "entry_point": "180001000",
  "resolution": {
    "requestedAddress": "18000108c",
    "kind": "pe-runtime-range",
    "recordedBodyContainsAddress": false,
    "database": {"exactEntry": null, "recordedContainingEntry": null},
    "boundary": {
      "source": "pe-exception-directory",
      "begin": "180001000",
      "endExclusive": "180001120",
      "tableRecordAddress": "180020000",
      "semanticMembership": "not-established",
      "instructionBoundary": "not-checked"
    }
  },
  "boundaryLookup": {"state": "complete", "complete": true, "recordsValidated": 4096, "bytesRead": 49664}
}
```

For `runtime_entry_not_defined`, status unresolved, omit entry_point/selectedEntry but retain the boundary. For unavailable lookup, omit boundary and preserve `resolution.database` plus explicit lookup state/reason/complete:false. For conflict, retain both DB fact and boundary but omit selectedEntry. Original selector spelling is authoritative for requestedAddress/output key; canonical numeric addresses can remain in the facts. Fixed metadata `semanticMembership:not-established` and `instructionBoundary:not-checked` must survive all projection and selected-entry read failures.

A nested `boundaryLookup.state` avoids recursive upstream placeholder policies accidentally rejecting a purposeful `status:unavailable`; inspect currently bypasses generic qualifyQuery, but keep this deliberate if refactored.

## Validation and bounds details that affect API truth

Use unsigned checked arithmetic (including base+RVA, record address, count*12, endExclusive); ensure both RVA and actual address-space limits. Validate DOS/PE signatures, COFF AMD64 machine, OptionalHeader PE32+ magic and declared size, directory-count availability, SizeOfImage, required header spans, directory range/count/alignment and 12-byte record size. Do not trust strings or Ghidra executable format labels alone.

Every accepted runtime record needs begin < endExclusive; ranges inside supported image/address space; monotonic table ordering; no duplicate/overlapping accepted ranges; full interval in current mapped initialized executable default-space memory. Adjacent eligible blocks can cover a range if the full interval is eligible; checking just the begin/end blocks is insufficient. Table itself needs initialized current bytes, not execute permission. Empty/absent-directory representation and inconsistent RVA/size cases need documented rules.

The parent chose a stricter supported subset requiring nonzero aligned in-image initialized UnwindData address, while not parsing UNWIND_INFO contents. Document this as a pointer/range policy, not validated unwind semantics. The flag max-unwind-bytes therefore bounds current metadata reads; it must not imply unwind program interpretation. No chain, handler, semantic ownership or instruction-boundary claim follows from an accepted table record.

An overlap rejection means “this table does not satisfy V1 disjoint-range policy.” It does not diagnose corrupted binary, invalid runtime behavior, overlapping semantic functions or absence of a function. Do not continue binary search using an accepted prefix once a later overlap/order/range defect appears.

Budget is batch-wide, not multiplied by selector count. Cap each read before performing it, account for actual reads, accept short reads only as incomplete/unavailable according to a specified rule, and check monotonic elapsed deadline at bounded validation/read intervals. Five seconds is a cooperative metadata-lookup bound, not a transport or decompiler CPU timeout. In-memory read buffers and temporary candidate bookkeeping within one batch are fine; no cross-call cache is needed.

## Benchmark equivalence and acceptance

**The pre-existing benchmark baseline is not equivalent to this proposed feature.** The newly proposed baseline can be, if the measured code obtains all evidence rather than inheriting fixture oracle facts.

Required measured A/B workload: identical request address set and fields/text budgets, identical before/after observations/DB facts, current PE header discovery, full current exception-table bytes and validation, current eligible memory map, same selection/conflict rules, selected-entry exact bulk inspection, and normalization. The old resolver can supply exact/body facts, but its preceding candidate must never be treated as containment or used instead of runtime evidence. Any inventory/map query must be complete for its declared bounded scope, with truncation rejected. Baseline must reject malformed/short/truncated memory bytes and report unsupported or incomplete evidence separately.

Fixture setup may know image base/ranges for correctness oracle, but timed baseline must discover header-dependent table location/size from current program bytes. Fixture-only assumptions about table addresses, function labels, adjacency, missing overlapping entries, or executable extents would make it unequal. Sharing the same oracle is appropriate for correctness expectations only.

Use the same persistent client transport bytes/settings; same fixtures/views and eligible facts; deterministic warmup; alternating AB/BA paired order; setup, fixture mutations, process startup, trace/receipt writes excluded from clock. Report client wall time and counts separately from nested native spans; do not sum nested spans. Include full validation cost for every measured batch and no warmed lookup cache. Hardware/process scheduling and fixture scope remain stated limitations.

Positive-record-only timing is acceptable if clearly labeled. It does not establish performance for unavailable/overlap/missing-entry/large-table cases. Correctness should be separate and cover: exact/body match, differing exact/body entry, endExclusive boundary, holes, non-executable/uninitialized middle bytes, section renamed away from .pdata, absent headers, rebased image, no directory, leaf without record, undefined begin, budget/deadline stop, malformed ordering/overlap/overflow, rejected late record after a potential early match, alias selectors, projections, selected function errors, failed dispatch, changed final view, failed final observation, and no saved outputs after guards fail. Assertions should establish no changes to generation, snapshot, modification count or script journal after fixture setup.

These are implementation/acceptance gates, not new unresolved design choices. API approval does not authorize game-worker execution or claim native test evidence.
