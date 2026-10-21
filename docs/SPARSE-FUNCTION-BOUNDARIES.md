# Sparse PE runtime-region inspection V1

The independently reviewed opt-in mode resolves up to20 default-space hexadecimal addresses
using recorded Ghidra function facts and current mapped PE32+/AMD64 Exception Directory records.
It reads no external executable or historical FileBytes and changes no Listing, function,
analysis state, snapshot, native save, or Factory component.

```sh
insight-cli ghidra functions inspect --session S --target T \
  --functions 180100008,180100028 \
  --resolve-address containing-or-pe-runtime --max-unwind-bytes 4194304 \
  --fields entry_point,decompiled_code --include-call-context false --json
```

`--max-unwind-bytes` is a batch-wide budget of1–16777216 returned header/table bytes, default4194304.
Every read is checked against remaining budget before dispatch. Header reads, table chunks and
rereads count. The complete table is read once per batch in chunks of at most4092 bytes; no cache,
cursor, symbol-name search or runtime script compilation is introduced. The separate fixed5-second
lookup deadline is cooperative, including memory-span preparation and table validation. It does
not interrupt a Ghidra library call or bound later upstream decompiler CPU time. `bytesRead` counts
bytes returned by the memory API; if that API throws without reporting a count, this is a lower
bound on bytes touched before the exceptional read. The parser stops immediately, so the attempted
read still fits the remaining cap and no subsequent read or accepted candidate follows it.

Only x86:LE:64:default, byte-addressed64-bit default space and current mapped initialized PE headers
at the Program's actual image base are supported. Missing/uninitialized headers return unavailable;
there is no signature search or file fallback. The runtime directory comes from PE headers, not a
section name. Current SizeOfImage, unsigned RVA arithmetic, optional-header size/directory count,
12-byte record shape, sorted disjoint half-open ranges and current initialized executable coverage
are validated for the *whole* declared table. Adjacent eligible blocks are allowed; holes and
ineligible middle blocks are not. The unwind-info RVA must be aligned, in-image and initialized;
unwind contents, chained records and fragmented regions are not interpreted or merged.

A matching runtime record describes a runtime region. It does not prove an instruction boundary,
semantic membership, execution, or a complete source-level function. Leaf routines may have no
runtime record. Overlapping/unsorted records are outside this V1's accepted table policy; their
rejection is not a claim that real executable code cannot have unusual layouts.

## Selection and coverage

DB exact-entry/recorded-body facts and validated runtime evidence are retained separately.

| Full lookup result | DB/runtime relationship | Inspection |
| --- | --- | --- |
| validated covering runtime record | DB entry differs from runtime begin | `boundary_conflict`, no selection, retain both facts |
| validated covering runtime record | DB agrees or no DB containment; function defined at runtime begin | select that entry once; `kind: pe-runtime-range` |
| validated covering runtime record | no function at runtime begin | `runtime_entry_not_defined`, retain bounds, no creation |
| validated table without covering record, or absent directory | positive exact/recorded DB fact | inspect that known function, retain DB provenance |
| validated table without covering record, or absent directory | no recorded function | `no_runtime_range_or_recorded_function`; leaf membership unknown |
| unavailable, malformed, incomplete | any DB fact | no automatic inspection; retain DB fact, no runtime bounds |

`boundaryLookup.complete` is true only for `state: validated` (every record validated) or
`state: absent` (validated headers establish no Exception Directory). `reason` distinguishes
`byte_limit`, `timeout`, unavailable mapping/format, and malformed table/header observations.
`recordCount` reports the declared count once known; `recordsValidated` counts completed record
checks, including a prefix that was subsequently rejected. No prefix candidate is returned after
any failure. Absence of one runtime record never establishes absence of an executable leaf.

A projected successful row still retains selected entry and resolution. Example, partial envelope:

```json
{
  "functions": {
    "180100008": {
      "status": "success",
      "entry_point": "180100000",
      "resolution": {
        "requestedAddress": "180100008",
        "kind": "pe-runtime-range",
        "recordedBodyContainsAddress": false,
        "database": null,
        "boundary": {
          "source": "pe-exception-directory",
          "begin": "180100000",
          "endExclusive": "180100020",
          "tableRecordAddress": "180200000",
          "semanticMembership": "not-established",
          "instructionBoundary": "not-checked",
          "unwindInfo": "not-parsed"
        }
      }
    }
  },
  "boundaryLookup": {
    "state": "validated",
    "complete": true,
    "reason": "validated",
    "headersSource": "current-mapped-memory",
    "recordCount": 1024,
    "recordsValidated": 1024,
    "bytesRead": 12496,
    "maximumBytes": 4194304,
    "deadlineMilliseconds": 5000
  }
}
```

An unresolved batch row has `status: partial`, a typed `reason`, and
`resolution: {kind: unresolved, database: <fact-or-null>, boundary: <validated-region-or-null>, ...}`.
An unresolved single `--function` returns the existing nonzero partial CLI error with the same
resolution, boundaryLookup and view retained in its result. It does not silently fall back to a
preceding function. The original default and `containing-or-preceding` selection policies remain.

The authenticated precompiled ReadOnly `/insight/function-boundaries/v1` endpoint selects only an
explicit already-open program. Ordered before/after source/process/view guards cover lookup and
inspection, including failed dispatch. Changed view or failed guard prevents owner-save and no
native operation is replayed. Selected entries are deduplicated for bulk inspection; original
selectors retain individual Unicode text budgets, paging/hash/continuation and owner-save rules.

## Verification and comparison

- Independent API and implementation reviews: [API review](verification/pe-boundaries-api-review.md),
  [source review](verification/pe-boundaries-implementation-review.md). Findings were fixed before native proof.
- `scripts/native/TestPeRanges.java`: generated memory corpus for malformed tables, adjacent ranges,
  exact exclusive ends, holes, initialized executable eligibility, rebasing, short optional header,
  limits/deadline and physical byte accounting.
- `function-boundaries.test.ts`: malformed protocol/coverage, evidence separation, alias/projection,
  single/batch behavior and failed-dispatch guards before save.
- `scripts/proof-function-boundaries.mjs`: installed disposable sparse PE, renamed table block,
  singleton bodies, missing runtime entry, DB conflict even when runtime begin is undefined, leaf
  no-record, incomplete/malformed/absent/unmapped controls and identical persistent AB/BA workload.
- `scripts/proof-function-boundary-guards.mjs`: real isolated bridge with auth, explicit already-open
  source, changed/lost/changed-and-lost lookup replies, wrong entry, PID/source/view failure and restart.

The matched workload's baseline obtains current header/directory/table bytes, current complete
bounded memory map, DB facts via the existing containing-or-preceding resolver (metadata only; discard its candidates)
and exact text inspection using old commands *inside* the clock; it fully
validates the same1024 records independently in JS. The new mode returns the same regions, DB
absence and decompile text/hash/length/truncation in one request. Setup/oracle values only assert
correctness.24 serial alternating AB/BA trials exclude setup/warmup/trace reads/receipt persistence and include
client calls plus test-side validation. Results describe this synthetic warm persistent
workflow on a shared host, not cold startup, inference time or a new game benchmark.

## Recorded result

The final [verification receipt](verification/sparse-function-boundaries.json) records24 measured
serial AB/BA pairs, identical canonical evidence/text and12496 header/table bytes per workload.

| Metric per workload | Previous indexed resolver + checks | PE runtime mode |
| --- | ---: | ---: |
| CLI requests | 8 | 1 |
| Native HTTP calls, including verification | 97 | 24 |
| End-to-end workload p50 | 992.04 ms | 761.35 ms |
| End-to-end workload p95 | 1051.18 ms | 775.11 ms |

Median latency fell23.3%; p95 fell26.3%. The independent [result audit](verification/pe-boundaries-results-review.md)
recomputed all48 measured rows and checked five raw receipts. These are matched synthetic workflow results under the
limits above. Native sparse controls and12 guard controls passed, and both fixture cleanups were
empty. The bridge rebuilt twice to the same SHA-256; installed package smoke passed. The default
offline suite passed284 tests, skipped4, and had2 sandbox process-identity failures; the unchanged
7-test supervisor suite passed outside the sandbox with ps access. Release checks33/33 passed.
