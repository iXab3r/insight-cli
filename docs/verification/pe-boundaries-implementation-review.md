# Independent implementation sanity review: PE function boundaries V1

Date: 2026-10-21. Repository: `<repository>`.

## Verdict

**APPROVE for continued native fixture/benchmark verification. No unresolved implementation blocker found in the final source inspected.** Two concrete boundary correctness issues found during this review were fixed by the parent, and I reread those fixes. This is a source review, not certification of compiled artifact identity, installed native behavior, latency, or the parent's reported test results.

I made no repository edits, started no worker, ran no native fixture/build/test, and saved only this report under `<private verification directory>`. The parent reported native helper compilation, core assertions and focused TS tests; those results were not independently rerun here. The working tree was changing during review, so hashes below identify the last inspected source snapshot.

## Reviewed source snapshot

All paths below are repository-relative.

| Source | SHA-256 |
| --- | --- |
| `skills/ghidra-coordinator/references/native/InsightPeRanges.java` | `2e82a7b2e908f29f6e68f6491549981cc709012186096a60ce10d5b15f29712b` |
| `skills/ghidra-coordinator/references/native/InsightFunctionBoundaries.java` | `61eab3948186597ad22396eb029d61d2ddeb89a77d3969ea41ead55a38deb651` |
| `skills/ghidra-coordinator/src/function-boundaries.ts` | `ce6531202dba2940bd00c0a243a2b582512ef96ab26d0d64e3f1b6ac5a541326` |
| `skills/ghidra-coordinator/src/function-entries.ts` | `508b21a350f17cefbe091cc4629b87fa064474042464e6ffeb595434d26ceab4` |
| `skills/ghidra-coordinator/src/function-inspection.ts` | `b7bb8f1307c382bc6673cd5a78ae12f99f20adba287728fd46b3b071ea5cff6d` |
| `skills/ghidra-coordinator/src/queries.ts` | `3d97b52f9eb4d24a834f5bf06dc0b61184f9924e87cdb0c29c279825c64309e6` |

Also read the new native/TS tests, bridge build/registration patch, relevant `Research.inspectFunctions` ordered context/observations, and the previously reviewed design. No Factory implementation changes were involved in the paths inspected.

## Findings fixed during review

### 1. Valid short optional header without Exception Directory was rejected

Initial `InsightPeRanges` required optionalSize >=144 and read144 before testing NumberOfRvaAndSizes. A valid PE32+ optional header of112 bytes with zero directories must permit complete absent-directory evidence; the old implementation classified it malformed and blocked positive DB inspection.

**Verified fix:** the parser now requires/reads the112-byte PE32+ fixed portion, validates declared directory count against declared optional header size, tests count<4, and reads only directory entry3 when available. The parent added a pure-core test for112-byte/no-directory. This also closes acceptance of declared directory counts that exceed optional header capacity. Current actual header reads for present DD3 are64+24+112+8=208 bytes.

### 2. Native and TS disagreed about endExclusive ==2^64

Native checked arithmetic and mapped spans permit a half-open end equal to2^64, while the initial TS address validator admitted at most16 hex digits. A valid native result containing the final address-space byte would be rejected as malformed.

**Verified fix:** only boundary.endExclusive additionally accepts canonical `10000000000000000`; all selected entries, begins, request addresses and record addresses remain unsigned64 addresses. Containment still requires begin<=query<endExclusive.

### Additional protocol consistency fixes observed

The parent also rejected an impossible unresolved runtime_entry_not_defined row that simultaneously supplies a matching DB entry, and rejected validated state with zero records. Both are consistent with the native selection algorithm.

## Correctness and state-machine assessment

- **Current source and context:** endpoint requires an explicit already-open program path, rejects ambiguity, uses inherited annotated ReadOnly/authenticated bridge registration and threading, and accepts only canonical distinct1–20 native selectors. Program image base, default-space memory and language are selected from that Program. No external executable or FileBytes source is consulted.
- **Supported subset:** PE32+ AMD64 in x86:LE:64:default,64-bit byte-addressable default space; mapped current headers only. Unsupported language/machine/header format returns unavailable. Missing current header/table/range/unwind mapping remains unavailable, not absent.
- **Address arithmetic:** PE fields are unsigned16/32 decoded into nonnegative Java values. PE offsets and32-bit RVA sums remain far below signed-long overflow; base+RVA/end arithmetic uses BigInteger and checks <=2^64. Table bounds are checked against SizeOfImage before scanning. No signed-long wrap was found in these paths.
- **Half-open ranges:** native accepts query>=begin && query<end; TS independently enforces the same predicate. Adjacent runtime records are allowed. begin<end, in-image ends, ordering and disjointness are validated for every record. Header/table chunk calculations remain multiples of12.
- **Full-table proof:** a possible covering record is only retained privately while the parser continues over the entire declared table. Any Stop clears all candidate ranges. Complete is true only for validated or absent; TS rejects boundary facts on every incomplete/unavailable/malformed response before get_functions. No early-match negative or accepted-prefix leakage was found.
- **Current eligible memory:** mapped() walks spans across the entire interval, permits adjacent initialized executable blocks, rejects holes or any ineligible middle span, and separately requires initialized table/unwind addresses. Eligibility is metadata evidence; code bytes are not decoded and unwind contents are not parsed.
- **Selection:** conflict compares accepted runtime begin with the DB exact/body selected entry before checking whether a function exists at runtime begin. Matching runtime begin must have getFunctionAt before selection. Missing begin yields unresolved runtime_entry_not_defined with bounds. Complete no-record can still select a positive DB exact/body fact. Unknown/unavailable/malformed/incomplete always retains DB fact and prevents automatic inspection. There is no preceding fallback in this mode.
- **Semantics:** runtime boundaries retain source, begin/endExclusive, table record address, semanticMembership:not-established, instructionBoundary:not-checked and unwindInfo:not-parsed. DB fact is independent. Overlap is rejected as a table-policy observation, not a semantic function diagnosis. No chain/fragment aggregation occurs.
- **API compatibility:** new CLI options validate before backend open, reject wrong-mode budgets, default to4MiB, cap at16MiB. Existing containing-or-preceding selection implementation remains the previous logic. In the new mode, row kind uses pe-runtime-range whenever accepted runtime evidence participates, while the independent database object retains the DB kind; this differs from my optional recommendation to keep the top-level DB kind but preserves the evidence and is not a correctness issue.
- **Downstream inspection/projection:** selected native entries are deduplicated, entry_point is requested for verification, projected output still carries provenance, selected-entry mismatch fails, aliases consume text budget in original order, and native read failures retain resolution. Batch unresolved is partial; single-selector unresolved is deliberately mapped to the existing partial CLI error with lookup/view metadata.

## Limits and security assessment

Actual byte budget is batch-wide, checked before each memory read, and charges bytes returned by the memory reader. Header reads and table reads share it. Chunks are at most4092 bytes. The parser's per-record work is bounded by table size,20 request addresses and current memory spans; retained candidates are at most20 because accepted ranges are disjoint. No persistent cache is used.

Five-second elapsed time starts before native span preparation in the latest source and is passed into the parser. The parser checks at read, record and span-walk boundaries and after validation. A preparation phase that overruns therefore cannot yield accepted table evidence. This remains cooperative: Ghidra getBlocks(), memory.getBytes(), sorting, indexed DB calls and upstream decompiler execution are not interrupted inside library calls. It should not be described as a hard endpoint/decompiler CPU timeout.

`function-inspection.ts:24–36` now captures lookup/dispatch/protocol errors and performs the final observation before rethrow. Successful dispatch also observes before normalization/save. Changed final view wins over the dispatch error; final-observation failure fails closed. Existing context ordering, before view identity, expected-view check, incarnation and backend source/process verification remain in effect. No retry or replay was added. Save creation follows the guards, selector checks, normalization and response-size check.

The additive bridge build registers the new helper through existing AnnotationScanner mechanisms; native compilation occurs at package build time. No runtime script compilation, analysis, Listing mutation, function creation, transaction or native save was found. Owner-requested existing text-save behavior is separate from the ReadOnly helper and remains after final guards.

## Nonblocking hardening / verification notes

1. **Counter-schema hardening:** TS currently verifies budget/counter monotonic consistency and validated count>0, but allows physically impossible successful counters such as absent with bytesRead0 or validated with bytesRead12*N. Native cannot produce these: absent needs at least200 bytes; validated needs208+12*N under the current staged reader. Adding these minima makes malformed-response fault injection stricter. This is a defensive consistency improvement, not a source-identified false native selection.
2. **Read-exception accounting:** a thrown memory reader provides no returned byte count. The parser reports bytesRead for successful/reported reads only, clears candidates and stops, so it cannot overrun the next read budget or claim no-record. Avoid describing that counter as a guaranteed number of physical backend bytes touched before an exceptional partial read unless Ghidra's implementation establishes it.
3. **Regression proof still required:** native guards/source selection/authentication, actual mapped header import behavior, final PID/source/view failures, sparse Listing behavior, renamed .pdata, no-directory positive DB inspection, conflict with undefined runtime begin, U64 exclusive end, late-table rejection, holes/ineligible middle spans, budget/deadline termination and no mutation need their dedicated disposable proofs. Pure-core/TS assertions do not replace installed native evidence.
4. **Benchmark scope:** no benchmark implementation/result was reviewed in this pass. The prior regex inventory baseline is not equivalent. The promised timed current header/table reads, complete current eligible memory map, equivalent DB facts/full JS validation and exact bulk inspection must be checked against the actual benchmark script; setup oracle facts cannot supply timed evidence.

The remaining notes do not block continued implementation verification. Publication/acceptance should use source/build identities and the planned disposable native results, not this static review alone.

## Addendum: benchmark source audit only

I separately reviewed `scripts/proof-function-boundaries.mjs` after the parent requested an evidence-equivalence audit. Last inspected SHA-256: `16c494759d0a2e43776ab7bb9d0407bb239daf5e98e7eee11cca3e1e20e9373d`. **I did not run or read the output of the benchmark; this addendum makes no latency/result claim.**

**Source verdict: the final baseline obtains equivalent runtime/DB/text evidence for its explicitly declared positive four-selector, three-entry fixture workload. No remaining source blocker to that comparison was found.** It is not a universal implementation of the new failure/resource-budget API, and its performance conclusions must retain that scope.

Inside the measured baseline, the source obtains a current bounded memory map with explicit total/count/offset/no-truncation assertions; reads DOS64, COFF24, optional fixed112 and DD3 eight bytes; derives table RVA/size from those current reads; reads the full declared table; and validates every record's shape, ordering/disjointness, image bounds, full initialized executable range and initialized unwind address. B is an explicit common known-program-base precondition. T/U/N fixture constants do not supply table location, table extent or record contents to timed baseline logic. Address/record formatting uses B plus the parsed RVA. The fixed low B plus an explicit image-end <=2^64 assertion makes the positive workload's unsigned arithmetic safe.

The original-selector DB check now uses the **existing indexed containing-or-preceding resolver with fields entry_point**, requiring every row to be a preceding-entry candidate with recordedBodyContainsAddress:false. Given that resolver's exact/body priority, those returned facts establish absence of exact/body DB membership for this fixture; the preceding candidates are ignored. Full validated runtime evidence chooses entries, and only then the baseline performs deduplicated exact text inspection. This removes the earlier plain get_functions name-fallback route caveat. The new path returns the same boundary/DB-null/selected entry/decompile/hash/length/truncation evidence and uses the same request selectors and output budgets.

The script verifies persistent-client transport bytes are identical, warms both clients, alternates AB/BA serially, excludes setup and trace-file reads, compares returned evidence, and checks retained view/context/request state around measured work. A single complete memory-map page and mapped headers are stated fixture constraints, not evidence of support for every imported PE or large map.

Two timing confounds found in the first source draft were fixed and reread: an extra baseline-only baseline-map.json write was removed, and per-call receipt files for warmup/measured phases are queued and flushed only after elapsedMs is captured. Timing still includes actual CLI work, JS parsing/validation/assertions and small in-memory receipt stringify/hash work; it does not isolate native fusion alone. Reported native spans remain separate from client wall time.

Optional gate hardening: bytesRead and recordCount are retained per workload but, in this inspected snapshot, deepEqual(result) compares boundary/DB/text evidence rather than explicitly comparing those two counters per A/B pair. Add explicit equality if the receipt claims an assertion of identical physical byte counts or complete-record counts. Source inspection establishes the same208+parsedTableSize reads and full declared record loops for the positive case; it does not independently verify runtime measurements or counters.

No claim is made here that baseline handles absent-directory, malformed, overlap, unsupported, deadline or byte-limit outcomes identically. The benchmark deliberately requires a present valid table; those behaviors belong to separate correctness/guard controls. A valid latency receipt must identify the final script/build hashes and final run, because the parent explicitly classified the earlier instrumented run as preliminary stand validation.

## Parent follow-up after review

The final validator enforces the successful-read counter minima identified above. The matched harness also asserts equal per-workload physical header/table bytes and validated record counts using independently parsed baseline facts. Native result evidence is recorded separately; this does not change the independent reviewer’s stated scope.
