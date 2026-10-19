# Native performance evidence, 2026-10-18

The initial component experiments below ran on an occupied macOS ARM64 host. They
establish component behavior, not isolated end-to-end native performance acceptance.
All rows, including warmups, are retained; summaries exclude declared warmups only.

| Component, n=30 per variant | Before p50/p95, ms | After p50/p95, ms | Equivalence |
| --- | ---: | ---: | --- |
| Deployed-byte artifact verification | 567.11 / 856.05 | 148.29 / 204.99 | All 62 observed build digests identical |
| Read-only Java view guard | 154.05 / 444.81 | 115.45 / 160.84 | All 66 observed values and modification counters identical |
| Trace sink, 100 no-op requests / 200 spans | 0.089 / 0.174 off | 2.908 / 14.572 on | Exact work count; 6,600 emitted records, no dangling parents |

Artifact hashing alternates old/new algorithms on the same installed public 0.2.4
package, with one warmup and 30 measurements each. View guard and trace cost alternate
three warmups plus 30 measurements each. The trace experiment excludes process startup
and measures sink/API overhead, not complete native overhead. Raw JSON is under
`components/`; no private inputs, endpoint credentials, local program paths or raw
research logs are included.

The main serial matrix freezes source `97e272413fc8974b4ad7be313fc0b248c872eff7`,
package artifact `01d03023112c2b36e7a540c3436a88929bb86f0f0aad6bad60701ec9f63979fc`
and resolved deployed-runtime graph
`716ced78afe22b8b1f983d89aa1be74fa5889f759ac9ab8e097ec911ea912e32`.
The earlier `c308a3c77622451ef330dd86b48495a46c9bb7b8aac0995b7ba49743cc75f49c`
was an unmeasured candidate plan, replaced before its first native request. The
original baseline rows and initial identity remain retained. Package-file identity
and resolved dependency-graph identity are distinct hashes; both are verified.
The installed dependency inventory retains actual versions/integrities, including
baseline/candidate `qs` 6.16.1/6.16.0, Node type-package differences and candidate
test-only tooling. Controlled component comparisons use the same installation;
whole serial version phases are descriptive comparisons under host load.
The owner requested wrap-up on 2026-10-19 before the entire serial matrix finished.
The [native report](native/report.md), [run status](native/run-status.json) and
[raw requests](native/requests.jsonl) preserve the resulting **incomplete diagnostic
run**, with the original 30-warm / 5-cold requirements unchanged. Reduced smoke
results do not substitute for missing groups.

Completed native evidence includes all baseline and candidate CLI/RPC reads
(20 fresh native trials and 2,640 measured warm reads each), 20 separate cold RPC
trials per version, and the stock Java 7/Python 6 parity matrix (1,200 warm reads).
All 44 useful-result variants, including prepared first queries, agree. The
independent memory oracle, 40 program-only script observations and 88 paired
CLI/RPC case groups pass. There are 12,851 recorded requests, with no recorded
failed or censored request. The next dispatched peer-open completed before the
scheduler stopped; it has no synthetic timing row, as the stop ledger explains.

Baseline persistence completed 120 measured cycles and concurrency completed
30 measured rounds. Candidate persistence completed 30 tiny/no-analysis cycles
and three tiny/analysis cycles; the next cycle only opened contexts. Candidate
remaining persistence/concurrency, stock Java 6, native tracing and the final
frozen-candidate traced/untraced functional proofs were not completed. Strict
coverage is **575 of 732 groups**. Native trace attribution is unavailable from
this run, rather than inferred from the component experiment.

The predeclared read budget fails three p95 checks: tiny/analysis RPC strings
229.18 to 389.22 ms, tiny/analysis RPC bounded undefined decode 238.06 to 330.16 ms,
and tiny/no-analysis CLI missing-function lookup 1,857.74 to 2,488.37 ms. These
samples remain included; budgets were not relaxed. For a descriptive improvement,
tiny/analysis metadata p50 is 487.38 to 312.09 ms over CLI and 22.85 to 14.01 ms
over RPC. Whole version phases are serial, so these are not causal speed ratios.

One-minute host load ranged 4.39–58.56 on 10 logical CPUs (p50 9.83, p95 29.03).
The owner explicitly authorized the occupied-host limitation. Full completeness
and performance acceptance are **not passed**. All four owned candidate profiles
have zero active contexts, unresolved operations and matching native processes;
their servers are stopped. Unrelated processes and the shared public IPC owner
were not stopped. Both installed runtime graph hashes were reverified unchanged.

An archival PID-reuse error happened after the complete baseline contention
measurement and cleanup. The original nonzero phase exit and unchanged raw-row
hash remain recorded in the [recovery addendum](native/resume-addendum.json).
The collector now reads process identity even when an old PID is inaccessible;
it still refuses live or unverifiable owned backing stores. This housekeeping
change is outside timed requests. Per-phase collector file hashes are retained.

The shipped changes are the identical-byte hash algorithm, authenticated schema
reuse with fresh cancellation/binding checks, removal of an unused metadata call,
and the small read-only view guard. Remaining helper startup, independently saved
effect inspection and publication readback are hypotheses for a future traced
run. Any reusable inspection worker must retain artifact hashes, read-only DB
access, authority checks, exact saved-effect verification and unknown-outcome
recovery. Scheduling/progress issues #68/#69 remain separate.

The frozen product source passed 230 facade tests (four platform skips), 45
release/script tests and the isolated offline package proof. Final performance
summary/storage tests pass 16/16; the final complete release/script suite passes
47/47. Factory source `13b01dc` passed its macOS,
Linux and Windows checks plus release dry-run. No merge or registry release was
performed.
