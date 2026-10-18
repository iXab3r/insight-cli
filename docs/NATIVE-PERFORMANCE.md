# Reproducible native performance

This protocol addresses #66/#67. It uses public installed entry points, disposable
owned native programs and ordinary authority/recovery/publication behavior. It is
separate from agent business-task acceptance. No game binaries or research answers
are required. Registry publication and merging remain separate decisions.

## Acquisition and one-command execution

Use Node 24+, Java 21, Ghidra 12.1.2, clang with Windows x64 cross-compilation and
`lld-link`. Install the exact baseline into a separate prefix; build/pack/install the
candidate into another prefix. Keep both installations immutable during measurement.
The runner currently observes macOS public AppData; it fails on another platform.

Acquire dependencies before going offline:

```sh
npm ci --ignore-scripts
npm install --prefix "$BASELINE_PREFIX" --ignore-scripts @eyeauras/insight-cli@0.2.4
npm run test:package
```

`test:package` reports its isolated installed candidate. The source tree version may
be unreleased; identify it by source commit, package archive hash and generated
`.cli-package-build.json`, not a fabricated registry version. Resolve the stock
bridge's canonical Git root and commit independently. Use the standard Python stdio
bridge and SDK MCP client, with a separate owned Java server for each cold trial.

```sh
npm run performance:native -- \
  --root "$NEW_EVIDENCE_DIRECTORY" \
  --baseline "$BASELINE_BIN" --candidate "$CANDIDATE_BIN" \
  --java "$JAVA21_BIN" --ghidra "$GHIDRA_HOME" \
  --python "$STOCK_BRIDGE_PYTHON" --bridge "$STOCK_BRIDGE_CHECKOUT" \
  --parity-jar "$PACKAGED_7_JAR" --stock-jar "$STOCK_6_JAR" \
  --ack-disposable
```

The directory must be new. `--smoke` explicitly reduces warm/cold/warmup counts to
3/1/1; it cannot establish full native acceptance. The default is 30/5/3. Execution
is serial and can take hours, especially the repeated publication/context lifecycle.
The initial public IPC owner must have exited naturally; the runner never issues a
global owner stop. Each insight profile, private context, stock JVM/project and token
is unique to this run. Stock selection asserts the exact owned endpoint and PID.
Only those contexts/servers are closed. Failures abort and retain partial evidence;
do not replace failing samples with successful retries.

Large raw Ghidra working databases and revision history can otherwise consume over
100 GiB across the matrix. After a fixture profile has completed **all** its later
uses, `storage.mjs` compresses large `.gbf` backing files. It requires closed private
contexts, no running/unknown journal or publication, verified retained GZF snapshots,
a stopped owned server and no matching live native process. Compression occurs
outside request timing. Each compressed stream is read back and SHA-256 checked;
an fsynced index records its source/hash before the uncompressed completed copy is
removed. Journals, receipts, immutable artifacts and prepared snapshots remain in
place. Failed/uncertain profiles are preserved without this housekeeping. Stock's
completed local project receives the same compression after its JVM has exited.

Archives and indices under `closed-fixtures` are private evidence and are never
included in public artifact uploads. Restore backing files before reusing an archived
benchmark profile; restoration refuses overwrite and verifies bytes again:

```sh
node --input-type=module -e 'import {restorePayloads} from "./scripts/performance/storage.mjs"; await restorePayloads(process.argv[1]);' "$PRIVATE_INDEX_JSON"
```

`.github/workflows/native-performance.yml` supplies the repeatable manual job. It
requires an explicitly labeled dedicated macOS ARM64 self-hosted runner and repository
variables `PERF_JAVA`, `PERF_GHIDRA`, `PERF_PYTHON`, `PERF_BRIDGE`, `PERF_STOCK_JAR`.
The workflow opts in with `INSIGHT_NATIVE_PERFORMANCE=owned`, serializes runs and
uploads only allowlisted sanitized evidence. It is not automatically dispatched by
an ordinary PR. The normal PR workflow runs the lightweight artifact-verification
smoke and publishes its raw component samples. A configured native job is not
evidence that it has actually run; report local/native execution separately.

## Frozen protocol and budgets

The initial release baseline is public `@eyeauras/insight-cli@0.2.4`, independently
identified through registry integrity and SLSA provenance as source
`fab6dd11a4e866f5ce4108f5773b27d2d0fa89f0`, release run `39132631665`.
Record identities again for each independent run rather than trusting a directory
name. Factory candidate dependency is `c7731269b68eaebbde69843430e1a5f178631c16`
([upstream PR #56](https://github.com/iXab3r/EyeAuras.CliFactory/pull/56)); immutable
vendored URLs/provenance are checked by the package proof.

The measured target is lower fixed one-shot artifact-verification cost and lower
bounded-view guard cost, with identical useful output and no weakening of binding,
saved-effect, request-ID, ordering or publication checks. Before full measurement,
the regression budget is fixed at `max(15% baseline p50, 3 * max(MAD))` for medians
and `max(30% baseline p95, 3 * max(MAD))` for tails. These are host-noise allowances,
not a speedup claim. Insufficient, failed or censored cases fail the gate. The PR
component smoke uses a deliberately broad `max(2x baseline median, +50ms)` ceiling
to catch gross algorithm regressions without pretending a hosted runner is stable.
Always publish actual distributions, including a failing gate, before interpreting
an optimization. A busy host limits performance acceptance even when these checks pass.

## Matrix, preparation and equivalence

`fixtures.mjs` builds deterministic PE x64 programs: a 2,560-byte tiny input and an
83,888,640-byte input (over 75 MiB), using `/timestamp:0`, no CRT and fixed source.
The manifest retains source/export/input hashes, sizes, compiler versions and command
options. Addresses come from an independent PE export parser. No expected decompiler
answer is manually inserted. Both routes use `x86:LE:64:default` / `windows`, separate
no-analysis/full-analysis imports and the same explicitly prepared function definitions.
The setup script is public and deterministic. Its merge produces an immutable GZF;
CLI and RPC get independent private copies of the same shared state, and stock imports
that exact SHA-256-checked GZF. Program Information's actual Executable SHA256 is
checked, in addition to metadata/function/result validation.

Fresh imports across package versions can have different GZF container bytes, so
cross-version equivalence binds useful metadata, code/signatures/comments, memory
bytes, paging, strings/xrefs and decode evidence. Transport/profile/view identities
are excluded explicitly in `equivalence.mjs`; no code, bytes or completeness fields
are removed to make a result pass. Errors for missing functions must have the actual
expected reason. Every measured response is validated inside the timing observer;
a fast truncated/error/missing answer is not useful throughput.

For every input/analysis combination, five fresh profiles/JVMs measure cold open and
first queries, and separate five fresh RPC processes measure cold RPC open. Each
initial open is followed by an import of the other owned input through the already
running profile server (`warm.new-input`), then that extra private context is closed.
The first
trial runs three warmups and 30 reads per case through both one-shot CLI and the
existing persistent JSON-RPC transport. Case rotation is deterministic (seed 66067,
round-index rotation); CLI/RPC order alternates each round. Whole version phases are
serial, not statistically time-paired. OS file caches are not flushed. JVM/database
caches are cold only after fresh native process creation; first decompiler and later
prepared queries are distinguished. Independent contexts are restored from saved state.

Read cases: metadata, two functions, bounded two-function inspection, missing
definition, undefined executable decode, strings/xrefs, offset paging, 16-byte memory
and larger memory output (256 bytes tiny, 65,536 bytes large). Stock decompile also
fetches all five comments, matching the useful facade response. Stock lacks an
equivalent read-only pseudo-decode: report N/A, never substitute mutating disassembly.
The version-parity run uses Java bridge 7 with the stock Python 6 client; a distinct
Java bridge 6/Python 6 factor run exposes the unavoidable bridge-version difference.

Repeated insight persistence samples cover fresh private context, independent peer,
small annotation, exact durable-ID replay, program-only read script, merge, refresh
and independent readback, close/reopen/readback. Both warmups and 30 measured lifecycle
iterations run per input/analysis combination. Stock performs 30 warm save/close/reopen
cycles plus the remaining cold-trial cycles, retaining their cold-trial IDs. A stock
save is not equivalent to shared publication with history and independent verification;
report these stage families side by side with the difference in guarantees.

Concurrency repeats three warmups and 30 measured rounds of a controlled eight-second
script on two independent tiny contexts, queues a unique profile creation, then
issues a cheap independent read and diagnostic, followed by two parallel context reads.
It retains the existing FIFO diagnostic blockage tracked by #68; #67 must not claim
to have solved that scheduling issue. Recovery/failure-path semantics are additionally
covered by the ordinary offline fault-injection suite and native bounded-function proof.

## Evidence and interpretation

Every request has monotonic nanosecond start, end-to-end milliseconds, observer/file
I/O time, fixture/analysis/route/stage, warmup/sample/cold-trial identity, success and
load averages. One-shot records include PID/exit status. Failed/censored samples are
retained; only declared warmups are excluded. `summary.json` reports n, p50/p95,
mean, sample standard deviation, MAD, min/max and failure counts. Use
`summary-by-phase.json` to distinguish the prepared first query from the separate
cold-RPC import, and `summary-warm-by-phase.json` for warm reads/lifecycle operations;
the latter excludes the four extra stock cold-trial persistence cycles.
`coverage.json` requires every declared case/route/input/analysis combination,
unique repetition indices and complete successful 30/5 counts. It also checks every
measured memory digest against the independently constructed fixture data array,
including all returned bytes. Entirely absent cases fail acceptance.
`equivalence.json` binds stable useful hashes within/across routes, including all
prepared first queries against the warm results. The separate cold-RPC raw import's
initial metadata is excluded from prepared-state equivalence because it precedes
explicit function preparation. `gate.json` retains budget decisions.
`cleanup.json` and lifecycle readbacks establish owned cleanup and saved state.
The full runner generates `report.md` with all warm/first-query routes, separate cold
startup and persistence tables, contention, trace boundaries and the optimization plan.
`script-effects.json` reduces private before/after status transcripts to pending-change
counts and unchanged revisions for every cold trial, checking baseline/candidate
equivalence. `trace-request-windows.json` correlates fully contained spans with isolated
serial diagnostic requests. It retains repeated backend/save/export/hash counts;
inclusive durations are distributions, never cross-stage or cross-process sums.
`paired-overhead.json` retains per-round CLI minus persistent-RPC differences for
adjacent alternating requests on matched prepared private states. Negative deltas
are retained. Serial package/stock phases are not labeled time-paired comparisons.

Raw stdout, database manifests and JVM logs can contain local paths. Keep them in the
private evidence directory. Publish sanitized `requests.jsonl`, distribution/gate/
equivalence/trace summaries, fixture recipe and tool hashes after scanning for private
data. Do not publish auth headers, process receipts, local roots or research logs.

```sh
node scripts/performance/compare.mjs "$EVIDENCE_DIRECTORY"
node scripts/performance/verify-results.mjs "$EVIDENCE_DIRECTORY/baseline" "$EVIDENCE_DIRECTORY/candidate" "$EVIDENCE_DIRECTORY/stock-parity"
node scripts/performance/trace-report.mjs "$EVIDENCE_DIRECTORY/trace"
node scripts/performance/finalize.mjs "$EVIDENCE_DIRECTORY" 30 5
node scripts/performance/paired-overhead.mjs "$EVIDENCE_DIRECTORY" 30
node scripts/performance/report.mjs "$EVIDENCE_DIRECTORY"
node scripts/performance/trace-cost.mjs --module "$FACTORY_TIMING_MODULE" --root "$NEW_TRACE_COST_DIRECTORY"
```

Trace stages are inclusive. Exclusive totals subtract the union of immediate child
intervals, never a sum of overlapping client/owner/backend work. Java helper spans
include Ghidra startup; HTTP dispatch includes backend execution rather than being a
CPU profile of the decompiler. See the shipped [timing reference](../skills/ghidra-coordinator/references/performance.md).
The on/off sink-cost experiment alternates 30 samples, each 100 no-op requests / 200
spans, with exact work-count checks; it excludes child startup and cannot establish
the entire native tracing overhead. Native traced runs are diagnostic and kept out
of the untraced regression/equivalence gate.
The diagnostic collection also repeats contention with tracing and runs the installed
bounded-function proof with tracing enabled. The proof exercises actual result-file
writes; contention exposes queue wait separately from handler/backend work. These
additional diagnostic samples do not replace any untraced sample.
`trace-coverage.json` requires the declared stage boundaries, resolved parent trees
and binding scopes shared across multiple requests. The bounded proof includes a
structured function mutation checked in an independently reopened saved database
and exact durable-ID replay, so saved-effect inspection is exercised in native traces.

The component `view-compare` phase alternates old/new Java sources on the same
immutable prepared database, three warmups plus 30 measured calls each, requiring
identical view data and unchanged modification counters. `hashing.mjs` alternates
the old/new deployed-artifact algorithms on the same installation and requires
identical build identity every time. These test bottleneck hypotheses separately
from total native latency.
