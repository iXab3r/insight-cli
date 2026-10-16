# Where the live-agent 7zr time went

The largest measured bottleneck is the agent/orchestration interval outside CLI calls,
followed by a substantial serial publication/acceptance tail. Faster Ghidra reads alone
cannot explain or remove most of this experiment's elapsed time. The three-agent result
also depends on the slowest assignment, which varied considerably between runs.

This is a retrospective analysis of the [original experiment](7ZR-LIVE-RESEARCH.md),
not a new benchmark or an optimized rerun. Original outcomes and clocks are unchanged.
[Detailed timing evidence](verification/7zr-time-breakdown.json) includes all nine attempted
runs, per-actor timings, failed commands, command latencies and hashes of 270 source receipts.
The [analysis script](../scripts/live-research/analyze.py) reconstructs eight successful
wall-clock partitions and asserts that every partition sums to the original total.

## Complete elapsed-time accounting

Means below use only the three completed prepared pairs. They are descriptive, not a new
performance gate; the failed fourth attempt remains separately recorded. Overlapping reads
are combined as an interval union, so concurrency is not counted twice.

| Exclusive wall-clock category | One agent, mean s | Three agents, mean s | Three-agent share |
| --- | ---: | ---: | ---: |
| Dispatch until first successful read starts | 21.61 | 22.04 | 8.7% |
| At least one successful research read is in progress | 16.45 | 16.91 | 6.7% |
| Rest of research window through final private save | 213.75 | 125.75 | 49.9% |
| Final save until collection starts | 15.69 | 11.61 | 4.6% |
| Read findings / copy other contexts into lead | 1.32 | 9.56 | 3.8% |
| One merge | 16.00 | 19.12 | 7.6% |
| Open fresh verification context | 10.77 | 14.63 | 5.8% |
| Remaining independent CLI verification | 13.08 | 15.16 | 6.0% |
| Semantic review and finish | 17.74 | 17.37 | 6.9% |
| **Total** | **326.41** | **252.15** | **100%** |

The sub-millisecond before-dispatch bookkeeping is retained in JSON and rounds to zero.
Preparation/import is excluded here. The 125.75 s category includes reasoning, provider
latency, tool dispatch/approval, JSON construction/file writes, save calls, failed reads and
waits outside successful-read envelopes. It is **not** an inference-time measurement or
an estimate of wasted time. The old logs cannot split it into those components.

The lead's handoff and semantic review alone averaged 28.98 s for triples and 33.44 s for
serial runs. These are experiment/orchestrator costs, including useful review, rather than
latency of an insight-cli command. The 21–25 s before a triple's first successful read also
includes dispatch, instruction reading and tool scheduling; native contexts were already ready.

Even in the fastest triple (pair 2), the last finding was saved at 128.52 s and the end
arrived at 205.75 s: another **77.23 s** for handoff, collection, merge and verification.
In pair 1 that tail was 90.73 s; in pair 3, 94.38 s. Parallel research cannot amortize away
this serial tail. A purely illustrative model that divides the mean serial research phase
by three while retaining the measured triple post-research overhead gives about 165 s,
or 1.98x versus 326 s, rather than 3x. That assumes perfect research scaling and is not a forecast.

## Why the third pair lost

Times are relative to dispatch of that prepared triple:

| Assignment | First read starts, s | Last successful read ends, s | Finding saved, s | Sum of all CLI latencies, s |
| --- | ---: | ---: | ---: | ---: |
| Switches | 25.17 | 49.98 | 111.30 | 8.07 |
| Password | 30.76 | 83.37 | **230.95** | 20.74 |
| Extraction | 36.72 | 70.96 | 104.47 | 12.27 |

Switches and extraction were finished about **120 and 126 s** before password. Those
are overlapping idle windows, not durations to add to total time. The password agent made
14 read attempts, two failed, and one save. Its successful reads, including several
overlapping calls, did not occupy anything close to the 231 s elapsed actor window.

From its last successful read to the save was 147.57 s. Subtracting its 9.69 s save plus
**all** 1.03 s of failed read latency still leaves a conservative **136.85 s outside timed
CLI calls**. Across its whole actor window, at least 210.21 s lay outside timed CLI calls.
This cannot be blamed on a 137-second Ghidra decompile. It includes uninstrumented agent,
formatting, execution-tool and provider activity; the exact composition is unknown.

This was not simply an unavoidable amount of password work. In pair 2, password's finding
was saved at 128.52 s, with 12.26 s of CLI latency; in the cold triple, at 151.76 s with
12.15 s of CLI latency. Agent variance and uneven task complexity matter more here than
the difference between individual read latencies. A static split into three topics leaves
two workers unable to help the longest assignment. Dynamic redistribution was not tested.

Pair 3 did save 19.05 s in the full research phase (260.75 → 241.70 s), but its later phases
cost 28.65 s more (54.98 → 83.63 s), producing the observed 9.60 s overall loss.
The publication/acceptance path was sequential; it did not become faster with three workers.

## What CLI and native code actually did

Client-observed subprocess latency for completed prepared research calls:

| Command | Calls | Median, s | P95 nearest rank, s | Maximum, s |
| --- | ---: | ---: | ---: | ---: |
| `strings search` | 18 | 1.207 | 2.835 | 2.835 |
| `xrefs to` | 49 | 0.487 | 1.227 | 1.584 |
| `functions decompile` | 67 | 0.778 | 1.418 | 2.665 |
| `functions get` | 6 | 0.516 | 0.568 | 0.568 |
| `comments set` (private saves) | 18 | 2.990 | 9.695 | 9.695 |

These are end-to-end CLI calls, including process startup, Factory IPC, keyring, facade,
native work and OS scheduling. They do not isolate Ghidra computation. Per-actor sums can
overlap and are not an elapsed-time partition. The observer recorded only about 8–13 CPU
seconds across owned native workers in completed prepared runs; its observation window
extends through collection/merge. This supports low worker CPU utilization in this task,
but is not a complete CPU profile of helper JVMs, Factory, AI inference or the host.

Several concrete inefficiencies/gaps are visible:

1. **Repeated boundary verification and HTTP discovery.** In the hot live-context path,
   [`verified`](../skills/ghidra-coordinator/src/contexts.ts) constructs a new `HttpBridge`,
   reads instance identity, obtains schema, checks source SHA and reads metadata. A
   [`function`](../skills/ghidra-coordinator/src/research.ts) read invokes that path for
   `open`, `/get_functions` and `/get_comment`. Static inspection implies 14 HTTP requests
   in that ordinary path, before unrelated surrounding CLI work. An xref read additionally
   resolves each containing function separately: an N+1 pattern. Those counts are inferred
   from source, not an HTTP trace of the historical runs. Reuse under the same verified
   process/runtime/view identity could reduce round trips; ownership checks must remain.
2. **Every private edit captures a whole program snapshot.** The
   [`capture`](../skills/ghidra-coordinator/src/contexts.ts) path saves and exports a GZF,
   then captures it durably. The lead repeats this for the other two findings. Collection
   averaged 9.56 s for triples against 1.32 s for serial. A durable batch transfer could
   avoid two independent whole-program captures. Simply acknowledging unsaved edits would
   violate the durability contract.
3. **Fresh native setup in the serial verification tail.** The fresh session alone costs
   10–20 s; its strings, xrefs and unique-function decompiles then run serially. The harness
   already caches decompiled functions within verification, but repeated string/xref checks
   for distinct anchors are not batched. Preserve exact-version independent readback while
   batching reads in one verified context. Do not remove verification to improve a score.
4. **Merge performs substantial independent work.** The
   [`merge`](../skills/ghidra-coordinator/src/research.ts) path obtains an actual shared
   snapshot, inspects base and shared fields through separate helper invocations, then
   publishes and independently verifies exact saved buffers. Even unchanged R1 takes this
   route. Reusing a verified immutable snapshot keyed by actual server revision may help,
   but requires version/authority checks. Existing timings do not split these substeps;
   no particular helper can yet be assigned the full 16–24 s merge cost.
5. **Function navigation errors are opaque.** Nine failed research calls across all nine
   attempts were `functions get`, reporting `coordinator.partial` / “Function result omitted,
   failed or changed the requested selector.” They cost seconds directly, not the long tail.
   Their recovery/reasoning cost is unmeasured. The evidence proves a navigation/error-UX
   gap; without the original transport response it does not establish whether each selector
   was absent, interior, ambiguously resolved or mishandled by the adapter.
6. **Failed reads disappear from the main event timeline.** `control.mjs` appends its read
   event only after success. The subprocess logs retain failures and their latency but no
   absolute start time. Therefore this analysis recovers failed attempts but cannot place
   them precisely in the original monotonic timeline. “Successful read count” was never
   the full number of attempts.

There were no repeated successful address reads of the same command within an actor in
these receipts. Read responses per parallel actor were only about 5–10 KiB. Therefore a
claim that the slowdown came from huge read payloads or repeated decompiles is unsupported.
Findings did require manually constructed JSON, literal code quotations and limitations;
output preparation is a plausible contributor to the long quiet tails, not a measured fact.

## Priorities and proof needed before claiming an improvement

| Priority | Change/investigation | Why / next measurable result |
| --- | --- | --- |
| P0 | One correlated trace for actor dispatch/ready/final, every read/save start/end/error, collection and each merge stage | Split the currently unassigned intervals; preserve errors, monotonic clocks and request IDs, without raw secrets/payloads |
| P0 | Free-space telemetry, owned-artifact accounting, preflight and safe ENOSPC recovery | Fourth attempt failed; failed journals stay retained. Sample disk per trial. Later ENOSPC does not prove earlier latency was disk-caused |
| P1 | Trace saved/final/collected boundaries and use event-driven handoff; automate mechanical validation and keep semantic-review time separate | 10–19 s after saves plus 12–23 s review are visible experiment costs. The logs do not isolate final-response generation from orchestration delay. Retain the original end-to-end metric alongside component times |
| P1 | Compact structured findings with evidence captured from CLI results, bounded required coverage and early progress/checkpoints | Test the 34–137 s post-read tails; avoid manually transcribing evidence without weakening correctness. Record generation/file-write/save boundaries |
| P1 | Redistribute unfinished research by explicit subquestions, or compare with two agents | Two workers waited about two minutes in the slow triple. Demonstrate reduced critical-path time with the same business coverage |
| P1 | Batch lead transfer and independent verification | Measure number of durable captures, fresh-reader open and read calls; retain save acknowledgments and exact-version correctness |
| P2 | Cache discovery/verification under an explicitly bound live identity; batch function/xref metadata | Existing reads are subsecond to a few seconds. First profile native round trips/keyring/CLI startup; avoid optimizing the smallest component first |
| P2 | Break down merge, then reuse immutable exact-version snapshots where safe | Measure shared export, field inspections, publish, fingerprint/readback separately; rerun conflicts, external changes and crash recovery |
| P2 | Typed navigation outcomes with requested/resolved address and actionable continuation | Eliminate generic function errors; prove selector behavior on the exact failing addresses |

The priority order favors observability, the critical actor and serial work. It does not
promise that all the unassigned time is recoverable. A fair next comparison must keep the
same findings/verification, report all failures, freeze its new protocol, and compare equal
agent configurations. It should separately report native request service time, agent elapsed
time and complete accepted-result latency. Increasing only the number of Ghidra instances
does not address most of the time identified here.

## Reproduce this analysis

```sh
python3 scripts/live-research/analyze.py <retained-private-run-directory> <output.json>
```

No live CLI or Ghidra process is started. The script reads historical monotonic events and
public subprocess receipts. It emits portable aggregates and sanitized error codes/messages;
raw inputs, command bodies, personal paths and credentials remain private. Model tokens,
provider queue/inference timings, execution-tool approval latency, agent final-response
timestamps and native substage spans were not captured and cannot be reconstructed.
