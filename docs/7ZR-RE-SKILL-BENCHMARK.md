# One versus three live RE-skill agents on 7zr.exe

This comparison uses the packaged RE skill, ordinary Markdown findings and automatically
retained public-CLI responses. It repeats the same useful three-part research question in
both modes on independently prepared bases. The final results and timing analysis are
recorded in [portable evidence](verification/7zr-re-skill-benchmark.json).

## Results: useful research through accepted merge

The three original prepared-base pairs all completed correctly and favored three agents:
**median paired full-task speedup 1.516x**, range **1.419–1.528x**. Active research through
the final worker's `done` improved by a median **1.806x**. An additional continuously warm
native-process control passed at **1.640x** full-task and **1.743x** active-research speedup.
Keep this control separate from the original three pairs; it changes owner maintenance.

| Pair / execution order | One agent, full task | Three agents, full task | Full speedup | Active-research speedup |
| --- | ---: | ---: | ---: | ---: |
| Original 1: 1→3 | 367.003 s | 240.245 s | 1.528x | 1.806x |
| Original 2: 3→1 | 366.438 s | 258.257 s | 1.419x | 1.755x |
| Original 3: 1→3 | 328.760 s | 216.924 s | 1.516x | 1.810x |
| Supplemental warm control: 1→3 | 356.870 s | 217.654 s | 1.640x | 1.743x |

These are eight actual live-agent executions, with 24 accepted part findings, eight single
merges applying three annotations each, and eight fresh-reader checks of code and R1/R2
history. All saved part folders and combined research folders match their source trees.
No failed or slower trial was replaced. A separate read-only audit checked timing unions,
identities, content proofs, native observation coverage and saved copies.

The repeated findings are useful navigation/research results, rather than timing-only
lookups:

| Topic | Located code | Accepted result |
| --- | --- | --- |
| Switch handling | `0x40125a`; comparison `0x402576`; character lookup `0x402369` | Longest ASCII-case-insensitive descriptor prefix wins; repeat permission and existing-result state control duplicate rejection. Postfix minimum/type determine separate short/incorrect/long diagnostics. Type 3 permits an empty postfix when its minimum permits it. |
| Interactive password | `0x43f4f5`; reader `0x401ec8`; wrapper `0x401f02` | Prompt and flush are conditional on an output stream. Echo suppression depends on successful console API calls; saved mode is restored only on the proven ordinary-return path. LF/EOF return success, NUL returns failure; no secure-erasure or exception guarantee is inferred. |
| Extraction diagnostics | `0x436fea` | Numeric selectors 1/2/3 mean unsupported method/data error/CRC failure. A separate zero/nonzero argument changes the wording for 2/3; “Wrong password?” does not prove password failure. Value 9 has separate `Wrong password` wording; the flag's provenance remains qualified. |

The portable report contains note hashes, entries, saved-material digests, raw-source
receipt hashes and independent verification flags. Full raw responses and findings remain
in the owned local research folders. No binary, personal paths or private transcripts are
committed. The task changes AI-agent count and native-context count together: it proves
this combined workflow's observed acceleration, not an isolated JVM-parallelism effect.
Three paired observations support repeatability here; under an independent equal-probability sign null, the chance of
all three improving is 1/8, with no population or broad statistical claim. The extra control is just one pair.
There is no controlled skill-enabled versus skill-disabled comparison.

## Where the time went

The following are **exclusive wall-time buckets**, in seconds. The first two columns are
means of the three original trials per mode; the last two are the supplemental pair.
Within concurrent research, interval unions count overlap once, with artifacts then
annotation then reads taking precedence. Unrounded buckets in the JSON sum exactly in
integer nanoseconds to every full task.

| Wall-time bucket | Original: 1 agent | Original: 3 agents | Warm: 1 agent | Warm: 3 agents |
| --- | ---: | ---: | ---: | ---: |
| Dispatch → first research read | 32.33 | 28.49 | 40.82 | 24.51 |
| Research reads through CLI | 19.51 | 18.43 | 18.62 | 14.62 |
| Private annotations | 10.36 | 8.60 | 7.42 | 6.46 |
| Part materials save | 2.07 | 1.83 | 1.36 | 1.60 |
| Research outside recorded task CLI | 201.73 | 91.32 | 185.53 | 98.38 |
| Last worker done → lead collection trigger | 18.41 | 15.38 | 42.17 | 14.85 |
| Collect/read/copy actual annotations | 2.07 | 6.74 | 2.13 | 6.31 |
| One merge | 21.14 | 21.89 | 17.74 | 16.64 |
| Fresh verification context open | 12.44 | 12.26 | 14.66 | 11.02 |
| Remaining native verification/history | 16.49 | 19.38 | 19.08 | 15.74 |
| Final acceptance outside summary save | 16.99 | 13.58 | 6.81 | 6.96 |
| Combined materials save | 0.54 | 0.56 | 0.53 | 0.57 |
| **Total** | **354.07** | **238.48** | **356.87** | **217.65** |

The largest original change is research outside recorded task CLI: **201.73→91.32 s**.
It accounts for about 110.41 s of the 115.59 s mean full-task reduction. Read-call wall time
changes only **19.51→18.43 s**. Parallel agents reduce the long human/agent-facing research
and reporting path; there is no evidence here that slow CLI reads explain most elapsed time.
Those outside intervals include reasoning, tool scheduling/approval, file work, output
composition and provider latency. They are neither isolated model inference nor all waste.
The warm control also includes maintenance metadata calls inside these ordinary wall
intervals; their separate overlay must not be added again.

After the last worker finishes, the original runs still spend **88.07/89.80 s** on handoff,
collection, publication and acceptance. From collection trigger onward this is
**69.66/74.41 s**. These stages remain serial and explain much of the gap between research
speedup and full-task speedup. Copying the other workers' comments adds collection work;
merge and fresh verification do not become three times faster with three researchers.

The supplemental baseline also has an unusually long **42.17 s** lead handoff versus
**14.85 s** for three agents. This is observed lead orchestration, not Ghidra latency.
For scale only, removing each observed handoff arithmetically gives 1.552x rather than
1.640x. That is a sensitivity calculation, not a separately measured optimized run or a
replacement result. The active-research ratio is 1.743x and still includes skill reading,
startup scheduling and the retained recorder error described below.

### Agent critical path and early finishers

Password was the last worker in all four three-agent trials. Its helper chain, ABI
ambiguities and reporting took longer than the other two topics.

| Three-agent trial | Switches done | Password done | Extraction done | Password last read → done |
| --- | ---: | ---: | ---: | ---: |
| Original 1 | 122.91 s | 148.02 s | 133.73 s | 56.78 s |
| Original 2 | 103.19 s | 159.86 s | 133.79 s | 52.77 s |
| Original 3 | 126.16 s | 138.16 s | 122.01 s | 45.22 s |
| Warm control | 121.88 s | 145.56 s | 113.23 s | 54.60 s |

In original pair 2, switches waits **56.67 s** and extraction **26.07 s** for password.
In the warm control these tails are **23.68/32.33 s**. They overlap and cannot be added to
the exclusive task partition. Original password workers spend only **10.30–15.76 s** summed
inside their research CLI calls. Their 45–57 s post-last-read intervals include notes,
annotation/save, scheduling and final markers. Writing markers alone often bracket only
the file-write step; they do not measure all note composition. The single agents have
118.16/147.86/120.23 s from their last read to final `done`, covering all three deliverables
and, for pair 2, an explicit correction.

### Client-observed call latency

Across the six original runs, failed calls remain included:

| Research operation | Calls | Failed | Median | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| Strings search | 18 | 0 | 1.214 s | 5.963 s | 5.963 s |
| Xrefs to | 41 | 0 | 0.452 s | 0.965 s | 2.168 s |
| Decompile | 72 | 0 | 0.724 s | 1.235 s | 1.395 s |
| Disassemble | 15 | 1 | 0.427 s | 1.002 s | 1.002 s |
| Private comment set | 19 | 0 | 2.654 s | 5.644 s | 5.644 s |
| Part artifacts save | 19 | 0 | 0.526 s | 1.354 s | 1.354 s |

One `functions inspect` attempt also failed in 0.450 s because the agent supplied
`--address` where `--function` was required. The disassembly failure was a recorder parsing
failure on `--help` text despite CLI exit 0, rather than a native operation failure.
The frozen recorder was not patched mid-series. These calls and corrections count in wall
time. In the warm pair there were no failed dispatched CLI calls; the single agent first
made three rejected recorder calls using `actor0` instead of numeric `0`, and an extra
readiness marker. This happened before CLI dispatch, so it is outside CLI spans but inside
elapsed time; its separate error-record hash is retained.

Original baseline pair 2 also corrected a too-strong empty-postfix claim after its first
checkpoint/`done`. The private first version and receipt are preserved with hashes; the
corrected version was checkpointed again before collection. No wrong version was merged.
The full **50.266 s** correction cycle stays in that baseline, and the analyzer uses the
**last** `done`. This required a nineteenth annotation/save rather than eighteen.

## Prepared bases, owner idle timeout and native CPU coverage

All contexts were ready on persistent **R1** before each clock. However, original baseline
pairs 1 and 3 lost their initial native PID before the first research read. Installed
Factory IPC defaults to a **60 s** idle owner shutdown, which calls application disposal;
insight-cli disposes its native contexts. Existing status RPC alone does not keep it active.
The initial `stopped.json` receipts are approximately 60.47/60.48 s after readiness, and
replacement process receipts retain base revision 1. Setup-ready → dispatch gaps of
38.42/55.06 s left little time for skill reading before that timeout. First reads restored
the prepared contexts and took approximately 5.8–6.0 s. These were not first imports, but
those two baselines are not continuously warm native-process measurements.

The original PID-only observer stopped sampling after **21.18/5.06 s** in those baselines.
Its measured CPU growth of **0.02/0.04 s** is therefore partial and says nothing about total
Ghidra CPU. Other original runs cover through final worker `done`; the fully observed
single has 8.66 s sampled initial-worker CPU, and triples have 9.38–12.85 s. All original
triples show CPU growth for every worker within their common research window. The recorded
native proof ends that common window at each actor's **first** `done`; only the task
partition follows the correction's final `done`. The observer has no explicit exit-reason
receipt; process receipts and installed lifecycle source establish the idle-restoration
explanation separately. No host CPU, peak memory or provider inference time is measured.

The declared [supplemental protocol](../scripts/re-skill-benchmark/warm-protocol.json)
adds one separate pair using ordinary read-only `targets list --limit 1` every 15 s in
**both modes**, starting before the task clock. It performs no target-specific warmup.
Public `open` revalidates the same ready R1 contexts with zero pending changes immediately
before dispatch. The unchanged package/skill/controller and fresh agent rules remain fixed.

All original PIDs remain present in the supplemental observations through final `done`:
maximum sampling gaps **1.021/1.031 s**, observed initial-worker CPU **8.62/11.51 s**.
All three workers increase CPU within their common 72.95 s sampled window. This is process
CPU growth, not proof that three cores were busy continuously.
All **24/16** maintenance calls succeed and terminate after the task. Of them **23/14**
overlap the task clock, occupying unions of **14.11/6.28 s**, with **3.93/2.01 s** already
overlapping task CLI calls. Maintenance is reported as an overlay; elapsed includes its
interference, and no subtraction is used in the headline ratio.

Preparation is excluded and separately retained:

| Pair | One-agent profile/import/context prep | Three-agent profile/import/context prep |
| --- | ---: | ---: |
| Original 1 | 96.97 s | 85.32 s |
| Original 2 | 60.06 s | 103.41 s |
| Original 3 | 59.12 s | 82.35 s |
| Supplemental | 67.35 s | 102.28 s |

These include first import/analysis and context preparation under the existing OS/runtime
cache state. Warm revalidation and dispatch gaps are separate receipts. No new full cold
end-to-end pair or cache-flush experiment was run. The earlier cold-agent result remains in
its original report. Disk preflight requires 40 GiB; observed free disk remains above
242 GiB in all eight runs. The historical ENOSPC/unknown-publication lane was not reopened.

## Priorities suggested by these measurements

1. **Bound reporting and helper exploration to the requested answer.** Ask for early concise
   notes and explicitly check high-risk boundaries such as empty postfixes. Preserve raw
   evidence automatically. The long post-read tails and one 50 s correction are larger
   opportunities than subsecond xref calls. Do not trade away qualified, code-backed answers.
2. **Use checkpoint-driven lead handoff and overlap review with research.** Avoid waiting
   for prose final messages or a slow polling cycle once durable checkpoints and final done
   exist. The observed handoff costs 15–42 s; final review/collection remains another serial
   stage. Preserve the one-merge and independent-readback gate.
3. **Balance the actual critical topic.** Password is last in every triple. Reassign useful
   independent validation to early finishers or size work from helper-chain uncertainty;
   simply adding equally sized labels does not equalize completion time. This requires a
   new controlled comparison before claiming improvement.
4. **Make owner/context lifecycle explicit for prepared runs.** Decide the intended idle
   retention/lease policy at the Factory integration boundary, and make the observer follow
   PID replacement with an exit reason. Metadata keepalive is a test control, not a shipped
   runtime fix. Avoid calling partial initial-PID CPU a complete native-work measure.
5. **Trace publication substages before optimizing them.** Individual merges span 16.26–29.58 s;
   mode means are about 21–22 s in the original series and 17–18 s in the warm pair.
   Fresh opens average 11–15 s by mode. Split client startup/IPC, snapshot preparation, server check-in
   and verification first; this experiment cannot identify which substage to cache or batch.

The package runtime and skill are unchanged by this benchmark. This change adds the
frozen experiment, offline reporting and documentation. `npm test` passes **139/139**
offline tests; real Ghidra acceptance is the eight research/merge runs above.

## Fixed workload and acceptance

Input: 7-Zip 26.04 x86 `7zr.exe`, 602624 bytes, SHA-256
`256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282`.
Only static analysis is performed; the target is never executed.

The three questions concern invalid-switch recognition/rejection, interactive password
input guarantees, and extraction-result diagnostics. Agents start with only the strings
`Unknown switch:`, `Enter password (will not be echoed):` and `CRC Failed`, the installed
skill and their assigned ready context. Timed agents receive no addresses, source, earlier
answers or correctness oracle. Each finding must explain at least three substantive
code-backed conditions, link to actual raw output and retain remaining uncertainty.

One fresh agent handles all three parts in one context, freely choosing order and batching
independent reads. Three fresh agents handle one part each in three separate native contexts.
All use `fork_turns=none`, inherit identical parent settings and have no model/reasoning
overrides. Exact deployment ID, provider queue/inference time and token usage are unavailable.
Other external tools remain permitted by the skill; this workload specifically requires
Ghidra control-flow evidence and does not add an external-tool worker.

Each part produces ordinary `finding.md`, retained raw responses, one durable private
annotation and a saved folder through `artifacts save`. The test recorder supplies routing
and automatic receipts; agents do not transcribe a finding JSON schema or literal quotes.
The lead collects actual comments into one context and merges once in both modes.
A fresh context checks all comments, clue-string/reference chains, actual main/helper code
and repository history R1/R2. The verifier strips C comments before checking code fragments,
so the newly written annotations cannot prove themselves. The lead separately reviews
business coverage and limitations. A final research-folder copy must match source bytes.

The [frozen protocol](../scripts/re-skill-benchmark/protocol.json),
[agent contract](../scripts/re-skill-benchmark/AGENT-TASK.md),
[public-CLI controller](../scripts/re-skill-benchmark/control.mjs),
[observer](../scripts/re-skill-benchmark/observer.mjs) and
[offline analyzer](../scripts/re-skill-benchmark/analyze.py) retain the experiment.
The hidden-from-agents oracle was calibrated against the previously verified binary;
this is instructional isolation, not an OS security boundary.

## What the clock includes

Three prepared pairs run in order 1→3, 3→1, 1→3. Every attempt, slower outcome and failure
is retained without replacement. Profile configuration, first import/analysis and preparing
all contexts are timed separately. No task-specific searches/decompilation are precomputed.
The main monotonic clock starts immediately before agent dispatch and ends after collection,
merge, independent native readback, semantic review and final materials save. Cleanup is
outside it. No new cold end-to-end agent comparison or cache-flush experiment is claimed.

Every public-CLI wrapper call has correlated start/end/error events, including failures.
Ready, writing/written and done markers expose handoff and note-writing intervals. Native
PID/root identities, process CPU and free disk are observed separately. All wall partitions
use interval unions and exactly sum in integer nanoseconds. Concurrent per-agent call
sums and idle tails are descriptive; they must not be added to the wall partition.

Outside-CLI intervals contain reasoning, tool scheduling/approval, file work and provider
latency. Writing markers bracket the reported writing operation, not every token generated
while planning a note. Neither quantity isolates model inference. Lead inspection may overlap research or handoff;
verified-to-finished is the final acceptance interval, not total analyst review effort. Merge and read latencies
are whole client-observed calls; they do not split Factory/keyring/transport/JVM substages.

## Reproduction

Use Node 24, the recorded package artifact, exact input and configured macOS Ghidra/Java.
The installed artifact is unchanged throughout all trials; product source is not patched.

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/re-skill-benchmark/control.mjs init \
  /tmp/new-re-skill-benchmark '<installed-package-directory>' /path/to/7zr.exe
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/re-skill-benchmark/control.mjs trial \
  /tmp/new-re-skill-benchmark pair-1-1 1
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/re-skill-benchmark/control.mjs start \
  /tmp/new-re-skill-benchmark/pair-1-1/trial.json
# Dispatch fresh agent(s) with AGENT-TASK.md, part(s), actor and ready selectors.
# Read settled findings; collect once, review the fresh proof, then finish.
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/re-skill-benchmark/control.mjs collect \
  /tmp/new-re-skill-benchmark/pair-1-1/trial.json
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/re-skill-benchmark/control.mjs finish \
  /tmp/new-re-skill-benchmark/pair-1-1/trial.json /path/to/review.json
python3 scripts/re-skill-benchmark/analyze.py /tmp/new-re-skill-benchmark --output report.json
# After all original six runs, optionally include the separately declared warm pair:
node scripts/re-skill-benchmark/export.mjs /tmp/new-re-skill-benchmark portable.json \
  /tmp/new-re-skill-warm-control
```

For the supplemental pair, copy its declared protocol to the run, retain its hash and the
maintenance-script hash in `manifest.supplemental`, start `keep-warm.mjs` before timing in
both modes, revalidate the existing R1 sessions through public `open`, and retain the
initial/native identity and revalidation timestamps. Export requires the retained local
process receipts, private result trees and installed artifact as well as event logs.
The frozen analyzer expects six original trials; the exporter deliberately selects the
two declared supplemental trials rather than treating unplanned pairs as failures.

This is a live-agent experiment, not an unattended npm/Gherkin workload. Later trials follow
the frozen order. On failure retain the run and inspect public status/history; never blindly
repeat a publication. Only owned disposable contexts/server are closed. The copied executable,
full findings/transcripts, selectors and personal runtime paths remain outside Git.

The [earlier pre-skill measurements](7ZR-LIVE-RESEARCH.md) and their
[time analysis](7ZR-TIME-ANALYSIS.md) keep their original outcomes. Different reporting and
orchestration contracts prevent attributing a before/after difference solely to the skill.

The frozen experiment uses its recorded unpublished `@ixab3r/insight-cli` artifact and
source revision. The later registry package is named `@eyeauras/insight-cli`; use the
recorded artifact/source when reproducing this historical timing series. Its receipts
are not rebound to the registry release.
