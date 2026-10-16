# Executable agent business acceptance

**All 25 business scenarios pass on real Ghidra through the installed public CLI.**
Six prepared-base pairs demonstrate repeatable acceleration with three native workers.
This document records the accepted results, limits and reproduction protocol.
The [agreed catalogue](BUSINESS-SCENARIOS.md) owns BS-01–BS-25 and their business criteria.

## Accepted native run

On 2026-10-16, Automation run `6c4a73fec46c417c8e2a61e98f4c755c` passed **25/25**
individual business scenarios, with zero failures or skips. The TRX interval was
11:18:38–12:51:33 Europe/Berlin, about 93 minutes including all functional cases,
setup, repeated trials and cleanup. The outer gate verified unchanged source/runtime
inputs and EXE bytes, one installed artifact across all scenarios and successful
owned-resource cleanup. All sentinel-tracked children exited; a subsequent read-only
process check found no remaining processes for its four disposable profiles.

[Machine-readable evidence](verification/business-scenarios.json) records all scenario
checks, source hashes, exact corpus/artifact identity, every trial and its phases,
actual worker CPU/overlap observations and the raw report/TRX SHA-256. Repeated lookup
tables are compacted there to counts, hashes and first/last rows; complete original
tables and private transcripts remain retained outside Git. Acceptance ran against
the intended source tree based on `3ceaa10`, with the subsequently committed source
bound by those hashes. No private Automation source or local manifests are published.

The same product correction passed **129 offline tests**, and the existing **two offline
Gherkin smoke scenarios** passed. The earlier 33-group GUI/full-facade gate retains its
historical identity; it was not rerun as part of this business gate.

Environment: Apple M5, 10 logical CPUs, 16 GiB, macOS/Darwin 25.6.0, Node 24.21.0,
.NET 10.0.303, Ghidra 12.1.2, Java 21.0.11 and Clang/LLD 22.1.8.
Installed npm artifact SHA-256:
`cd7b9e2be2c7ea1b18ba2f2a270eab44b3d08cc30629c1afd6ed118b6bdc3504`.

### Prepared-base acceleration: required gate passed

All six paired trials had equivalent complete findings and `T3 < T1`. The median
paired speedup is **1.601x**, range 1.569–1.727x; median three-worker efficiency is 53.36%.
The exact one-sided paired sign probability is **1/64 = 0.015625** under the declared
null model. This is evidence for this fixed workload and machine, not a guarantee for
all investigations. The protocol and strategy were frozen before this complete run.

| Pair | One worker, seconds | Three workers, seconds | Speedup |
| --- | ---: | ---: | ---: |
| 1 | 234.84 | 136.00 | 1.727x |
| 2 | 218.38 | 136.77 | 1.597x |
| 3 | 217.56 | 138.68 | 1.569x |
| 4 | 220.78 | 137.59 | 1.605x |
| 5 | 222.59 | 137.97 | 1.613x |
| 6 | 221.43 | 139.23 | 1.590x |

Median times are 221.11 and 137.78 seconds.
Sample standard deviations are 6.29 and 1.19 seconds respectively. The standalone
BS-21/BS-22 correctness runs measured 245.25 and 140.24 seconds; they are reported
separately and do not replace any of the six pairs.

### Cold and uneven work: separate reported outcomes

| Case | One worker, seconds | Three workers, seconds | Observed speedup | Required speedup |
| --- | ---: | ---: | ---: | --- |
| BS-24, fresh profiles and first imports | 258.25 | 194.00 | 1.331x | No |
| BS-25, partition `[128,32,32]` | 212.58 | 173.44 | 1.226x | No |

Both cases published and independently verified all findings. Cold timing includes
import, analysis and native context startup, with unflushed OS/tool caches. The uneven
case still performs 192 batches / 3,840 candidate evaluations; a heavier first part
limits the benefit of three workers. Coordination costs and unused parallel capacity
remain visible in per-trial phases and efficiency. Neither observation is counted as
a prepared-base acceptance pair.

## Gherkin and public interface boundary

Five [business feature files](../tests/acceptance/Features/Business) contain 25 separate
scenarios, tagged `business`, `native` and their stable BS ID. BS-21–BS-25 additionally
carry `performance`. English Reqnroll/NUnit scenarios run through the pinned
[Automation runner](ACCEPTANCE-AUTOMATION.md).

[Product bindings](../tests/acceptance/Bindings/BusinessSteps.cs) launch the test-side
[driver](../scripts/business/driver.mjs) under Automation's process sentinel. The driver
starts actual installed `dist/src/bin.js` processes, using ordinary Factory IPC, AppData,
profiles, permissions and OS keyring. Research, edits, conflict handling, status,
continuation and verification use public CLI commands. The driver imports Node builtins
and test-side modules only. Product code, custom entry points, SDK calls, direct MCP
requests and runtime hooks are absent from the business workflow.

The [functional workflows](../scripts/business/cases.mjs) assert actual findings, private
and shared values, retained conflicts and independent readback. A lost reply in BS-19
and BS-20 is deliberately discarded at the CLI-client boundary; the actor then uses
public status, original request identity and independent readback. BS-17 kills a verified
owned first-import worker; BS-18 kills a verified owned active context. Private process
receipts are inspected only by fault injection and worker-identity observation.

Cases close their contexts through the CLI. Suite cleanup disconnects only its recorded
disposable profiles. It does not globally stop the ordinary IPC service; Factory's normal
idle policy owns its exit. Profiles, journals and diagnostic evidence remain retained.

## Corpus and independent oracle

The source-controlled [research fixture](../tests/acceptance/fixtures/research.c) builds
two actual x64 Windows PE executables with Clang/LLD. They have the same `client.exe`
basename and overlapping code addresses, differing version evidence and different hashes.
The independent PE export-table reader records expected addresses before Ghidra imports
anything. Each run records both exact EXE hashes and the installed npm artifact hash.

The fixture includes a string-to-function clue, exported scalar functions, and three
real byte-string hash implementations: FNV-1a, DJB2 and SDBM. An independent JavaScript
oracle computes expected hash matches. The benchmark emulates the actual executable's
instructions on Ghidra and requires every candidate to finish normally. Incomplete,
truncated and budget-exhausted results fail. Source/runtime and corpus identity are frozen
before Gherkin execution and checked again afterward.

This suite's corpus is a compiled research fixture. The earlier production `7zr.exe`
[walkthrough](AGENT-CLI-WALKTHROUGH.md) and [import recovery](INITIAL-IMPORT-RECOVERY.md)
retain their separate evidence. The benchmark measures CLI-assisted investigation
execution on the declared corpus; it makes no live-AI reasoning-speed claim.

## Product correction found by the workflows

BS-03 exposed an exported-data reference that Ghidra reports as `Entry Point` with
kind `EXTERNAL`. The convenience `ghidra xrefs to` command previously tried to parse
that metadata label as an address and rejected the whole reference page. It now
preserves the row with `from: null`, `source: "entry-point"` and its actual destination;
ordinary navigable references remain available with their containing functions. An
offline regression checks mixed metadata/navigable pages and still rejects malformed
non-external addresses. The real workflow then traverses the clue into decompiled code.
See the [public research contract](../skills/ghidra-coordinator/references/research.md).

## Frozen timing protocol

The machine-readable [protocol](../tests/acceptance/fixtures/benchmark-protocol.json)
declares 64 batches for each of three hash functions, 20 candidates per batch and
1024 ASCII characters per candidate. Both modes therefore verify 3,840 candidate/function
evaluations and publish three complete hash-to-candidate-ID lookup tables. Each finding
contains the function address, dictionary identity/generation parameters and every resolved
target hash with its matching candidate IDs. An ID `seed/part/batch/index` identifies the
corresponding input dictionary entry unambiguously; a digest is additional integrity evidence.
For this version, its ASCII bytes are the ID followed by `/`, padded to the declared
length with the character `a + ((index + batch) % 26)`. The published dictionary
descriptor and candidate ID therefore reconstruct the matched input without an internal
tool database or an opaque digest lookup.
Candidates, target hashes and oracle results match within each serial/parallel pair.

The first attempted full run was cancelled during BS-21 after identifying that its
digest-only publication did not deliver the usable lookup findings. Its partial logs and
measurements remain retained as non-acceptance development evidence. The lookup-table
publication/readback fix was verified by restarting the complete run; it does not change the task volume
or paired timing criterion.

An initial lookup-table run used three separate publications in parallel mode. Its
second prepared pair failed the acceleration criterion: 233.41 seconds serial versus
279.78 seconds parallel (first pair: 236.24 versus 236.01). These measurements remain
failed evidence, not acceptance pairs for the revised strategy. The native computation
was faster in parallel; separate publications consumed the gain. The revised protocol
keeps the same computation volume, repetition count and criterion, and explicitly changes
coordination to one lead publication using existing public CLI operations.

The serial mode completes all three parts with one CLI actor/Ghidra worker; the parallel
mode gives one part to each of three independent actors/workers. In both modes the lead
reads all producers' saved findings through the CLI. In parallel mode it copies the two
other producers' complete tables into its context and explicitly merges the combined
result once. Source contexts and private snapshots remain retained. Collection, copying,
publication and verification all remain inside the task clock. A fresh session validates
all three published findings. Digest equality checks equivalent results across modes.
The process observer verifies distinct owned native PIDs, overlapping work intervals and
CPU-time growth in all three processes during a common active interval.

Prepared-base trials begin after import, context readiness and a short separate warmup
that uses no measured candidates. The measured clock includes dispatch, CLI calls,
emulation, local findings, coordination, every merge and fresh-session verification.
Setup, research and completion durations are recorded separately. No sleep or artificial
wait is included in the executable's research workload.

BS-23 runs six paired trials, alternating `[1,3]` and `[3,1]`. Every pair must have a
correct equivalent result and `T3 < T1`. Under the paired-sign null model, six wins have
one-sided probability `1/64`; the predeclared comparison requires less than 0.05. There
is no 1.5x margin. All trials are retained; failures fail the run without automatic
exclusion or replacement. Fixing code requires a new complete acceptance run.

BS-24 uses fresh product profiles and canonical imports, with unflushed OS/tool/compiler
caches explicitly disclosed. It reports cold end-to-end times without requiring a speedup.
BS-25 uses an uneven `[128,32,32]` partition of the same total batch count and reports
the measured scaling outcome, including any slowdown.

Development calibration used eight batches per part and 12 candidates per batch. It observed about 54.5 seconds
serial versus 74.8 seconds parallel: faster research did not compensate for extra
publication costs at that small task size. That pilot used an earlier artifact and is
retained as calibration, not counted among the six acceptance pairs. The acceptance
workload/protocol is frozen before its full run. Acceleration claims apply only to that
declared workload and environment.

## Reproduction

Prepare Node 24+, .NET SDK 10, the pinned private Automation submodule and ordinary npm
dependencies as in [Automation setup](ACCEPTANCE-AUTOMATION.md). Native business acceptance
targets local macOS with Ghidra 12.1.2, Java 21 and Clang/LLD; it does not run in ordinary CI.
Use only explicitly authorized disposable fixtures. The suite requires the ordinary
insight-cli IPC owner to be idle/stopped before setup and never stops unrelated work.

```sh
npm run build
INSIGHT_NATIVE_DISPOSABLE=1 \
INSIGHT_JAVA=/absolute/path/to/java \
INSIGHT_GHIDRA_HOME=/absolute/path/to/ghidra \
INSIGHT_CLANG=/absolute/path/to/clang \
INSIGHT_LLD=/absolute/path/to/lld-link \
npm run test:business
```

The suite packs and installs the current CLI in an isolated directory, builds the corpus,
creates a unique profile and runs all 25 scenarios. Allow enough time for repeated native
trials. Gherkin selection for development retains its narrower scope:

```sh
npm run test:business -- --tag BS-03
npm run test:business -- --filter 'TestCategory!=performance'
```

Each invocation prints its owned diagnostics directory. `manifest.json` records private
local paths, tool versions, machine resources, input and package identity. Automation
retains TRX, per-scenario receipts and CLI transcripts. Performance scenarios additionally
retain the frozen protocol, every trial, CPU/overlap observations, raw timings and paired
comparison. The outer suite accepts a full run only with all 25 distinct IDs passed,
one artifact, unchanged inputs and successful owned-resource cleanup. Publish only
sanitized evidence; private manifests and raw local logs remain outside Git.
