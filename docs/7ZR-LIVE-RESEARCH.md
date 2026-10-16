# Live agent research on 7zr.exe

**Repeatable acceleration is not confirmed.** On 2026-10-16, three completed prepared-base
pairs produced 1.475x, 1.609x and 0.971x speedups for three actual AI agents/Ghidra contexts
versus one. All six completed research runs passed content verification after merge.
The third pair was slower with three agents. The next three-agent attempt failed during
merge when the host ran out of disk space. The six-pair protocol therefore did not pass.

The separate cold comparison passed correctness: **415.24 s with one agent versus
328.11 s with three**, or 1.266x for this one pair. These observations do not establish a
general reasoning-speed benefit or attribute the benefit to Ghidra alone.

[Machine-readable evidence](verification/7zr-live-research.json) contains exact timings,
phase costs, verified findings, worker observations, the frozen protocol and 419 source hashes.
This experiment is separate from the [25 business scenarios](BUSINESS-ACCEPTANCE.md): their
controlled hash-research workload previously achieved 1.601x. That number does not describe
live AI research on this production executable.

## The same useful task in both modes

Input: production `7zr.exe`, 7-Zip 26.04 x86, 602,624 bytes, SHA-256
`256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282`.
The retained input came from the [official download](https://www.7-zip.org/a/7zr.exe);
the hash identifies the experiment because that download URL can change. The target was
statically analyzed and never executed.

The question was to explain three user-visible failure/security paths in the stripped binary
and publish an evidence-backed navigation guide in the shared database:

| Part | Initial clue | Required answer |
| --- | --- | --- |
| Switch parsing | `Unknown switch:` | Recognition, longest-name selection, duplicate and malformed-postfix rejection |
| Password input | `Enter password (will not be echoed):` | Prompt, console echo handling, restoration, termination and failures |
| Extraction diagnostics | `CRC Failed` | Numeric result mapping and encrypted-file/password suspicion |

One fresh agent investigated all three parts in order in one private context. Three fresh
agents each investigated one part in distinct contexts of the same target. They received the
same part questions, used the installed public CLI, and saved structured private comments.
No timed agent received addresses, source code, previous answers or the correctness oracle.

The lead read the actual comments through CLI, copied the other agents' findings into its
context, and merged **once in both modes**. A fresh session then verified all three published
comments, actual clue strings and xref chains, and every quoted decompiled-code fragment.
The verifier removed C comments before matching quotations, so the new annotations could
not act as their own code evidence. An independent semantic review checked business coverage.
Different fact counts and prose were allowed; missing required behavior was not.

## Prepared-base results

Each run used a fresh profile, imported/analyzed R1 and one or three ready contexts before
starting its task clock. No task-specific searches or decompilation were precomputed.
The monotonic clock included dispatch, AI inference, tools, collection, merge, fresh-reader
verification and semantic review. Final resource cleanup was outside the clock.

| Pair | Order | One agent, s | Three agents, s | T1 / T3 | Content |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | 1 → 3 | 332.42 | 225.36 | 1.475x | Both passed |
| 2 | 3 → 1 | 331.07 | 205.75 | 1.609x | Both passed |
| 3 | 1 → 3 | 315.74 | 325.33 | **0.971x** | Both passed |
| 4 | 3 first | Not run | Merge failed | No result | Three private findings retained |
| 5–6 | Not run | — | — | — | Unexecuted |

The median **observed** paired speedup is 1.475x, range 0.971–1.609x. It is descriptive
of the three completed pairs. The frozen requirement was six correct pairs with T3 < T1
in every pair; it already failed at pair 3. The prepared series stopped after pair 4's
disk failure. The slower pair and failed attempt remain in the evidence; neither was
replaced. No six-of-six result or 1/64 significance claim is made.

| Run | Research, s | Collect, s | Merge, s | Fresh verification, s | Semantic review, s |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pair 1 / one | 274.10 | 1.55 | 16.57 | 28.56 | 11.64 |
| Pair 1 / three | 148.33 | 6.66 | 17.91 | 38.95 | 13.51 |
| Pair 2 / one | 267.63 | 1.27 | 16.22 | 22.87 | 23.10 |
| Pair 2 / three | 138.91 | 5.85 | 15.46 | 23.84 | 21.69 |
| Pair 3 / one | 260.75 | 1.15 | 15.21 | 20.13 | 18.50 |
| Pair 3 / three | 241.70 | 16.16 | 23.98 | 26.58 | 16.91 |

In pair 3, a longer password investigation reduced the research benefit to about 19 s;
collection/publication/verification costs consumed that saving. This illustrates the effect
of the longest assignment and coordination costs on this small task. It does not identify
provider latency versus reasoning time; those components are not exposed separately.

The completed parallel runs had three distinct native PIDs and project-root identities.
Their agent research windows overlapped for 82.56, 51.14 and 67.75 s respectively. CPU time
grew for every native worker inside each common window. This verifies active independent
workers and overlapping investigations, without claiming every native call ran simultaneously.

## Cold startup, reported separately

Cold here means a new profile, new native processes and first import. Software was already
installed; profile configuration was outside the clock. OS/tool/provider caches were not
flushed. It is not a machine-reboot or cache-empty measurement.

| Phase | One agent, s | Three agents, s |
| --- | ---: | ---: |
| First open to all contexts ready | 58.65 | 80.47 |
| Ready-to-dispatch orchestration | 10.56 | 6.70 |
| Agent research | 288.49 | 165.85 |
| Collection | 1.30 | 6.31 |
| Merge | 15.88 | 17.85 |
| Fresh verification | 24.36 | 39.18 |
| Semantic review | 15.99 | 11.74 |
| **Total** | **415.24** | **328.11** |

All three findings reached R2 and passed fresh-session verification in both runs.
The cold triple also passed distinct-worker, CPU-growth and overlap checks. Its 1.266x
ratio is a single observation with no cold speedup gate or statistical significance claim.

## Useful published findings

The evidence retains the complete representative three-agent records from pair 1, including
addresses, actual string/reference hops, literal code quotations and limitations:

* **`0x40125a`, switch parser.** A nonempty wide-character argument must start with `-`.
  Matching starts after that prefix; helper `0x402576` folds ASCII case and the descriptor
  search keeps the longest matching name. Descriptor bytes control duplicates, minimum
  postfix length and kind-specific validation. Unknown, repeated, too-short, too-long and
  incorrect postfix diagnostics are distinct. Source-level names and descriptor types
  remain inferred.
* **`0x43f4f5`, password acquisition.** The prompt is conditional and flushed. The code
  obtains standard input, checks handle/mode calls, and attempts to clear console bit `0x4`.
  Reading continues even if this fails. On normal return it restores the saved mode only
  when disabling echo succeeded; it ignores restoration's result. The reader accepts
  newline/EOF termination and returns false for NUL. Caller `0x43f4b1` exposes distinct
  error/abort values. This is not proof of guaranteed no-echo input, exception-safe
  restoration, memory erasure or encryption strength.
* **`0x436fea`, extraction diagnostics.** Results 1/2/3 map to unsupported method/data error/CRC
  failure. For 2 and 3, a nonzero second argument selects encrypted-file text asking
  `Wrong password?`; zero selects the plain error. Case 9 separately reports wrong password.
  The formatter prefixes `ERROR:` and uses a numeric fallback for unmapped results. A CRC
  string is reached through a data pointer slot and then a code reference; the verifier
  checks both hops. The flag's recovered type and source-level meaning remain qualified.

The hidden oracle was frozen before timing and cross-checked against official tag 26.04:
[parser](https://github.com/ip7z/7zip/blob/26.04/CPP/Common/CommandLineParser.cpp),
[input](https://github.com/ip7z/7zip/blob/26.04/CPP/7zip/UI/Console/UserInputUtils.cpp),
[diagnostics](https://github.com/ip7z/7zip/blob/26.04/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp)
and [result enum](https://github.com/ip7z/7zip/blob/26.04/CPP/7zip/Archive/IArchive.h).
Source hashes are recorded in the evidence. Timed agents did not use these files.

## Disk failure and retained recovery state

In `pair-4-3`, all three agents saved findings and the lead collected them. The native
publisher then threw `java.io.IOException: No space left on device` while opening the
packed snapshot after recording publication intent. CLI reported `coordinator.authorization`;
session status exposed three pending changes and an unknown merge. Public history showed
only R1 before and after a scoped `ghidra open` recovery attempt. Recovery remained blocked.
History alone was not used to declare the effect safely aborted.

No merge was retried and no profile/journal was reset. Diagnostics were saved, and only
already-closed disposable copies from completed trials were removed to free space.
The failed publication's journal, database and private snapshots remain retained. The two
ordinary contexts closed publicly; the lead's close was blocked by its unresolved operation.
Its process subsequently ended through ordinary owner cleanup. No experiment-owned native
processes remain, and no global IPC-owner stop was used.

This is an operational gap: an ENOSPC failure before an established check-in can leave the
lane safely blocked without an automatically proven abort. Resource preflight and a verified
negative-outcome recovery path deserve follow-up; deleting the journal or blindly repeating
publication would invalidate the safety contract. This run does not claim that gap is fixed.

## Identity, reproduction and limits

The installed CLI artifact SHA-256 is
`cd7b9e2be2c7ea1b18ba2f2a270eab44b3d08cc30629c1afd6ed118b6bdc3504`,
built from source `0ee655ade6fd30f4411e0ff7e5ab8ec3c0915a7f`. Host: Apple M5,
10 logical CPUs, 16 GiB, macOS/Darwin 25.6.0, Node 24.21.0, Java 21.0.11, Ghidra 12.1.2.
The artifact, executable, frozen oracle, dispatch template and all 419 source/runtime/harness
hashes were unchanged after the experiment. Product code was not changed for these results.

[Protocol](../scripts/live-research/protocol.json), [agent instructions](../scripts/live-research/AGENT-TASK.md),
[controller](../scripts/live-research/control.mjs) and [observer](../scripts/live-research/observer.mjs)
retain the test-side workflow. With a package manifest from the existing business pack/setup,
an explicit disposable macOS environment and the exact input, the controller sequence is:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/live-research/control.mjs init <run-dir> <package-manifest> <7zr.exe>
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/live-research/control.mjs trial <run-dir> <trial-name> <1-or-3> <prepared-or-cold>
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/live-research/control.mjs start <trial.json>
# Dispatch fresh live agents with the instructions and assigned part(s); they call/submit.
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/live-research/control.mjs collect <trial.json>
# Independently review semantic coverage and record criteria/explanation in review.json.
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/live-research/control.mjs finish <trial.json> <review.json>
```

This is an orchestrated live-agent experiment, not an unattended npm/Gherkin timing test.
Prepare assignments before the prepared clock, start immediately before dispatch, and keep
human/reviewer delay inside the clock. On failure retain transcripts and inspect public
status/history; do not blindly rerun `collect`. Cold trials start timing before first open.
Ensure sufficient free space before starting and retire completed disposable copies between
future experiments; resource failures remain reportable failures.

All agents used `fork_turns=none`, inherited the same parent configuration and had no
model/reasoning overrides. Exact deployment model ID and token usage were unavailable.
Provider caches were opaque. Isolation from answers/source was instructional. The serial
baseline explicitly handled parts sequentially, so this does not compare against the best
possible single-agent batching. Concurrent AI inference and native worker count changed
together. These limits preclude a universal or Ghidra-only acceleration claim.

The post-run offline suite passed **129/129**; harness syntax checks passed. Native results
above came from the unchanged installed artifact, independently of those offline tests.
Raw prompts, CLI transcripts and runtime data remain private; portable evidence omits
personal paths and credentials. The failed state is retained for subsequent recovery work.
