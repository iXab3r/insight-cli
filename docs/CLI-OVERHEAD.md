# Short CLI latency: matched one-shot and persistent transports

Measured on 2026-10-20 against the unchanged isolated BB-07 development package. Persistent
JSON-RPC removes about 0.7 seconds per short invocation on this host. Across the identical
72-command workload, measured request time fell from **61.60 s to 10.57 s (5.83×)**.
This investigation adds reproducible benchmark tooling and evidence; the fixes below are proposed.
The subsequent [persistent/inspect implementation](PERSISTENT-INSPECT.md) records the approved
client and native-observation repair, final installed checks and a new counterbalanced comparison.
The [machine-readable report](verification/cli-overhead.json) retains all 144 measured latencies,
result hashes, quantiles, artifact identity, control measurements and limits.

## Matched experiment

| Operation | One-shot p50 / p95 | Persistent p50 / p95 |
| --- | ---: | ---: |
| `ghidra memory read`, 32 bytes | 716 / 873 ms | 25.8 / 34.2 ms |
| `ghidra functions inspect`, `main`, `entry_point` only | 1023 / 1342 ms | 375 / 540 ms |
| `sessions status`, one context | 735 / 994 ms | 3.49 / 5.59 ms |

Each route ran the same three argv vectors 24 times, alternating AB/BA and reversing operation
order each round. Nearest-rank p95 has only 24 samples per cell; it is a description of this run.
One warmup of every operation/route and the persistent connection handshake were excluded.
First persistent connection through an already warm owner took 701 ms (one sample).

Both routes used the same immutable installed package, cwd, isolated profile, Factory owner,
native process and saved context. The input was a generated x86-64 PE exporting `main`, imported
with `--no-analysis`. Native reads and field bounds were identical. The full result JSON hash
matched on every repetition, including across transports. Context generation, snapshot, request
journal, input bytes and process records remained unchanged. Cleanup closed the owned context,
server, persistent connection and Factory owner; private journals/transcripts remain retained.

The public fixture helper keeps a second, quiescent JSON-RPC connection open. This deliberately
holds owner lifetime constant in both arms; no competing commands ran on that connection during
measurement. Factory's default idle policy and the native 768 MiB heap were unchanged.

The parent Node runner uses a monotonic clock from spawn to process close for one-shot, and
from request write to a complete response line for persistent. Reading spans and writing
benchmark transcripts happen outside these intervals. Agent/tool/reviewer latency is excluded.
OS caches were warm; the shared machine's CPU and other applications were not isolated.

## Observed delay boundaries

| Existing span / boundary, p50 | Memory one-shot / persistent | Inspect one-shot / persistent |
| --- | ---: | ---: |
| Full facade handler | 22.6 / 22.0 ms | 366 / 371 ms |
| Native HTTP union within handler | 18.9 / 18.4 ms | 354 / 361 ms |
| Outside facade handler | 693 / 3.33 ms | 659 / 3.58 ms |
| First stdout chunk to process close | 5.18 / n/a ms | 5.45 / n/a ms |

Native HTTP, backend, context-open and normalization are nested/overlapping observations. Do not
add them to the handler or to one another. Likewise, quantiles do not add. `context.open` on this
warm path verifies the existing process/program; it does not imply a fresh JVM. Its p50 was
about 10–11 ms. Facade queue p95 was below 0.02 ms; inspect normalization p95 below 0.10 ms.

The residual outside the handler includes Factory parsing/profile work, client startup, package
validation, IPC, serialization and awaited facade telemetry append. Baseline instrumentation
does not split those boundaries. In particular, the 3–4 ms persistent residual is **not** a
measurement of IPC alone.

An additional cost remains inside compact inspection. Every inspected call made **27 native
HTTP requests**: six each to instance info, schema, program options and metadata; two inline
scripts; and one `/get_functions`. The before/after `backend.observation` checks call logical
`/research_view` through the trusted native-query script path. Those two `/run_script_inline`
requests together had p50 **293 ms one-shot / 311 ms persistent**. `/get_functions` itself had
p50 **1.79 / 1.87 ms**. These are observed transport durations; they do not separately time Java
compilation, loading or execution. View checks enforce the continuation consistency contract and
must be preserved when optimizing this path.

Memory reads made nine HTTP requests: two sets of those four verification requests plus one
`/read_memory`; the data read itself had p50 1.59 / 1.70 ms. Redundant verification is measurable
even after removing the repeated frontend startup cost.

## Separate diagnostic controls

These controls ran after the matched workload, 12 fresh processes per case, with the exact same
installed bytes. They are diagnostic controls, not additional spans of the baseline requests.

| Control | p50 | p95 |
| --- | ---: | ---: |
| Bare Node process, minimal JSON output, no fixture preload | 28.1 ms | 33.5 ms |
| Same process with Factory AppArguments isolation preload | 42.6 ms | 48.0 ms |
| Local `tools show ghidra`, complete normal CLI process | 139 ms | 158 ms |
| Exact exported Factory `readPackageBuildManifest` | 463 ms | 863 ms |
| Remaining IPC/facade module imports after preload, diagnostic entry | 68.3 ms | 137 ms |
| `createDefinition` / `createCli` / classify one owner command | 6.72 / 1.49 / 8.66 ms | 9.49 / 3.30 / 14.3 ms |

The normal bin eagerly imports IPC and the complete facade. Factory `runHosted` creates the
definition and local parser, classifies the command, and resolves the packaged build before
connecting to the owner. Package resolution validates the package's declared artifact files and
recursively reads the deployed dependency graph, including complete dependency package trees.
Every new frontend repeats that operation. A connected `--json-rpc` invocation resolves the
build once for its streaming lifetime and reuses the established owner invocation.

A separate filesystem-traced validation control recorded **6100 file opens, 6116 reads,
863 directory scans and 47,560,080 returned bytes** in the exact validation interval. Opens
are not a count of unique paths. Tracing increased that control to 946 ms; it and the separate
CPU-profiled process are excluded from the 12 uninstrumented controls and matched latency data.
The CPU sample included substantial idle/async filesystem wait, file open/close/stat operations,
path handling and hashing; it does not establish physical disk latency or a pure hashing cost.

The 463 ms validation control is a strong optimization candidate within the roughly 700 ms
one-shot residual. It cannot be subtracted from another run's median to derive an IPC duration.
The local metadata control already costs 139 ms without owner/build validation. Process exit
after output is only about 5 ms, and the existing isolation preload adds roughly 15 ms in its
own control. Neither explains the much larger repeated validation cost.

## Proposed repair order

1. **Use the existing persistent frontend for agent research loops.** Keep one child process,
   its stdin and a request-ID map alive across calls. The existing `cli.execute` contract already
   supports this; reconnect is a new transport, and uncertain writes keep their existing journal
   recovery semantics. Acceptance: rerun this exact harness, identical results and recovery
   behavior, no extra owner/JVM restarts. This is the fastest immediately available improvement.

2. **Add Factory-owned timing boundaries before changing its compatibility checks.** Instrument
   definition/import readiness, classification, artifact/dependency validation, owner status/
   startup, relay setup, queue, profile/permission resolution, execute and output completion.
   Correlate one request across client and owner using IDs; measure durations on each local
   monotonic clock, without subtracting unsynchronized clock origins. A diagnostic observer
   belongs upstream in Factory. No copied host, second IPC implementation or payload logging.

3. **Optimize packaged build validation upstream in Factory.** Current full recursive validation
   is the first one-shot target. First test lower-risk improvements that preserve the byte-level
   guarantee: bounded parallel reads, fewer repeated filesystem/path operations and hashing the
   same deployed file once per validation. Benchmark wall time and CPU/memory/open-file limits.
   A persistent verified-install receipt could remove more work, but needs an explicit deployment
   and invalidation contract. A cache based only on package version/mtime/TTL does not preserve
   detection of arbitrary in-place edits. Mutable/dev installs must retain full validation unless
   a trustworthy immutable generation is established. Cover dependency/optional/peer changes,
   relocation, symlinks, same-size edits with restored mtime, stale owners and interrupted updates.

4. **Make view observation cheap while retaining before/after checks.** The two script-based view
   reads dominate persistent compact inspection. Propose a typed precompiled native bridge method
   for the existing modification/language/compiler observation, then consolidate duplicate binding
   verification within one ordered command where the identity guarantees permit it. Check process
   replacement, program replacement, modification during reads, GUI edits and changed continuation
   views. A new native bridge surface requires a separately agreed request/response example.

5. **Reduce frontend eager imports and parser work after measuring the new boundary spans.**
   Keep the full command schema/help in Factory's parser, defer heavy adapter implementations to
   their handlers, and preserve local metadata routing. Do not implement an argv dispatcher here.
   The 139 ms complete local control suggests a smaller opportunity than graph validation.

Suggested performance gates are p50 outside-handler below 200 ms for warm-owner one-shot reads,
and no more than 10% regression in the paired persistent workload. These are targets to validate,
not predicted gains. Keep cold owner startup, first import, first native helper execution and warm
requests as separate distributions. Recheck the same frozen artifact/workload after each change.

For discussion before any native surface expansion, the narrow view-method candidate is an
authenticated ReadOnly `GET /research_view?program=/fixture.exe` returning the same logical facts
currently obtained through a script:

```json
{"modification":"42","language":"x86:LE:64:default","compiler":"windows"}
```

The facade would still attach its verified process incarnation and keep observations on both
sides of the inspected read. Existing CLI arguments and `view.identity` semantics remain the
intended contract. This endpoint is a proposal, not an available native HTTP method in this build.
It needs capability/version negotiation and failure behavior agreed before implementation.

Existing transport example (no API expansion): start `insight-cli --json-rpc` once and send:

```json
{"jsonrpc":"2.0","id":1,"method":"cli.execute","params":{"argv":["ghidra","memory","read","--session","S","--target","T","--address","0x140001000","--length","32"]}}
{"jsonrpc":"2.0","id":2,"method":"cli.execute","params":{"argv":["sessions","status","S","--target","T"]}}
```

Read each corresponding `result` or typed `error` envelope; keep the process for subsequent
commands. This experiment deliberately compared complete CLI processes with individual requests
on an already connected stream. It does not claim an individual persistent connection starts
in 3 ms, nor that holding only the IPC owner removes frontend validation costs.

## Reproduction and scope

```sh
node scripts/benchmark-cli-overhead.mjs --ack-disposable \
  --package <frozen-installed-package> --root <new-absolute-fixture-directory> \
  --java <jdk>/bin/java --ghidra-home <ghidra> --rounds 24
```

The benchmark saves private `result.json`, progress, spans and cleanup receipts under the selected
fixture directory. To reproduce diagnostic parts, save one owner-routed argv vector from its
`workload` to an ordinary JSON file, then run fresh processes with the retained isolation preload:

```sh
node --import <fixture-directory>/fixture-environment.mjs \
  scripts/probe-cli-startup.mjs <frozen-installed-package> <argv-json-file>
```

The diagnostic calls Factory's own exported build API and `classify`; it does not execute the
selected research command or start another host. Its dynamic import grouping differs from the
normal bin, so component numbers remain controls. The prior RE agent benchmark's multi-second
outer residual also included Python/tool orchestration and different inputs/work. Comparing it
directly with this pure-process measurement would falsely attribute a benchmark-method change
to a product speedup. No production API, idle policy, Factory source or installed package was
changed for this investigation.
