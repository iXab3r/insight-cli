# Toolkit benchmark repairs

This work follows a private static-RE comparison. Reproductions here use generated, disposable
fixtures only. Private inputs, addresses, observations and research reports do not belong in
this repository. This is a repair checkpoint, not a completed rerun or a performance claim.

## Existing behavior fixes

**BB-01 — filtered function inspection.** The pinned native bulk endpoint always returns basic
name/size metadata but filters `entry_point` with the requested fields. The adapter incorrectly
required it even for `--fields decompiled_code,callees`. Inspection now permits its omission
only when an explicit field selection excludes it. Default/full inspection, explicitly requested
entry points, and simple get/decompile keep strict address validation. An unexpected malformed
entry point still fails. Per-item outcomes, field filtering, Unicode windows, hashes, view guards,
owner-host saves and existing single/bulk exit semantics remain intact.

The public proof reproduced `invalid_native_shape` on installed 0.3.2 while direct decompile
succeeded. The separately packed candidate passed single and mixed batch reads, a real call edge,
continuation, JSON-RPC and saved manifest/hash checks. The candidate is a development artifact;
the repository package version is not a production release declaration.

**BB-03 — scan discoverability.** Generated help and validation errors now state the existing
1–200000 visited-input scan bound. Result offsets skip matching rows rather than continuing
coverage. Help explains the defined-string scope and points to the existing initialized-memory
byte search for undefined literals. No new cursor, scan semantics or automatic analysis is added.

**BB-06 — missing-function recovery.** Missing definitions suggest the existing bounded
`functions decode` with explicit session/target and address. The message distinguishes read-only
instruction decoding from defining functions, listing instructions or xrefs. Native diagnostics
remain separately retained and bounded.

Validation on 2026-10-20: the full offline suite passed 253 tests with four declared skips;
all 31 release tests passed. The isolated packed-install test passed. Native acceptance passed
the filtered inspection checks above, incomplete-zero/late-defined-string behavior, undefined
literal byte search, and unseeded instruction recovery with unchanged context identity and no
new function definition. The input digest remained unchanged and owned cleanup succeeded.
The two process-identity supervisor tests require OS process inspection; the restricted sandbox
denied that inspection, and the full suite was rerun with that access before recording success.

Run the opt-in native proof against an isolated installed package:

```sh
node scripts/proof-filtered-inspection.mjs \
  --cli <installed-package>/dist/src/bin.js \
  --java <jdk>/bin/java --ghidra-home <ghidra> \
  --root <fresh-short-absolute-directory> --ack-disposable
```

`--expect-broken` checks the historical inspection failure instead. The proof uses the same
test-only Factory AppArguments storage seam as the existing public toolbox fixture. It generates
a PE with two exported functions and a call edge; all program writes are confined to that fixture.
It retains command receipts and closes its own context, server and isolated IPC owner. Initial
open/analysis timings are setup costs, not matched warm-query performance measurements.

## Approved diagnostic extension

The owner approved this plan on 2026-10-20 after discussion and concrete examples. The commands
and internal measurements below are implemented; bounds are specified in the research reference.

**BB-02 — navigation diagnostic.** The ReadOnly command:

```sh
insight-cli ghidra analysis navigation --session S --target T --max-scan 10000
```

It reports the original import policy separately from current observed metadata. Bounded
function/body/instruction/reference/defined-string samples expose coverage and limits; a
one-byte-body-heavy sample can produce a `sparse-metadata` assessment. Example fragment:

```json
{
  "initialAnalysis": "none",
  "functions": {"sampled": 128, "oneByteBodies": 121},
  "scan": {"complete": false},
  "assessment": "sparse-metadata"
}
```

An analysis request/flag is provenance, not proof that every analyzer succeeded. Imported GZF
contents may have unknown prior provenance. A complete diagnostic scan cannot prove semantic
completeness. Neither this read nor `ready` should silently start expensive analysis.

**BB-04 — controlled timing.** Existing facade integration boundaries now have
correlated internal spans, without recording request payloads, code, credentials or personal
paths. A fixed workload must declare cold/restored/warm state and use the same saved fixture.
Report facade queue/open/native/validation/save boundaries actually observed. Client startup and
IPC cannot be inferred by subtracting unrelated spans: their separate spans require an upstream
Factory integration hook. Do not copy Factory ownership, add a second IPC host or optimize an
unmeasured presumed bottleneck. A public trace flag/schema would need an explicit further example.

**BB-05 — lifecycle diagnostic.** The ReadOnly, non-starting command:

```sh
insight-cli ghidra diagnostics lifecycle --session S --target T
```

The facade retains bounded start/restore/stop events with time and reason, scoped by context. Reasons describe
what the facade actually knows: explicit close, view replacement, owner disposal, failed startup,
or unknown. Existing receipts without a reason stay unknown. The current Factory host default
idle timeout is 60000 ms; its shutdown disposes the facade, which stops authenticated native
children. This establishes a possible mechanism, not the cause of historical PID changes.
The Factory public dispose callback currently does not identify the host shutdown cause, so
`owner_dispose` must not be falsely called `idle_timeout`. Keep the idle policy unchanged until
controlled measurements justify a separately agreed change.

## Repeat benchmark gate

Finish the agreed repairs and installed native checks before dispatching two fresh agents. Use
one shared task with only tool-routing differences, identical input and saved analysis state,
and verify per-agent tool exposure before GO. Keep all failed attempts and setup time, measure
the same phases, compare evidence quality and unresolved questions, and disclose any analysis,
toolchain or workload differences. Do not give either fresh agent the earlier research answers.

## Diagnostic validation and measured limits

The [generic native proof](verification/benchmark-toolkit-repairs.json) passed analyzed and
seeded/no-analysis navigation, common work-budget exhaustion, non-starting lifecycle reads,
explicit close, saved-snapshot restoration and actual owner disposal after a 70-second idle
control. It verified nested correlated spans and unchanged fixture input bytes. No historical
stop cause was reconstructed from that experiment.

Across the nine fixed-workload calls, warm navigation took about 0.73–0.87 seconds externally
and 0.18–0.28 seconds inside the facade handler. Around 0.55 seconds remained outside the
observed handler boundary; startup/IPC/response cannot be split without Factory hooks. Native
HTTP dominated measured handler time; adapter normalization and queues were negligible in this
uncontended control. No IPC rewrite, lifecycle retention change or hypothetical speedup is
claimed. The next upstream timing hook is still a separate contract decision.

The later [matched short-call experiment](CLI-OVERHEAD.md) compares one-shot with an existing
persistent JSON-RPC frontend on identical disposable reads. It adds exact outer/handler timing,
separate Factory validation controls and a proposed repair order; these controls do not replace
the still-missing cross-process Factory boundary spans.

The approved [persistent client and fast inspect observations](PERSISTENT-INSPECT.md) are
implemented and verified separately, including installed headless/GUI fixtures and the same
counterbalanced read workload. Factory itself remains unchanged.

## BB-08 follow-up: existing sparse-navigation route

The owner prioritized sparse navigation before the proposed script-stage diagnostics. No new
command, flag, result field or scanner was added. The packaged Ghidra entry point now branches
to a [sparse-navigation recipe](../skills/ghidra-coordinator/references/sparse-navigation.md).
Generated help, existing decompiler-failure guidance and navigation recommendations distinguish
known function entries, executable bytes without entries, and undefined literals.
Batch inspection preserves its facade recovery message alongside the separate bounded native
diagnostic instead of replacing the next step with only the native failure text; CLI/RPC agree.

Try compact `functions inspect --fields decompiled_code,callees` at known entries first.
Use existing `force-decompile --function <entry>` when a fresh native decompiler pass is needed,
and bounded `decode` when no function entry exists. A transient decompile does not populate
Listing instructions or stored xrefs. Undefined literals use initialized-memory byte search
with explicit `next_address` continuation. The recipe preserves upstream work-limit warnings
and does not infer a complete call graph from missing xrefs or local decode.

The [installed native proof](verification/sparse-navigation.json) used a generated no-analysis
x86-64 PE and a separately created disposable block. With Update revoked, a compact batch
returned both function bodies, cache refresh succeeded at an existing entry, an absent entry
remained absent, bounded decode recovered its local instructions, and a byte-search continuation
found an undefined literal beyond its first window. Listing remained empty. Saved snapshot,
context generation, request count and input digest were unchanged; owned cleanup passed.
The test uses the existing test-only Factory AppData seam, not another product IPC host.

Run it against an isolated installed package:

```sh
node scripts/proof-sparse-navigation.mjs \
  --package <installed-package-root> --java <jdk>/bin/java \
  --ghidra-home <ghidra> --root <fresh-short-absolute-directory> --ack-disposable
```

This validates a route already supported by the CLI; it is not a measured agent speedup or a
whole-program sparse-code-reference scanner. BB-07 and the proposed constrained code-reference
API remain separate decisions. No production release or new agent benchmark is implied.

## BB-07 — Java inline compile/load diagnostics

The owner approved and the [installed fixture proof](verification/inline-scripts.json) verifies
the narrow V1. The existing Update-gated `ghidra scripts run-inline` now uses a facade-owned
compiled executor. A fixed trusted shim uses the existing native transport; user source is
compiled in a fresh attempt directory with annotation processing disabled. No Factory core,
IPC host or upstream JAR was replaced. Class resolution is non-initializing, with an explicit
user-code barrier before initialization and construction.

Native facts are read from a versioned receipt bound to the attempt, request and source hash,
after the executor acknowledgement. User console text cannot supply that proof. Compiler and
console capture each retain at most32KiB before UTF-8 decoding, with explicit truncation;
structured diagnostics retain at most100 entries with individually bounded messages and
source-line mapping where possible. Attempts and failed sources stay in profile analysis storage.

A compile/load rejection proven before user code starts becomes a terminal failed request and
returns a nonzero `rejected` result with `contextState: ready`. It neither saves a new program
snapshot nor changes the existing pending work. Same-ID retries return that failure; a changed
source needs a new ID. Initialization/constructor/runtime failures and lost/malformed replies
remain unknown even when `run()` was never entered. This is not a general script sandbox or a
rule for clearing historical unknown attempts from their error strings.

The generated sparse-PE reproduction of `getFunctionBefore(currentAddress)` returns
`coordinator.script.compile`, `cannot find symbol`, and `sourceLine: 1`. Snapshot/generation
remain unchanged, the request is failed, status stays ready, and the next navigation read works.
The12 public native checks also cover non-initializing load rejection, missing default
constructor, diagnostic overflow, same-ID replay, fresh classes, imports/args, initialization,
construction and runtime sentinel writes, and console-proof spoofing. A separate real lost-reply
test retains unknown with exactly one native dispatch despite an existing compile receipt.
All fixture workers/servers were stopped and journals preserved; public-fixture cleanup passed.

Final validation:264 offline tests passed with4 declared skips,19 focused tests passed,
31 release checks passed, and isolated offline package install/relocation passed. Earlier
fixture-runner errors and restricted/concurrent test failures are retained as limits in the proof;
the final stable sequential run passed. This is a development candidate, not registry publication.

```sh
node scripts/proof-inline-scripts.mjs \
  --package <isolated-installed-package> --java <jdk>/bin/java \
  --ghidra-home <ghidra> --root <fresh-absolute-directory> --ack-disposable
node scripts/proof-inline-loss.mjs \
  --package <isolated-installed-package> --java <jdk>/bin/java \
  --ghidra-home <ghidra> --root <another-fresh-directory> --ack-disposable
```
