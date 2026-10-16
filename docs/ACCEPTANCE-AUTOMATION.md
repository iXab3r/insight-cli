# Gherkin acceptance with EyeAuras.Automation

The test runner is [EyeAuras.Automation](https://github.com/iXab3r/EyeAuras.Automation),
pinned as a Git submodule at `b9fdfd6ea11feb8d88fd4cbe6a98ab0f24aca033`.
English Gherkin + Reqnroll 3.3.4 + NUnit 4 run through its workspace runner and
process sentinel. Product bindings belong to this repository. Automation supplies
process ownership, deadlines, logs and cleanup; insight-cli retains its existing CLI,
Factory lifecycle and native acceptance assertions.

This is the connection and migration foundation. The agreed next step is to design
a hierarchy of 20–30 business scenarios together. The technical bridge features below
do not substitute for that hierarchy and do not claim to cover it.

[Connection evidence](verification/automation-bootstrap.json) records two passing offline
scenarios, the real installed multi-agent native scenario, four-scenario discovery and
rejection of an empty selection on macOS ARM64. The full 33-group bridge was discovered
but not executed in this connection check. The existing 128 offline tests also pass.

## Setup and commands

Node 24+, .NET SDK 10 and authenticated read access to the private Automation repo
are required for this development suite. Normal installation/use of insight-cli does
not require .NET or the submodule. Its libraries target net8; our host/tests target
net10 and use the root SDK selection. NuGet dependencies have committed lockfiles.

```sh
git submodule update --init tests/vendor/EyeAuras.Automation
npm ci --ignore-scripts
npm run build
npm run automation -- list --suite acceptance
npm run test:acceptance
```

The bootstrap is a thin consumer of `AutomationCli.RunAsync`. Each invocation builds
the host into a different ignored directory, so it cannot rebuild another live sentinel.
The shared runner builds the test project into its own per-run directory. Restore
uses locked dependencies; dependency updates require an explicit unlocked restore
and lockfile review. Acquisition may need network; offline scenario execution does
not require Ghidra or access to the upstream repository after setup.

| Selection | Current behavior | Boundary |
| --- | --- | --- |
| `npm run test:acceptance` | Two `@offline @technical` scenarios: isolated npm package/CLI/IPC and existing session CLI integration tests | Session tests use a fake Ghidra backend; package check uses its existing isolated Factory test setup |
| `npm run test:acceptance:native` | One `@native @facade` scenario: installed multi-agent CLI/IPC, two EXEs/four contexts, merge/refresh/conflicts and owner/server restart | Real Ghidra; synthetic EXEs and existing test-only isolated identity |
| `npm run test:acceptance:full` | One `@native @full` bridge to the unchanged 33-group combined gate, including its fault phases and artifact/source checks | Full macOS GUI/keyring prerequisites; each original runner still owns its native fixtures |

The existing first-import production-EXE runner remains separate. It has not yet been
translated into individual Gherkin business scenarios. The same is true of assertions
inside the other bridged scripts: Gherkin currently selects those runners; their checks
remain in JavaScript. No native tests were replaced with mocked acceptance.

Native invocation requires explicit disposable-fixture authorization and tool paths:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 \
INSIGHT_JAVA=/absolute/path/to/java \
INSIGHT_GHIDRA_HOME=/absolute/path/to/ghidra \
INSIGHT_CLANG=/absolute/path/to/clang \
INSIGHT_LLD=/absolute/path/to/lld-link \
npm run test:acceptance:native
```

The complete gate uses the same variables with `npm run test:acceptance:full`.
Native selections fail when authorization/prerequisites are absent. Empty selections,
all-skipped runs and missing TRX evidence cannot produce a passing Automation run.
The default npm test command remains the existing offline suite.

## Results and CI

Each `.automation/results/acceptance/<run-id>/` retains `tests.trx`, the runner's
`run.json`, bounded command logs and per-scenario `scenario.json`, `timing.json` and
`command-timing.json`. NUnit/TRX includes individual scenario duration. Our monotonic
command duration includes subprocess startup and teardown; scenario duration includes
steps and scenario cleanup. Runner build/restore time is separate from those measurements.
Failed executions remain failures even when process cleanup succeeds.

Automation is private while insight-cli is public. The separate
[`gherkin-integration` workflow](../.github/workflows/acceptance.yml) is manually dispatched
and requires a repository secret `AUTOMATION_READ_TOKEN` with read-only Contents access
to `iXab3r/EyeAuras.Automation`. It checks out the exact gitlink commit and uploads selected
receipts/TRX only, excluding dependency assemblies and build trees. This integration does
not create a token, publish private source, or claim an automatically running Gherkin CI
gate. Existing push/PR offline CI remains independent of that private dependency.

## Business hierarchy and parallel throughput

The next design pass should organize scenarios by an agent's outcome: investigate one
EXE through one CLI; cooperate through two CLIs on the same EXE; work on several EXEs;
retain findings through conflict and interruption; finish a shared investigation with
three workers. Assertions should check discoveries and the accepted shared result through
the public CLI. Technical recovery fault matrices remain a supporting integration layer.

**A shorter test run alone does not prove that three Ghidra instances accelerate research.**
The planned comparative acceptance must establish all of the following:

1. One fixed, versioned EXE/task and deterministic expected findings. Serial and parallel
   runs perform the same total useful work and produce the same verified shared result.
2. A serial baseline with one Ghidra versus three independent, simultaneously active native
   Ghidra processes working on complementary parts of that same task. Three CLI processes
   alone are insufficient. PID/context evidence must establish actual concurrent execution.
3. A monotonic end-to-end wall time, from task start until all required findings are merged
   and independently readable. Count coordination, refresh, publication, conflicts/retries
   and worker failure; also report setup/import and investigation phases separately.
4. Separate cold-start and already-prepared measurements. Fixed versions, machine/resources,
   analysis settings and cache policy; alternate/randomize run order and retain every trial.
5. Repeated paired measurements, a declared repetition count and acceptance threshold before
   measuring, raw timings and variability. Report `speedup = T1 / T3` and efficiency
   `T1 / (3 * T3)`. A failed or incomplete trial cannot count as a faster success.

The parallel case must demonstrate a repeatable improvement on the agreed workload, not
assume linear scaling or generalize to all investigations. Current timing receipts prepare
measurement collection; neither a comparative workload nor a demonstrated speedup exists yet.
