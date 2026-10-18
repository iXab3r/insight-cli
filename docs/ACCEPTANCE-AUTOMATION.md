# Gherkin acceptance with EyeAuras.Automation

The test runner is [EyeAuras.Automation](https://github.com/iXab3r/EyeAuras.Automation),
pinned as a Git submodule at `b9fdfd6ea11feb8d88fd4cbe6a98ab0f24aca033`.
English Gherkin + Reqnroll 3.3.4 + NUnit 4 run through its workspace runner and
process sentinel. Product bindings belong to this repository. Automation supplies
process ownership, deadlines, logs and cleanup; insight-cli retains its existing CLI,
Factory lifecycle and native acceptance assertions.

The [25 business scenarios and acceptance criteria](BUSINESS-SCENARIOS.md) now have
five executable feature files and product-specific public-CLI bindings. Run them with
`npm run test:business`; [business acceptance](BUSINESS-ACCEPTANCE.md) describes the
corpus, interruption points, frozen benchmark protocol and passing 25/25 native result
with six-of-six prepared-base improvements (1.60x median paired speedup). The
older technical bridge features remain a separate supporting layer.

[Connection evidence](verification/automation-bootstrap.json) records two passing offline
scenarios, the real installed multi-agent native scenario, four-scenario discovery and
rejection of an empty selection on macOS ARM64. The full 33-group bridge was discovered
but not executed in this connection check. That connection check also passed the then-existing 128 offline tests. Current discovery
finds 31 scenarios: 25 business workflows, four technical bridges, managed runtime delivery
and the combined shared tool runtime scenario.

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
| `npm run test:business` | 25 separate `@business @native` scenarios, BS-01–BS-25, including six paired prepared-base comparisons | Installed public CLI, ordinary Factory IPC/keyring, owned real Ghidra workers and versioned PE fixtures |
| `npm run test:acceptance` | Two `@offline @technical` scenarios: isolated npm package/CLI/IPC and existing session CLI integration tests | Session tests use a fake Ghidra backend; package check uses its existing isolated Factory test setup |
| `npm run test:acceptance:native` | One `@native @facade` scenario: installed multi-agent CLI/IPC, two EXEs/four contexts, merge/refresh/conflicts and owner/server restart | Real Ghidra; synthetic EXEs and existing test-only isolated identity |
| `npm run test:acceptance:full` | One `@native @full` bridge to the unchanged 33-group combined gate, including its fault phases and artifact/source checks | Full macOS GUI/keyring prerequisites; each original runner still owns its native fixtures |

The existing first-import production-EXE runner remains separate. BS-17 independently
exercises that business outcome using the controlled PE corpus and only public CLI
continuation. The older technical features still select their original JavaScript
runners. Business features instead select individual agent workflows, with assertions
in test-side JavaScript and scoped C# bindings. No native tests were replaced with mocks.

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

The [agreed hierarchy](BUSINESS-SCENARIOS.md) covers one EXE, several EXEs, collaboration
through independent CLIs, interrupted investigations and shared-task throughput. It owns
the stable BS-01–BS-25 IDs and business acceptance criteria. Technical recovery fault
matrices remain a supporting integration layer.

Acceleration is **required on the prepared base** (BS-23). Cold-start time is measured
separately (BS-24), with no required cold-start speedup. No numeric margin such as 1.5x
has been agreed. Freeze the concrete workload and comparison protocol before measurement.

**A shorter test run alone does not prove that three Ghidra instances accelerate research.**
The comparative acceptance must establish all of the following:

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
assume linear scaling or generalize to all investigations. The concrete workload uses
three real executable hash functions and publishes complete hash-to-candidate lookup
findings. See the [business acceptance protocol and results](BUSINESS-ACCEPTANCE.md);
its prepared-base gate, cold measurements and uneven-partition measurements remain distinct.

## Managed runtime delivery

`ManagedRuntime.feature` adds a separate opt-in `@runtime` scenario. Its public global-CLI
runner is `scripts/proof-managed-runtime.mjs`, covering fresh acquisition without configured
Java/Ghidra, native decompilation/server checks, two-agent real 7zr.exe publication/refresh,
live-process deletion guards, local archives, reinstall continuation and an external launcher.
It requires `INSIGHT_GLOBAL_CLI`, `INSIGHT_RUNTIME_EXE` (the exact static 7zr fixture) and
`INSIGHT_EXTERNAL_GHIDRA` (actual external launcher), and `INSIGHT_GHIDRA_ARCHIVE` (official pinned
12.1.2 zip, to verify macOS native supplementation and GUI/debugger operation). The installed CLI must match the built
candidate; installation itself is an explicit development/release step. This scenario downloads
public runtime artifacts and is not part of offline CI or the historical 25 business IDs.

## Shared tool runtime gate

`SharedToolRuntime.feature` adds `@tool-runtime`, separate from the historical business IDs.
Its runner `scripts/proof-tool-runtime.mjs` first runs the complete existing managed-Ghidra
public global-CLI gate, then verifies parallel clients, atomic conflicts/refresh, authenticated
owner replacement, generic process stop/kill and server failure with saved private work.
The same profile then performs real ILSpy C#/IL/type/resource/project/metadata research,
parallel CLI reads, ordinary-file saving, offline/local archive reinstall, external executable
selection and uninstall while retaining both tools' targets and evidence.

In addition to the managed runtime variables above, supply `INSIGHT_MANAGED_ASSEMBLY`,
`INSIGHT_ILSPY_ARCHIVE` and `INSIGHT_DOTNET_ARCHIVE`. Build the versioned fixture with
`dotnet build tests/acceptance/fixtures/managed/ResearchFixture.csproj -c Release -o /absolute/output`.
Use a disposable output path outside the source tree. This SDK is required only to prepare
acceptance input; installed ILSpy supplies its own runtime and does not require an SDK.
The native runner clears global Java/Ghidra/.NET selectors and uses a PATH without a global
`dotnet`. Run the selection with `npm run automation -- test --suite acceptance --tag tool-runtime
--property RestoreLockedMode=true --timeout-seconds 3600`. Every named assertion must pass;
a successful process exit without completed research/cleanup is insufficient.

[Shared tool runtime acceptance](verification/tool-runtime.json) records the passing exact
packed/global-installed macOS candidate and all named research/recovery/removal checks.

## Toolbox development gates

`Toolbox.feature` adds five separately selected native scenarios: actual Codex bundle
metadata connect/disconnect, a globally installed public 7-Zip container workflow, and
LLVM investigation of owned PE/PDB, ELF and Mach-O images, plus live managed
stack/heap/trace research and DiE classification with explicit scan uncertainty. Run

```sh
INSIGHT_NATIVE_DISPOSABLE=1 INSIGHT_TOOLBOX_MANIFEST=... npm run automation -- test \
  --suite acceptance --tag toolbox --property RestoreLockedMode=true --timeout-seconds 1200
```
The private JSON manifest supplies `packageRoot`, `sevenzipArchive`, `sevenzipExecutable` and `container` for the
owned two-entry fixture; `llvmArchive` and `nativeSubjects` select the LLVM archive and
owned image directory. Prepare those images with `scripts/toolbox/prepare-native-inputs.mjs`
and explicit Clang/lld-link/ld.lld paths (a maintainer fixture prerequisite, not a user SDK).
`diagnosticsArchives`, `dotnetArchive` and `managedWorker` select the three retained NuGet
archives, the private runtime archive and a maintainer-built owned console fixture. Build
`tests/acceptance/fixtures/diagnostics/Probe.csproj` into a disposable output directory.
`dieArchive` selects the reviewed console/Qt archive for header and signature triage of those inputs.
The acceptance project excludes fixture source and nested build output from its own assembly.
The driver creates a separate profile and test-only short temporary
AppData root, so long Automation artifact paths cannot exceed the Unix socket path limit.
No ordinary user profile or installed tool is reset. All five scenarios passed together (5/5) on the recorded DiE candidate; an earlier runner-path failure was corrected
in the fixture setup. LLVM verifies each advertised family, the hexadecimal type index,
output limits/overwrite refusal and external sibling drift/preservation. Managed diagnostics
verify the waiting stack, real heap/object/field/root evidence, a two-second thread-time
trace, readable Speedscope export, preserved external target lifetime and retained licenses.
DiE verifies native/managed headers, .NET signatures, explicit partial results on actual upstream
script errors, pagination, output preservation and external database drift. The first five-case
run failed only DiE doctor: canonicalizing framework symlink targets fixed staging relocation.
Its regression still rejects changed bytes and links escaping owned installation storage.

These are native developer gates, not independent model acceptance. The
[managed agent evidence](verification/toolbox-agent-managed.json) separately records cold
and prepared independent cheap-model static research, exact resource/checkpoint readback,
and the earlier IPC-blocked trials that were rejected. Per-tool family coverage and the
final exact-artifact whole-toolbox gate remain open. A successful model exit or plausible
report does not count without evidence review: the first container trial omitted a real
configuration field despite correct recovered bytes, and required a correction pass.

The macOS `ghidra-debugger` selection adds an installed public-CLI GUI/LLDB case. Its private
manifest supplies `packageRoot`, `ghidraHome`, `java` and `ghidraDebuggerWorker`. Prepare the
short-lived, source-unavailable native worker with `prepare-native-agent-fixture.mjs` and use
its `fast` executable; the source fixture is `fixtures/toolbox/debugger-fast.c`. It requires no
sleep or interactive subject. The case stops at entry, maps a function, sets a breakpoint
before resuming, checks actual argument/return registers, closes/reopens the same context and
compares disconnected trace registers, memory and mapping. It also checks launch request replay,
checkpoint bytes, actual session IDs and terminal public debugger process inventory. Run it
with the ordinary acceptance runner and `--tag ghidra-debugger`. The two opt-in owner fault
tests remain separate from this real Ghidra GUI case.

The actual standalone [Codex host trials](verification/toolbox-agent-host.json) also passed
cold/prepared container research with the same business-only prompt. Project startup metadata
supplied the skill list; the prompt did not identify a tool or a command sequence. Keep the
runtime selected by that CLI consistent with its shared owner. Prestarting an owner from an
operator's different Node can create a deliberate compatibility rejection.

For new tool cases, `scripts/toolbox/run-agent.mjs MANIFEST` launches the real opt-in model
trial with `INSIGHT_NATIVE_DISPOSABLE=1 INSIGHT_RUN_AGENT_EVAL=1`. The private manifest supplies
absolute `packageRoot`, `project`, `preload`, `outputDirectory` and frozen package `artifact`,
project-relative `inputs`, a business-only `prompt`, and the explicitly chosen `model` and
`reasoningEffort`. `path` may select the candidate global prefix. Prepare only disposable
profile storage and a project bundle link, using `public-fixture.mjs` as the test-side seam;
existing project instructions remain authoritative. Use a new output directory per attempt.

The runner records package/build/skill/input/prompt identities, raw private events, final
answer, time/exit state and owned-owner shutdown. Its successful terminal state is
`needs_review`. Independently verify the useful answer, recovered bytes, saved checkpoint
and tool-specific process cleanup before writing an acceptance receipt. It does not make
model calls in default CI or turn a zero exit code into a business verdict. The actual
source-runner smoke was reviewed against the owned oracle and exact saved bytes; its final
prose omitted checkpoint locators, so that small handoff limitation is retained in the receipt.

Native toolbox CI checks out the private Automation repository at the exact pinned
submodule commit using the repository secret `AUTOMATION_READ_KEY`. Its deploy key
grants read-only access to Automation, is not persisted into test runtime configuration,
and is not available to fork pull requests. The framework remains private; it is not
copied into this repository's package or tool Releases.


The TShark native gate is independently selectable with `--tag tshark`. Prepare its
private manifest with `INSIGHT_NATIVE_DISPOSABLE=1 node scripts/toolbox/prepare-tshark-fixture.mjs
OUTPUT GLOBAL_PACKAGE_ROOT [SOURCE_BUNDLE] [RUNTIME_ARCHIVE]`. Without local archives it
fetches the pinned assets from our immutable Release. It verifies the runtime/source hashes,
extracts the public HTTP fixture only from the matching original Wireshark source and retains
its GPL text. Set `INSIGHT_TOOLBOX_MANIFEST=OUTPUT/manifest.json` and run the ordinary
Automation command above with `--tag tshark`. No live traffic or system capture settings
are involved. [Receipt](verification/toolbox-tshark.json) records the final installed build.
The current TShark addition passed this scenario on its committed globally installed
artifact. The complete Node 24 offline suite is 201 tests (199 passed, two explicit
opt-in skips), and release/admission checks are 29/29. Offline process fixtures require
permission to authenticate their own PIDs/listen on their own loopback sockets; a denied
native identity read remains unverified rather than being weakened into a pass.

### Large-assembly bounded discovery fixture

The C06 `overview` native case also requires `largeManagedAssembly` in the private
`INSIGHT_TOOLBOX_MANIFEST`. Produce that assembly with
`scripts/toolbox/prepare-overview-agent-fixture.mjs` into disposable storage and pass its
returned `assembly` path. The maintainer producer requires the pinned .NET SDK; the
installed CLI needs only its managed runtime. The fixture contains 1001 methods, including
one business method under a namespace shared by unrelated helpers. The public CLI test
checks full-signature collisions, case-insensitive `--name-filter` selection, exact-token
member decompilation without the whole class, and existing ILSpy/Ghidra text windows.
Do not supply producer source or PDBs to independent research agents.
