# insight-cli

Agent-facing CLI/API for durable research sessions and isolated Ghidra contexts. Targets and
sessions live above tool namespaces; an agent uses `insight-cli ghidra ...` with explicit session
and target identifiers. The service owns processes, routing, saved views and publication mechanics.
Agents choose the investigation and interpret results.

The package includes an [RE workflow skill](skills/ghidra-coordinator/skills/insight-re/SKILL.md)
for multiple agents, Ghidra and ordinary external tools. Locate it with
`insight-cli skill insight-re`. Keep useful outputs and short findings as ordinary files;
`insight-cli artifacts save ./research --json` retains a file or folder and returns a
browsable saved path. It uses the profile's Update permission and needs no Ghidra/Java.
The [save contract](skills/ghidra-coordinator/references/artifacts.md) covers stable folders,
independent copies and receipts. Installing the package does not register either skill.
The [real 7zr.exe workflow](docs/RE-SKILL.md) records three agents, two isolated Ghidra
contexts, external utilities, reviewed findings, merge/refresh and saved-copy verification.

The [RE-skill comparison on 7zr.exe](docs/7ZR-RE-SKILL-BENCHMARK.md) completes three
prepared-base live-agent pairs with useful findings, one merge and fresh verification:
**1.516x median full-task speedup** (1.419–1.528x). Two original baselines restored their
prepared contexts after owner idle shutdown; a separate continuously warm-process pair
passes at **1.640x**. Its detailed wall-time breakdown distinguishes research, handoff,
publication and acceptance, with retained errors and CPU-observation limits.
[Evidence](docs/verification/7zr-re-skill-benchmark.json) retains all eight runs.

The [live-agent 7zr.exe comparison](docs/7ZR-LIVE-RESEARCH.md) does **not confirm repeatable
acceleration**: prepared pairs achieved 1.475x, 1.609x and 0.971x; the next attempt hit a
disk-full merge failure. The separate cold pair achieved 1.266x. Real findings were merged
and verified from fresh sessions in all completed runs; the failed publication remains
retained without a retry. [Evidence](docs/verification/7zr-live-research.json) includes every
attempt and the unexecuted remainder of the planned series.
The [time analysis](docs/7ZR-TIME-ANALYSIS.md) accounts for agent critical paths, CLI latency,
serial publication/verification and experiment overhead, with concrete optimization priorities.

The [25 business Gherkin scenarios](docs/BUSINESS-ACCEPTANCE.md) pass through the installed
public CLI on real Ghidra, covering two EXEs, private contexts, merge/refresh, conflicts
and interrupted work. On their controlled fixture workload, six prepared-base
one-versus-three worker pairs all improve, with
**1.60x median paired speedup** on the declared hash-research workload. Cold start (1.33x)
and uneven work (1.23x) are measured separately. [Evidence](docs/verification/business-scenarios.json)
binds exact artifacts, source/input hashes, findings, worker overlap and raw timings.

The [real-EXE agent walkthrough](docs/AGENT-CLI-WALKTHROUGH.md) follows an official `7zr.exe`
through installed public CLI commands: strings, xrefs, decompilation, private annotations,
merge and another agent's refresh. It records the resulting import timeout/diagnostic fixes
and focused verification separately from the earlier combined gate below.
The subsequent [first-import recovery](docs/INITIAL-IMPORT-RECOVERY.md) continues interrupted
analysis/publication in the original profile using verified staging and conditional promotion.

The agreed **M0–M5 delivery and selected P0–P3 additions pass combined acceptance**. The current
tree has 272 public command leaves; all 210 pinned operations and eight bridge-control equivalents
remain accounted for. The [earlier combined report](docs/verification/full-facade-current.json) records
118 passing offline tests and 33 native groups on its unchanged build, with the exact source and
installed artifact hashes. The installed CLI/Factory IPC/OS-keyring scenario exercises two agents,
two EXEs, four private contexts, parallel callers and nine actual owner SIGKILL phases.

The [SDK → MCP → facade comparison](docs/gaps_api_ghidra.md) records the selected P0–P3 contracts
and limits. They include bounded native analysis and typed reads/edits, Version Tracking,
FID/BSim, GDT, loaders/exporters, live/trace operations and managed ready-built extensions.
Opt-in publication after edit/save and refresh before edit use the same conflict/recovery rules;
manual merge/refresh remains the default. See the installed
[native workflows](skills/ghidra-coordinator/references/native-workflows.md) and
[extensions/synchronization reference](skills/ghidra-coordinator/references/extensions-and-sync.md).

[Reproduce the combined gate](docs/FINAL-ACCEPTANCE.md). Native combined acceptance targets macOS,
Ghidra 12.1.2 and Java 21, including simultaneous GUI/LLDB contexts. The
[P2 report](docs/verification/api-gaps-p2.json) retains its separate selected headless Windows/Linux
identity; it does not imply current full GUI/P3 acceptance on those OSes. The
[original M0–M5 report](docs/verification/full-facade.json) and individual P0–P3 reports retain their
historical identities. Universal native DB merging and external archive-service deployment
remain outside the selected functional delivery. See [design](docs/DESIGN.md),
[scenarios](docs/CLI-SCENARIOS.md) and [milestones](docs/PLAN.md).

Install the CLI with Node 24 or newer:

```sh
npm install --global @eyeauras/insight-cli
insight-cli --help
insight-cli skill insight-re
```

The executable is `insight-cli`; npm's global executable directory must be on PATH. No source
checkout or build is needed. The pinned official IPC tarball is fetched automatically from an
immutable GitHub URL; installation needs registry and GitHub access. Java/Ghidra are configured
separately for native analysis. See [npm distribution](docs/NPM-RELEASE.md).

For development:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
node skills/ghidra-coordinator/dist/src/bin.js --help
node skills/ghidra-coordinator/dist/src/bin.js skill
```

[Gherkin acceptance](docs/ACCEPTANCE-AUTOMATION.md) connects the pinned
EyeAuras.Automation runner to existing offline and native integration checks. Its
development setup requires .NET 10 and access to the private Automation dependency;
`npm run test:acceptance` selects the offline Gherkin smoke scenarios. The
[25 business scenarios](docs/BUSINESS-SCENARIOS.md) have individual executable Gherkin
workflows, including required acceleration on a prepared base and separate cold-start
measurements. `npm run test:business` runs their installed public-CLI/native gate;
[business acceptance](docs/BUSINESS-ACCEPTANCE.md) records the passing native gate, protocol and measurement limits.

The canonical npm helper and its progressive skill live in `skills/ghidra-coordinator`; the npm
package is `@eyeauras/insight-cli`, with executable `insight-cli`. Factory supplies one command tree
for help, human/JSON output and `cli.execute`, plus profiles, OS credentials, permissions and shared
IPC ownership. Update permission starts disabled. All mutable state derives from profile AppData.

Configure Java 21 and Ghidra 12.1.2 as described in
[setup](skills/ghidra-coordinator/references/setup.md). Omit `server` for managed local startup;
an external server profile uses explicit repository and distinct reader/publisher accounts.

```sh
insight-cli ghidra open ./client.exe --session new --json
insight-cli ghidra strings search --session <session> --target <target> --contains config.json --json
insight-cli ghidra functions get --session <session> --target <target> --address <address> --json
insight-cli sessions status <session> --target <target> --json
```

Opening returns the actual session/target to retain. Another agent opens with `--session new`
to receive an independent view of the same input. Read the [workflow skill](skills/ghidra-coordinator/SKILL.md),
[research guide](skills/ghidra-coordinator/references/research.md) and
[continuation contract](skills/ghidra-coordinator/references/recovery.md). Ordinary edits are saved
privately before `applied`; with the default manual policy they await explicit merge. Optional
request IDs identify original changing intentions and return their result or unresolved state
without repeating effects.

The manual [Release npm workflow](https://github.com/iXab3r/insight-cli/actions/workflows/release-npm.yml)
provides the same build checks, an archive/receipt artifact and optional registry publication.
See [release setup and re-runs](docs/RELEASE-CI.md).

Build prepared artifacts with `npm run pack:cli`. The tarball also installs by itself:

```sh
npm install --global ./artifacts/eyeauras-insight-cli-0.2.0.tgz
```

The IPC dependency uses the recorded immutable tarball URL, so no separate dependency archive
is supplied by the caller. The local vendor copy remains a provenance/offline mirror.

Core is pinned to 0.4.1. [IPC provenance](vendor/provenance.json) records Factory source, license and
artifact hash; [Factory PR #51](https://github.com/iXab3r/EyeAuras.CliFactory/pull/51) implements
reusable external package identity. The installed helper needs no Factory source checkout.
Installing it does not register a skill or rewrite agent settings.

Default tests and isolated package tests are offline after dependency acquisition. Native runners
require explicit runtime/compiler paths and `--ack-disposable` and use only owned
fixtures. The [combined gate](docs/FINAL-ACCEPTANCE.md) runs locally on macOS; selected headless
Windows/Linux P2 workflows have separate explicitly enabled native CI evidence.
[Verification](docs/verification/README.md) distinguishes each proof's scope and remaining gates.

The earlier `insight-ghidra` coordinator remains an internal regression fixture. Its
[historical findings contract](docs/prototype-findings.md) and separate journals are not migrated
into root sessions or exposed as public worker/proposal commands. Existing RE environments are
not adopted or modified by the facade.

Managed Ghidra delivery: [runtime commands and ownership](skills/ghidra-coordinator/references/managed-runtime.md).
Version 0.2.0 is published on npm as `latest`. The manual release workflow passes build,
OIDC publication and a fresh registry global installation; the archive matches the native-tested
candidate byte for byte. See [release verification](docs/verification/npm-release-0.2.0.json).
