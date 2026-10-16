# insight-cli

Agent-facing CLI/API for durable research sessions and isolated Ghidra contexts. Targets and
sessions live above tool namespaces; an agent uses `insight-cli ghidra ...` with explicit session
and target identifiers. The service owns processes, routing, saved views and publication mechanics.
Agents choose the investigation and interpret results.

The [real-EXE agent walkthrough](docs/AGENT-CLI-WALKTHROUGH.md) follows an official `7zr.exe`
through installed public CLI commands: strings, xrefs, decompilation, private annotations,
merge and another agent's refresh. It records the resulting import timeout/diagnostic fixes
and focused verification separately from the earlier combined gate below.
The subsequent [first-import recovery](docs/INITIAL-IMPORT-RECOVERY.md) continues interrupted
analysis/publication in the original profile using verified staging and conditional promotion.

The agreed **M0–M5 delivery and selected P0–P3 additions pass combined acceptance**. The current
tree has 271 public command leaves; all 210 pinned operations and eight bridge-control equivalents
remain accounted for. The [current report](docs/verification/full-facade-current.json) records
118 passing offline tests and 33 native groups on one unchanged build, with the exact source and
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
historical identities. Universal native DB merging, external archive-service deployment and npm
publication remain outside the selected delivery. See [design](docs/DESIGN.md),
[scenarios](docs/CLI-SCENARIOS.md) and [milestones](docs/PLAN.md).

Use Node 24 or newer:

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
`npm run test:acceptance` selects the offline Gherkin smoke scenarios. The business
scenario hierarchy and a measured one-versus-three Ghidra comparison are the next design step.

The canonical npm helper and its progressive skill live in `skills/ghidra-coordinator`; the npm
package is `@ixab3r/insight-cli`, with executable `insight-cli`. Factory supplies one command tree
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

Build prepared artifacts with `npm run pack:cli`. Until a separately authorized IPC npm release,
install the CLI tarball together with the prepared official Factory IPC tarball:

```sh
npm install ./vendor/factory-ipc-a2094fb.tgz ./artifacts/ixab3r-insight-cli-0.1.0.tgz
```

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
