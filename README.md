# insight-cli

Agent-facing CLI/API for durable research sessions and isolated Ghidra contexts. Targets and
sessions live above tool namespaces; an agent uses `insight-cli ghidra ...` with explicit session
and target identifiers. The service owns processes, routing, saved views and publication mechanics.
Agents choose the investigation and interpret results.

The agreed **M0–M5 delivery is implemented and verified**: all 210 pinned operations and eight
bridge-control equivalents map to 215 public leaves. The [combined acceptance report](docs/verification/full-facade.json)
records 93 passing offline tests, 23 passing native groups, the installed CLI/IPC/OS-keyring crash
matrix and the exact tested source/artifact hashes. [Coverage evidence](docs/verification/coverage-evidence.json)
joins each inventoried operation to its command/equivalent and verification group.

Native acceptance targets macOS/Ghidra 12.1.2/Java 21. It includes two simultaneous GUI/LLDB
contexts, retained trace/mapping recovery, explicit merge/refresh and seven owner SIGKILL phases.
Native Windows/Linux acceptance, automatic strategies, universal native DB merging, external
archive-service deployment and npm publication remain outside this pass. See
[design](docs/DESIGN.md), [scenarios](docs/CLI-SCENARIOS.md) and [milestones](docs/PLAN.md).

Use Node 24 or newer:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
node skills/ghidra-coordinator/dist/src/bin.js --help
node skills/ghidra-coordinator/dist/src/bin.js skill
```

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
privately before `applied`; they do not publish themselves. Optional request IDs identify original
changing intentions and return their result or unresolved state without repeating effects.

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
require explicit runtime/compiler paths and `--ack-disposable`, refuse CI and use only owned
fixtures. Native acceptance targets macOS; native Windows/Linux acceptance is deferred.
[Verification](docs/verification/README.md) distinguishes each proof's scope and remaining gates.

The earlier `insight-ghidra` coordinator remains an internal regression fixture. Its
[historical findings contract](docs/prototype-findings.md) and separate journals are not migrated
into root sessions or exposed as public worker/proposal commands. Existing RE environments are
not adopted or modified by the facade.
