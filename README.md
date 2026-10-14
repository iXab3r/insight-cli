# insight-cli

**Implementation in progress:** the agreed public CLI is `insight-cli`, with shared `targets` and `sessions`
and tool branches such as `ghidra`. Each tool owns its working contexts and shared analysis
models. See the [agreed model](docs/DESIGN.md#agreed-product-model). The draft implementation
below is the earlier `insight-ghidra` publication prototype. Durable session/target storage and
managed native context/server mechanisms now have their
[foundation evidence](docs/verification/README.md); the public command transition and combined
facade acceptance remain in progress. [Work items](docs/WORK-ITEMS.md) record exact checkpoints.
The [agent walkthroughs](docs/CLI-SCENARIOS.md) record the intended commands and responses;
the [milestone plan](docs/PLAN.md) separates that contract from the existing implementation and
defines observable completion criteria. Those examples are not commands available in the prototype.
The owner selected one full M0–M5 pass, explicit merge/refresh, managed local startup plus external
server profiles, and GUI/debugger support on demand. The [pinned coverage ledger](docs/GHIDRA-COVERAGE.md)
accounts for 210 GhidraMCP operations and eight bridge controls. Native acceptance targets macOS;
CLI/CI portability remains required. The new facade is accepted only after combined full delivery.

Agent-oriented TypeScript CLIs and matching skills built on AI CLI Factory. The first executable,
`insight-ghidra`, coordinates independent Ghidra readers and durable scoped-comment proposals.
Its canonical source and installed skill live together under `skills/ghidra-coordinator`.

Use Node 24 or newer:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
node skills/ghidra-coordinator/dist/src/bin.js --help
node skills/ghidra-coordinator/dist/src/bin.js skill
```

Factory supplies help, human/JSON output, profiles, OS credentials, permission gates, JSON-RPC
and a shared IPC owner. Update permission starts disabled. The CLI stores its journal, worker
projects and retained stages below the selected profile's AppData; installation contains no user
state. Investigators use server-enforced read-only accounts. Only the coordinator receives the
publisher account and private bridge token.

Read the [installed workflow](skills/ghidra-coordinator/SKILL.md), [setup](skills/ghidra-coordinator/references/setup.md)
and [recovery contract](skills/ghidra-coordinator/references/recovery.md). Commands include
`targets register/list/show`, `workers start/list/stop`, `inspect`, `findings submit/list/show`,
`integrate`, `status` and `recover`. Native database merging, types/signatures and automatic
semantic conflict resolution are outside this version. Separate MCP calls form a retained stage;
there is no atomic multi-call or exactly-once guarantee.

Build prepared artifacts with `npm run pack:cli`. Until a separately authorized IPC npm release,
install the CLI tarball **together with** the prepared official Factory IPC tarball:

```sh
npm install ./vendor/factory-ipc-a2094fb.tgz ./artifacts/ixab3r-insight-ghidra-0.1.0.tgz
```

The published Core dependency is pinned to 0.4.1. [IPC provenance](vendor/provenance.json)
records its Factory source commit and artifact SHA256; [Factory PR #51](https://github.com/iXab3r/EyeAuras.CliFactory/pull/51)
implements reusable external package identity. This repository contains a prepared upstream
package, with its license, rather than another IPC host. Neither package has been published to npm
as part of this change. Installing the CLI does not register a skill or rewrite agent settings.

Default tests and the isolated package proof run offline after dependency acquisition. Actual
Ghidra writes are a separate local-only [disposable acceptance runner](scripts/acceptance-ghidra.mjs),
which refuses CI and requires `--ack-disposable` plus explicit external runtime paths. Add
`--faults` to exercise native owner crashes. It creates its own server, synthetic PE files and
temporary keyring namespace. Existing RE environments are not test fixtures.

See [design](docs/DESIGN.md), [contribution guidance](CONTRIBUTING.md) and
[verification scope](docs/verification/README.md). Source delivery is tracked by
[Factory #49](https://github.com/iXab3r/EyeAuras.CliFactory/issues/49).
