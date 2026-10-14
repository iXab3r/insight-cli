# insight-cli design

One public agent repository ships real TypeScript/Node CLIs and version-matched skills. Each
executable helper has one canonical source under `skills/<product>` as an npm workspace.
No speculative product packages are generated. Factory 0.4.1 supplies the command tree, output,
profiles, keyring, permissions and RPC. Reusable IPC/package identity is implemented in Factory
under its issue #50, as agreed with the owner in #49; no product-specific host exists here.

## Ownership

Stable applicationId insight-ghidra selects the Factory owner. Package-scoped artifact and
installed-runtime fingerprints reject incompatible builds. The same definition serves help,
human/JSON and JSON-RPC. Profile AppData owns SQLite/WAL, worker receipts, stages/backups/logs.
Passwords and per-publisher bridge tokens are injected from Factory secrets into owned process
environments, never profile JSON. Publisher HTTP/UDS endpoints require that private token; status
returns only a secret-key reference. Reader processes receive no publisher credential or token.
Readers and publisher use distinct server accounts. Investigator CLI operations expose inspection
and proposal submission only. Ghidra Server ACLs must restrict readers; advisory locks do not
prevent direct writes made with a separate privileged account under the same OS identity.

## Commands and permissions

| Leaf | Gate |
| --- | --- |
| targets register | Update |
| targets list/show | ReadOnly |
| workers start/stop | Update |
| workers list | ReadOnly |
| inspect | ReadOnly |
| findings submit | Update |
| findings list/show | ReadOnly |
| integrate/recover | Update |
| status | ReadOnly |
| skill (local builtin) | no service prerequisites |

Update defaults off. Factory owns standard configuration/auth/permission commands. Handlers return
values; unsuccessful integration throws CliError with the retained batch as result. Partial,
conflicting and uncertain outcomes are failures across every output transport. Querying that
batch is a successful read. There is no implicit grant, secret fallback or runtime data override.

## Durable comment lane

Immutable target identity includes profile/server/repository/program/SHA/language/compiler/base.
The lane key is profile/server/repository/program. A unique target per lane prevents cross-build
transfer. Independent actual PID/endpoint/project/path/SHA bindings identify each worker.
Unique request/finding IDs and canonical content hashes provide idempotent durable submission.
SQLite WAL/FULL and transactions persist acceptance and every state transition. A partial unique
index prevents another active batch for a target, including unresolved/failed publication stages.
In-memory per-lane tasks share an executing call within the elected Factory owner; different
programs may publish concurrently. Existing acknowledged proposals are never silently dropped.

Fresh exclusive checkout -> all before-value/baseline checks -> all comments applied and read back
-> save -> persisted check-in intent -> check-in with batch marker -> history + new independent
reader + checkout-release proof -> published_verified. Conflicts retain both proposals and current
values; fresh proposals explicitly reference the quarantined finding. Native DB merging is not
performed. Multiple calls are a recoverable stage, not an atomic transaction.

After persisted intent, any failure/kill leaves an uncertain lane. Recovery reads history/readback
and never replays check-in. A live prior PID blocks recovery without TTL expiry; PID reuse fails
conservatively. Pre-intent abandonment requires stopped identified writer, retained stage backup
and verified checkout release. Cleanup never terminates every checkout or kills by port/basename.
Profile invalidation must preserve unresolved journals rather than deleting AppData underneath work.

## Verification and distribution

Default CI executes only synthetic/offline boundaries; npm dependency acquisition is a separate
setup step. Unit fault injection proves state semantics; actual process kill tests prove durable
SQLite recovery. Real Ghidra write acceptance is a separate local-only disposable-fixture runner,
not Factory's ReadOnly service proof and not CI. Report limits at the tested revision/environment.

Core and MCP SDK use MIT; SQLite is provided by Node. Ghidra/GhidraMCP/Python are configured external
runtimes with their own licenses. Prepared unpublished IPC dependency artifact is pinned with
source provenance; install it alongside the CLI artifact until an authorized Factory npm release.
Packing prepares Factory's manifest after compilation and includes skill/resources; installation
never edits an agent's personal settings. Registry publication is outside this delivery.
