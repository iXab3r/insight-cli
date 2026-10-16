# insight-cli design

## Agreed product model

The owner agreed this model in the development discussion on 2026-10-14. The public executable
is `insight-cli`; Ghidra functionality belongs under `insight-cli ghidra ...`. The agent-facing
surface is our CLI/API. The service owns underlying instances, routing, isolation, lifecycle,
change capture and merge orchestration. Callers provide research intelligence and assignments.

This section records the implemented contract. The last combined M0–M5 and selected P0–P3
acceptance passed on its recorded build; the [full report](verification/full-facade-current.json)
identifies 33 native groups, 118 offline tests, the installed artifact and limits. The later
[production-EXE walkthrough](AGENT-CLI-WALKTHROUGH.md) keeps separate focused evidence for
the import timeout and open-error improvements. The
[original M0–M5 report](verification/full-facade.json) retains its historical source identity.
The earlier `insight-ghidra` implementation remains a scoped-comment regression fixture for
publication mechanisms, with its historical behavior recorded below. The agreed walkthroughs
are in [CLI scenarios](CLI-SCENARIOS.md); [the milestone plan](PLAN.md) and
[work items](WORK-ITEMS.md) retain the delivery contract and checkpoint history.

### Full delivery scope agreed on 2026-10-14

The owner chose one implementation pass covering the whole M0–M5 plan, with acceptance of the
combined result. Milestones are internal checkpoints; completing the research slice alone does
not complete delivery. The baseline is the pinned GhidraMCP 7.0.0 functionality, including server
management and GUI/debugger operations. [Coverage](GHIDRA-COVERAGE.md) inventories the actual source
catalog and bridge controls. Logical equivalents can replace underlying routing, checkout/check-in,
save/close and discovery operations; callers need not receive a literal backend passthrough.

Ordinary work uses owned headless instances. GUI-only operations use managed isolated GUI instances
for the appropriate contexts when needed. Combined native acceptance targets macOS; portable
CLI/CI remains required. Earlier selected headless Windows/Linux P2 checks retain their own
identity; full GUI/P3 native acceptance on those OSes remains deferred. Static PE research and
native macOS debugger fixtures are distinct acceptance cases; this does not claim macOS can execute
every imported EXE format. Saved analysis/trace state is recoverable; a crashed live debuggee is not
silently resumed from a prior CPU execution state.

On a machine with the configured Ghidra/Java dependencies, the facade starts its owned local server
and creates its own repository/storage for the ordinary open workflow. An externally configured
Ghidra Server is also supported through a profile. Factory continues to own profiles, permission
gates, credentials and host lifecycle. Managed resources live in profile AppData; starting local
infrastructure does not grant administrative control over unrelated external repositories.

Two catalog operations exchange documentation with an independently configured archive service.
The owner confirmed inclusion of their facade/configuration/contract verification while keeping
that service an external dependency; developing/provisioning a new archive product is excluded.
Server administration,
debugger actions, exports and archive exchange have immediate operation-specific effects rather
than being ordinary program-DB edits awaiting merge.

### Shared targets and sessions

| Entity | Responsibility |
| --- | --- |
| Target | A specific immutable input revision, such as an EXE; shared identity for all tools |
| Session | Independent work by an agent or task across several targets and tools |
| Tool context | A tool's working state for a session and target |
| Shared tool model | The tool's agreed analysis/results for a target, from which working contexts are opened |

Targets and sessions belong above the Ghidra namespace. Names and input paths locate/display
targets; the service determines input identity. Changed input bytes identify a new target.
Tool-specific load settings and analysis data belong to the tool. Publishing Ghidra annotations
updates its shared analysis model while preserving the target's source bytes.

Sessions persist across CLI invocations, API reconnects and replacement of underlying processes.
Each independent worker in the A/B scenario has a separate session. A session may work on
multiple targets with multiple tools. The working context is selected by `(session, target, tool)`;
ordinary calls need no additional backend instance or worker identifier. Callers deliberately
using the same tuple share that working context. Labels do not substitute for identity.

Context state and merge rules are tool-owned. Shared target identity links outputs from different
tools and their provenance; it does not imply a uniform analysis database or an atomic snapshot
across tools. A stateless tool may use session/target scope without a mutable working copy.
No hypothetical second tool or general plugin framework is required to implement this model.

### A/B binding example

| Session | Target | Tool | Working state |
| --- | --- | --- | --- |
| s_a | t_client | ghidra | A's private work on client |
| s_a | t_helper | ghidra | A's private work on helper |
| s_b | t_client | ghidra | B's independent work on client |

The routine entry point opens an input and creates an independent session in one call:

```text
insight-cli ghidra open ./client.exe --session new --json
```

The result supplies `session` and `target`, for example `s_a` and `t_client`. B independently
opening the same input receives a different session, such as `s_b`, and the same target identity.
The agent uses those identifiers on subsequent calls:

```text
insight-cli ghidra functions get --session s_a --target t_client --address 0x140001000 --json
insight-cli ghidra open --session s_a --target t_client --json
```

The second form continues an existing context after reconnecting or process replacement.
If native opening fails after its intent is reserved, the failure returns the retained session,
target and optional caller request ID, with follow-up commands to inspect status and continue.
An unresolved open retry exits nonzero and preserves the original intent; it never reimports
merely to obtain a successful response. Initial import/analysis has a bounded ten-minute native
job budget. [First-import recovery](INITIAL-IMPORT-RECOVERY.md) uses private completion receipts,
independently verified staging and conditional canonical promotion; it also handles retained
legacy failures without resetting a profile. The earlier
[production-EXE walkthrough](AGENT-CLI-WALKTHROUGH.md) keeps its original timeout-fix evidence.
Separate target/session management can remain available, but is not required setup for each
research task. The combined native/installed acceptance covers opening and ordinary research/edit commands
together with the full inventoried facade.

Program-scoped research calls identify the session and target rather than changing a global
active program. The facade resolves backend bindings and captures changes automatically;
agents do not construct baseline/SHA/checkout/proposal journals. The intended tool surface
covers Ghidra/server functionality, with logical lifecycle and management operations exposed
through the facade. Functional editing support and automatic merge support are separately
specified for each operation. The prototype's comment-only scope is not the facade's API ceiling.

### Explicit scope across multiple inputs

The owner agreed the two-input walkthrough: a session may open another input without replacing
its existing context. Opening `helper.exe` in A's session creates or continues the context for
that target, while A's work on `client.exe` remains independently available:

```text
insight-cli ghidra open ./helper.exe --session s_a --json
```

```json
{
  "session": "s_a",
  "target": "t_helper",
  "state": "ready"
}
```

Research commands require explicit `--session` and `--target`. There is no active input that
opening another EXE silently switches. Omitting `--target` is an error with a nonzero exit status,
even if the session currently has only one target. Input-opening calls can establish target
identity from their supplied path and return it to the agent.

Every scoped research JSON result includes `session` and `target` alongside the operation's
data, so agents can associate responses from parallel calls with the intended input. An address
alone never identifies an object across targets; two EXEs can contain unrelated functions at
the same address.

`ghidra merge` and `ghidra refresh` affect only the selected session, target and tool context.
Result counts such as `pendingChanges`, `receivedChanges` and `preservedLocalChanges` refer to
that context, not all targets in the session. Publishing A's changes to `t_client` leaves A's
unpublished `t_helper` changes intact. B may open and refresh `t_client` without opening `t_helper`.
Reopening `(s_a, t_helper, ghidra)` after a failure preserves its local work under the continuation
rules below.

### Concurrent callers

Different CLI processes using the same `(session, target, tool)` operate on the same working
context, not independent copies. Independent agents use different sessions. Changing operations
on one context, including setters, merge and refresh, execute in sequence. Simultaneously submitted
calls have no promised order. If a setter executes before merge, its change is included; if it
executes after merge, its change remains pending. A caller requiring inclusion waits for the edit's
`state: applied` response before invoking merge. A failed or unknown publication never produces a
successful merge acknowledgment merely to allow the next call to proceed.

This does not define all calls as atomic database transactions, nor promise unlimited parallelism
across contexts. Tool resource limits and consistency for reads overlapping long mutations must be
specified for the supported operations. No agent-visible process ID or lock command is required.

### Publication and incoming updates

If A and B open a shared Ghidra model at R1, each context starts from R1 and accumulates its own
changes. A publishing produces shared R2. B retains its working view and local work until its
Ghidra context is updated. Updating `(s_b, t_client, ghidra)` does not update other targets or tools.
For supported scopes the service compares the original, local and shared states, preserves local
changes and retains incompatible values as explicit conflicts. Context refresh and publication
are distinct operations; refresh does not itself approve replacing shared data with local values.

The manual A/B walkthrough uses `ghidra refresh` to receive shared changes and `ghidra merge`
to publish local changes, both scoped by `--session` and `--target`. A successful ordinary edit
is visible to subsequent reads in that context. An acknowledged `state: applied` means the local
edit is recorded for recovery; `sharedState: pending` means it has not yet been published.
This is a required facade behavior, not a durability claim about the existing prototype.

The owner selected explicit `merge` and `refresh` for this pass. Automatic publication and incoming
refresh strategies were deferred in M0–M5. The owner's subsequent P3 request adds explicit per-context `sync-policy`: publication after an edit/save
and incoming refresh before an edit; default behavior stays manual. See
[extensions and sync](../skills/ghidra-coordinator/references/extensions-and-sync.md). If any selected local change conflicts, merge publishes nothing
and preserves all local work. This is a publication gate, not a claim that separate backend calls
are atomic: incomplete stages remain recoverable and never receive a successful publication result.

Refresh applies incoming changes that can be safely combined and preserves conflicting local values
alongside the shared version. Dependencies between edits must be checked; sharing an address or
being an unchanged scalar value does not establish that applying it to a changed structure is safe.

Complex local program changes can be published when the relevant shared model is unchanged and
their saved result can be verified. Once that model diverges, only categories with defined and
verified merge semantics are automatically combined. Other changes retain the local and shared
versions as an explicit conflict. The caller transfers the desired work onto a current shared
base before publication; whole-version force replacement is outside the selected contract.
No universal native database merge or replay of arbitrary scripts is implied here.

### Agreed scalar conflict resolution

For supported scalar fields, conflict detection compares original, local and shared values.
A change on only one side can be preserved; equal resulting values do not conflict. Different
changes on both sides retain all three values as an explicit conflict. The service does not
choose a semantic winner. A failed merge returns a conflict result and a nonzero CLI exit status;
the conflicting local value remains available in the session.

The agent resolves a comment conflict through the ordinary setter, explicitly identifying the
shared value it considered. It can choose the existing shared text, its own text, or a new text:

```text
insight-cli ghidra comments set \
  --session s_b --target t_client \
  --address 0x140001000 --kind eol \
  --text "Loads settings from a file; falls back to embedded defaults" \
  --resolve-conflict \
  --expect-shared "Loads settings from a file" \
  --json
```

```json
{
  "session": "s_b",
  "target": "t_client",
  "state": "applied",
  "conflict": "resolved",
  "sharedState": "pending"
}
```

This acknowledges the observed shared value as the new comparison base for that field and
records the selected local value; it does not publish the choice. `--resolve-conflict` is an
explicit decision, not a side effect of ordinary editing. `--expect-shared` is required for this
form. If the shared value differs at resolution time, the command fails with `state: conflict`,
`reason: shared_changed`, and the expected, current shared and retained local values. It preserves
the local work and unresolved conflict. If the shared value changes after resolution, the next
merge compares it with the acknowledged base and checks for a new conflict.

```text
insight-cli ghidra merge --session s_b --target t_client --json
```

```json
{
  "session": "s_b",
  "target": "t_client",
  "state": "merged",
  "applied": 1,
  "pendingChanges": 0
}
```

These examples cover one non-null scalar comment. The typed implementation must define null/absent
values and operation-specific conflicts consistently. The full-delivery choices above now settle
multi-change publication and incoming refresh; they do not make non-scalar changes independently
mergeable fields.

### Request identity and lost responses

Changing commands accept an optional `--request-id`; API callers use the same command option
through Factory. The service records a request's identity and intent before acknowledging effects.
Within the selected profile, the same ID and same effective input identify the same request,
including initial `open --session new` before the session ID is known. Reuse with different input
fails. A retry retrieves the prior result or its current unresolved state rather than repeating
the operation. Without a caller-provided ID, each invocation is a new intent; ordinary workflows
remain unchanged.

An unknown or partially completed request must not be reported as successful or executed again
merely because its caller retries. Reconciliation can establish a terminal result; otherwise the
affected mutation/publication remains blocked as appropriate. Readback or remote-specific evidence
is required for effects outside the program DB. This is not a blanket exactly-once guarantee for
arbitrary scripts, debugger execution or external services.

### Continuation after failure

The same session and target reopen the saved private context, including unpublished changes
and unresolved conflicts. Reopening does not silently replace it with the latest shared model.
If a publication response is lost, continuation must establish the actual outcome from durable
evidence. A known completed publication is reported without repeating it; an unestablished
outcome stays unknown and blocks further publication that could duplicate or overwrite it.
Session pause/finish commands and additional lifecycle states are deferred until actual usage
demonstrates a need. Optional caller request identity does not require a separate job/operation
object in the ordinary research workflow.

## Current prototype implementation

One public agent repository ships real TypeScript/Node CLIs and version-matched skills. Each
executable helper has one canonical source under `skills/<product>` as an npm workspace.
No speculative product packages are generated. Factory 0.4.1 supplies the command tree, output,
profiles, keyring, permissions and RPC. Reusable IPC/package identity is implemented in Factory
under its issue #50, as agreed with the owner in #49; no product-specific host exists here.

### Ownership

Stable applicationId insight-ghidra selects the Factory owner. Package-scoped artifact and
installed-runtime fingerprints reject incompatible builds. The same definition serves help,
human/JSON and JSON-RPC. Profile AppData owns SQLite/WAL, worker receipts, stages/backups/logs.
Passwords and per-publisher bridge tokens are injected from Factory secrets into owned process
environments, never profile JSON. Publisher HTTP/UDS endpoints require that private token; status
returns only a secret-key reference. Reader processes receive no publisher credential or token.
Readers and publisher use distinct server accounts. Investigator CLI operations expose inspection
and proposal submission only. Ghidra Server ACLs must restrict readers; advisory locks do not
prevent direct writes made with a separate privileged account under the same OS identity.
Native read-only proxies may accept transient in-memory comments. The canonical boundary is
server-enforced checkout/check-in denial, plus private authentication on publisher endpoints.
Investigator CLI leaves expose inspection/proposals; reader memory never becomes the publication base.

### Commands and permissions

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

### Durable comment lane

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

### Verification and distribution

Default CI executes only synthetic/offline boundaries; npm dependency acquisition is a separate
setup step. Unit fault injection proves state semantics; actual process kill tests prove durable
SQLite recovery. Real Ghidra write acceptance is a separate local-only disposable-fixture runner,
not Factory's ReadOnly service proof and not CI. Report limits at the tested revision/environment.

Core and MCP SDK use MIT; SQLite is provided by Node. Ghidra/GhidraMCP/Python are configured external
runtimes with their own licenses. Prepared unpublished IPC dependency artifact is pinned with
source provenance; install it alongside the CLI artifact until an authorized Factory npm release.
Packing prepares Factory's manifest after compilation and includes skill/resources; installation
never edits an agent's personal settings. Registry publication is outside this delivery.
