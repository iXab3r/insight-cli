# insight-cli milestone plan

The owner requested documentation and milestone planning on 2026-10-14. The product contract is
in [DESIGN](DESIGN.md#agreed-product-model), with concrete [CLI scenarios](CLI-SCENARIOS.md).
The owner subsequently selected one full M0–M5 implementation pass and answered the product
decisions below. This plan records the delivery contract and completed acceptance. Npm
publication remains excluded.

## Business acceptance follow-up

The next planned infrastructure slice is [shared tool runtime](TOOL-RUNTIME.md): CORE helpers,
retained GitHub tool distributions, Ghidra migration and ILSpy as the second consumer, followed
by combined installed acceptance. TR-01–TR-10 execute sequentially and remain separate from
the completed M0–M5 and business gates below.

On 2026-10-16 the owner agreed the [25 business scenarios](BUSINESS-SCENARIOS.md) in five
branches and requested documentation before implementation. BS-23 requires demonstrable
one-versus-three Ghidra acceleration on a prepared base; BS-24 measures cold start
separately without a required cold-start speedup. A 1.5x margin has not been agreed.
The catalogue owns the acceptance criteria and measurement boundaries. Its executable
Gherkin workflows and benchmark are now implemented; [business acceptance](BUSINESS-ACCEPTANCE.md)
records their separate passing native gate: 25/25 scenarios and six of six prepared-base
pairs faster on three workers (1.60x median paired speedup). Cold/uneven timings are
reported separately. The new gate establishes these business outcomes independently
from earlier technical acceptance.

## Closed owner decisions

| Topic | Selected behavior |
| --- | --- |
| Delivery | Entire M0–M5, accepted as one combined result |
| Publication mode | Explicit merge/refresh by default; subsequent P3 adds opt-in after-edit/after-save publication and before-edit refresh |
| Complex program edits | Publish a verified saved result if shared base is unchanged; after divergence automatically combine only verified categories |
| Complex conflicts | Preserve local/shared versions; caller transfers desired work onto the current base; no force replacement |
| Mixed merge | Any conflict prevents publication of the whole selected merge; preserve all local work |
| Mixed refresh | Apply safe incoming changes; retain conflicting local values with the shared version |
| Runtime modes | Headless for ordinary work; owned GUI instances on demand, including debugger |
| Ordinary startup | Managed local server/repository/storage; external Ghidra Server also configurable by profile |
| API parity | Functional equivalents may replace backend routing, checkout/check-in, save/close and discovery controls |
| Retry identity | Optional request-id on changing commands/API; same intent retrieves the previous result/state, different content is rejected |
| Native acceptance | macOS in this pass; portable CLI/CI; native Windows/Linux deferred |
| Archive exchange | Facade/configuration and contract verification included; developing/provisioning the external service excluded |

These answers replace the corresponding open policy questions in the earlier plan. Remaining
schema, storage and adapter choices are engineering work, not requests to reopen these decisions.
The owner also confirmed the archive-service boundary: it is an explicitly configured external
dependency. All owner questions raised for this full pass are answered. The concrete implementation
backlog is in [work items](WORK-ITEMS.md).

## Current combined acceptance

The final M0–M5 plus selected P0–P3 gate passes 118 offline tests, all 33 native groups and
isolated package checks on one unchanged build. The [current full report](verification/full-facade-current.json)
records two agents/two EXEs/four contexts, explicit and opt-in synchronization, conflict retention,
backend/owner/server recovery and seven manual plus two automatic actual owner SIGKILL phases.
[Reproduction and limits](FINAL-ACCEPTANCE.md) keep native macOS, selected older headless OS
evidence and external archive-service scope distinct. Historical receipts retain their identities.

## Historical original M0–M5 acceptance

M0–M5 passed as one combined result at implementation revision
`300884e3c9be0928a8e1659e088aa2144c2c70b4`. The
[full report](verification/full-facade.json) binds all 23 native groups and the installed owner/IPC
crash matrix to the tested tarball. All 93 offline tests and isolated package checks pass.
[Coverage evidence](verification/coverage-evidence.json) accounts for all 210 operations and eight
bridge equivalents; native macOS limits and deferred scope remain explicit.

## Starting baseline (historical)

| Area | Existing evidence | Remaining work |
| --- | --- | --- |
| Factory integration | Pinned Core; prepared official external IPC artifact; installed-package proof | Reuse the same Factory command/output/IPC foundation for `insight-cli`; no custom product host |
| Backend isolation | Owned Ghidra processes/bridges, binding checks and cleanup exercised on disposable fixtures | Bind them through root sessions/targets and hide worker/backend identifiers from agents |
| Durable publication | Comment proposals, serialized publisher, independent readback and unknown-outcome recovery | Capture ordinary local edits; support session merge/refresh and explicit field resolution |
| Public workflow | `insight-ghidra` worker/proposal prototype | Deliver `insight-cli ghidra ...` and the agreed agent workflow |
| Tests and packaging | Offline tests, native fixture receipts and isolated package proof | Exercise the revised facade and installed skill at the exact delivered revision |

Existing evidence is limited to the [recorded prototype scope](verification/README.md).
It can justify reuse of mechanisms, but cannot complete an acceptance criterion for a new contract.
The new facade must not silently reinterpret prototype target identities, journals or pending work.
Decide the transition before changing runtime storage; migration of production databases remains
outside this delivery.

The initial source inspection gives these concrete starting points; reuse still requires tests
against the changed contract:

| Existing module | Assessment for the facade |
| --- | --- |
| `src/bin.ts` | Retain Factory `runHosted({ entryPoint, createDefinition })` |
| `src/cli.ts` | Replace worker/proposal leaves with the root `insight-cli` and scoped research commands |
| `src/model.ts` | Separate input identity from Ghidra binding/settings; add session context semantics; do not expose Finding/Binding as the new agent contract |
| `src/store.ts` | Reuse durable SQLite principles; current schema has targets/workers/findings/batches but no sessions or ordinary private edit tracking |
| `src/coordinator.ts` | Adapt fresh publication/readback/recovery mechanisms; current finding integration is not session refresh or three-way conflict resolution |
| `src/ghidra.ts`, `src/transport.ts` | Adapt owned process/binding/transport mechanisms; add the required research operations and recoverable private working state |
| Tests, native runner, packaging scripts | Retain suitable infrastructure; revise fixtures and assertions for the actual facade rather than renaming prototype expectations |

Paths in this table are relative to `skills/ghidra-coordinator`. Physical source/package naming
can change only with the real product transition; this plan adds no second implementation.

## Milestones

| ID | Outcome | Depends on | Status |
| --- | --- | --- | --- |
| M0 | Documented contract, pinned coverage audit and acceptance plan | — | Complete: contract, source catalog and typed adapter accounting |
| M1 | Open and continue isolated contexts for several inputs and agents | M0; relevant M1 decisions | Complete: native and public isolation/recovery verified |
| M2 | Agent reads and makes recoverable ordinary edits | M1; relevant M2 decisions | Complete: ordinary reads/edits and durable save verified |
| M3 | Publish, refresh and resolve supported conflicts | M2; relevant M3 decisions | Complete: scalar/complex publication, refresh and recovery verified |
| M4 | Installed research workflow passes concurrent/crash checks | M3 | Complete: final installed owner/IPC/keyring matrix passed |
| M5 | Full inventoried facade and combined delivery acceptance | M4; operation-specific engineering | Complete: full catalog and combined final artifact gate passed |

M1–M4 are internal implementation/verification checkpoints in one pass. Delivery is complete only
after M5 covers the whole agreed inventory and the combined artifact repeats the reliability and
package checks. The first research slice does not reduce the final scope. Dates/effort are not
promised from endpoint counts: GUI lifecycle and whole-program persistence require native proofs.

### M0 — Contract and scope

- Preserve agreed targets, sessions, tool contexts, private views, explicit scope, per-context
  mutation ordering, conflict resolution and continuation semantics.
- Keep example leaf names/results distinguishable from executable prototype commands. Define the
  first-slice command/output/permission map using Factory, including scoped errors and bounded reads.
- Use [the audited coverage baseline](GHIDRA-COVERAGE.md): 210 unique source-catalog operations
  and eight static bridge controls. Each operation has a planned facade mapping, runtime mode,
  access annotation, scope and effect/publication class. Verify typed arguments/results against
  actual handlers during adapter implementation; annotations are not semantic merge evidence.
- Classify actual modules as reusable, needing adaptation or prototype-only. Review uncertain
  journals and stored identities before proposing the transition.

Exit: a reviewer can map each first-slice acceptance scenario to a command and distinguish an
agreed rule from an open decision. The inventory accounts for broader functionality without
pretending that every editing operation already has an automatic merge rule.

### M1 — Sessions, targets and isolation

Deliver `ghidra open <input> --session new`, opening another input in an existing session, and
`ghidra open --session <id> --target <id>` for continuation. Root sessions/targets select contexts;
the agent supplies no backend instance, worker, checkout or proposal file.

Exit:

- A and B opening identical bytes receive different sessions and the same target identity within
  the selected profile. Changed bytes identify another target; equal basenames do not conflate inputs.
- One session opens two inputs and routes explicit scoped reads to the correct context, including
  identical addresses in different inputs. Missing research selectors fail without inference.
- Repeated open continues the same context; replacement of a backend does not substitute another
  target or silently reset the saved view. Concurrent open of the same tuple does not create
  competing working contexts.
- Scoped JSON results echo session/target. Factory profiles, permissions, secrets and AppData
  boundaries remain in force. The runtime does not require a Factory source checkout.
- Ordinary startup owns its local server/repository/storage. External server profiles also work
  without adopting unrelated existing processes. GUI contexts are isolated and started only when
  required; a mode transition preserves the saved working state and verifies the binding.
- Optional request identity reconciles concurrent/retried initial open without creating duplicate
  sessions or contexts; reusing an ID with a changed input fails.

### M2 — Ordinary research and local changes

Deliver the first research path: strings search → xrefs → function get/decompile → rename/comment
→ readback. Bound search/list output and indicate truncation. Capture changes automatically from
ordinary setters; callers do not construct before-value/SHA/journal proposals.

Exit:

- The [research walkthrough](CLI-SCENARIOS.md#research-one-input) runs through the public CLI and
  Factory JSON-RPC command path with matching results and accurate failure status.
- Acknowledged local edits survive owner/backend replacement and are visible to subsequent reads
  in the same context. B's independent context retains its own view.
- Two processes sharing a tuple see shared local work. Local changing calls execute sequentially;
  independent contexts retain their own view and pending work.
- Malformed/partial backend results, interrupted local writes and lost acknowledgments have
  explicit outcomes. Do not report `applied` until the effect is recorded and recoverable, or
  replay a non-idempotent operation merely because the caller did not receive its response.
- The packed skill and help describe the implemented facade slice; ordinary use needs no MCP
  routing or worker-management instructions.

Local persistence and mutation ordering are required now, not deferred to final crash testing.

### M3 — Merge, refresh and conflicts

Deliver explicit `ghidra merge` and `ghidra refresh` for the selected context, initially for
comments and function names once their exact field contracts are settled. The owner selected this
explicit mode for the M0–M5 pass; P3 subsequently adds opt-in per-context synchronization.

Exit:

- Disjoint A/B edits publish and refresh without loss. A's publication does not silently replace
  B's working view. Refresh preserves B's local changes and reports received/preserved/conflicting
  values for that target only.
- Original/local/shared comparisons handle one-sided changes, equal results and incompatible
  changes. Conflicting shared values are not silently overwritten; local work remains inspectable.
- The ordinary setter supports explicit resolution with `--resolve-conflict --expect-shared`.
  A stale expectation fails without losing work; later shared changes are checked again at merge.
- Merge/refresh participate in the same per-context mutation order. A setter executed before a
  successful merge is included; one executed after it remains pending for a later publication.
- Any conflicting selected change prevents publication of the whole merge. Refresh can receive
  changes proven safe to combine while retaining local/shared conflict values. Counters and
  failure status describe actual effects; multiple calls are not advertised as atomic transactions.
- Publication is serialized per shared target/tool model across sessions. A fresh verified
  publication base, readback and durable outcome checks prevent stale native check-in and duplicate
  publication. Unknown outcomes block publication affecting that model, including other sessions.
- Unsupported merge scopes return a clear limitation while preserving exploratory local work.
  Functional operation coverage and automatic merge coverage remain separately documented.
- Verified complex saved program changes publish when the relevant shared base is unchanged.
  Once it diverges, unproved merge categories remain explicit conflicts with both versions
  preserved. The caller can open a new session on the current target and transfer desired work;
  the old context remains available. Arbitrary operation/script replay is not a merge algorithm.

### M4 — Recovery and installed workflow checkpoint

Run the complete [A/B, conflict and failure walkthrough](CLI-SCENARIOS.md) through an installed
package. Reuse existing test infrastructure where valid, adding checks for the changed contract.

Exit:

- Two disposable synthetic inputs, two independent agents per input and multiple CLI processes
  exercise reads, ordinary edits, merge, refresh, conflicts and continuation. Equal basenames and
  addresses cannot route writes to the wrong input. Independent readers verify published values.
- Owner/backend failures around local acceptance, application, save, publication intent, committed
  publication and verification preserve acknowledged work. Lost successful responses reconcile
  without duplicate publication; genuinely unknown outcomes stay observable and blocked.
- Restart preserves pending edits, conflicts and each private view. Only receipt-verified owned
  resources are cleaned up; no existing RE environment is a fixture.
- Locked offline build/tests and isolated installed-package checks verify `insight-cli`, matching
  skill/resources, Factory help/JSON/RPC, permission denial, profile isolation and relocation.
  The package includes runtime/proto/license inputs required by the agreed Factory contract.
- Native acceptance uses the declared runtime versions and disposable fixtures. Public evidence
  records the exact source/artifact revision, sanitized assertions and exercised limits. Required
  checks establish this internal checkpoint; the source PR stays draft until the full M5 gate.

Packing and source delivery do not authorize npm publication, production migration or replacement
of an existing RE workflow. Report resource/capacity limits from the exercised cases.

### M5 — Full facade and combined acceptance

Use the M0 inventory to expand actual operation groups in reviewable increments: analysis and
listing, symbols and types, program/project/server management, and other available capabilities.
Order increments by real research needs. Every group needs public help/examples, permissions,
scope validation, failure/continuation semantics and operation-specific acceptance.

GUI/debugger and program/project/server operations are included, not an optional follow-up. Native
acceptance uses macOS fixtures: PE for static analysis and an owned native executable for debugger
launch, mappings, reads, breakpoints, interruption, stepping and trace persistence. A live process
lost to a crash is reported as disconnected; no transparent CPU-state resurrection is promised.
External effects have operation-specific outcomes and are not rolled back by a program transaction.
For archive exchange, include profile configuration, payload/response validation,
bounded bulk results and retry/partial-outcome behavior for both archive operations. Adapter tests
use an owned contract fixture; claims about a separately deployed service require declared matching
service evidence. Building/provisioning that external service is outside the agreed scope.

Exit: each operation in the agreed inventory is exposed through the facade or has an agreed
equivalent replacement. Unsupported/unimplemented functional entries remain open; documenting a
limitation does not count as delivering that operation. Automatic merging is claimed only for
scopes with defined and verified semantics. Agents continue using logical session/target scope
rather than backend details.

The final artifact must also repeat the M4 A/B/crash suite after all operation groups are present,
pass installed CLI/skill/Factory transport checks and satisfy the coverage ledger at the exact
source/artifact revision. Broad functional availability does not widen automatic merge claims.

## Subsequent P3 delivery

The later autonomous P3 request expands the original scope with ready-built managed SDK modules
and opt-in per-context synchronization. Language/analyzer/script/GUI plugin workflows and
publication after edit/save plus refresh before edit use the existing sessions, targets, saved
contexts and conflict/recovery rules. No new agent-visible lifecycle object is introduced.
[P3 evidence](verification/api-gaps-p3.json) records native macOS and installed-package checks
at their own source identity. Defaults and historical M0–M5/P2 evidence stay explicit.

## Engineering work owned by implementation

| Before | Engineering task | Constraint already agreed |
| --- | --- | --- |
| M1 storage/open | Preserve prototype state separately; implement input identity, binding/load compatibility and request-id handling | Immutable targets, root sessions, no loss of pending work or duplicate creation on retry |
| M1 runtime ownership | Local bootstrap, external profiles, GUI lifecycle, resource limits and dependency checks | Isolated owned instances; macOS native acceptance; no adoption of unrelated resources |
| M2 public leaves | Typed schemas, bounded traversal, scoped errors, interrupted writes and reads overlapping mutation | Factory owns transports/output; explicit selectors; acknowledged edits recoverable |
| M3 supported fields | Null/absent comments, rename identity/collisions, resolution syntax for each supported field | Preserve local work; explicit original/local/shared conflict; stale resolution rejected |
| M3 multi-change operations | Capture verified saved state; test dependencies, partial failures, refresh and publication gates | Merge publishes nothing on conflict; refresh receives safe changes; no unproved atomicity |
| M5 operation groups | Scripts/batches, structural changes, GUI/debugger and external effects | Full functionality; unchanged-base publication; divergence conflicts outside verified categories |

Pause/finish/reopen workflow expansion, a hypothetical second tool, cross-tool transactions and
an unrestricted plugin SDK remain outside the selected contracts. P3 adds content-pinned ready-built
extension modules, native capability discovery, managed GUI enablement and explicit synchronization
policies; [the agent contract](../skills/ghidra-coordinator/references/extensions-and-sync.md)
defines the tested workflows and boundaries.

No further owner choice is required for the closed delivery. All ordered work items have their
combined acceptance evidence in [the current full report](verification/full-facade-current.json); historical
checkpoints remain available in [verification](verification/README.md). Source delivery is tracked
under [Factory #49](https://github.com/iXab3r/EyeAuras.CliFactory/issues/49). Npm publication,
production migration and the deferred scope above are not implied by completion.
