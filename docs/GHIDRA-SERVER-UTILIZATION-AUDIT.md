# Ghidra Server utilization audit

Audited on 2026-10-27. Scope: repository source, the pinned bridge bytecode, Ghidra
12.1.2 source/help and previously retained disposable native evidence. No product
profile or `ec2-native` data was opened, and no server or new runtime test was started.
This is an architecture audit, not acceptance of a migrated CLI.

This retained audit describes the pre-integration source revision. The subsequent
[primary native CLI integration](NATIVE-CLI-INTEGRATION.md) records the replacement
path and its separate runtime evidence; the original source-only report is historical.

**The CLI at the audited revision did not use native collaboration end to end.** It
uses a real Ghidra repository for shared version storage, authority, history and
publication serialization, but substitutes detached snapshots and coordinator merge
decisions for agent checkouts, native change sets, native update and native check-in.
The [accepted ownership boundary](DESIGN.md#native-merge-ownership) requires replacing
that substitution. The [prototype](NATIVE-MERGE-PROTOTYPE.md) proves a useful subset;
it does not establish production parity.

Exact repository/source/help identities are in the
[audit manifest](verification/ghidra-server-utilization-audit.json). Native source
references below are archive entries listed there, not modified installed files.

## Actual execution path

The product entry is `bin.ts` -> `cli.ts` `Owner.selected` -> `Research` with
`GhidraContexts`. `Research.merge/refresh` uses `scalarMerge/scalarRefresh`;
`GhidraContexts.publish` calls `GhidraServer.publish`, which runs
`db.InsightSnapshotPublisher`.

`GhidraRuntime` in `src/ghidra.ts` is wired through `prototype-cli.ts`, a separate
historical publication fixture. Its native checkout/check-in calls do not establish
that the product facade already uses them. Changing its exclusive flag would not
migrate the active product path.

Read-only inspection of the locally installed npm package `@eyeauras/insight-cli`
`0.5.8` also finds the hosted facade wiring, scalar merge/refresh calls, private packed
imports and `db.InsightSnapshotPublisher` dispatch in its selected `dist/src` files.
Their hashes and inspected markers are recorded in the manifest. This corroborates
those architectural characteristics in that installed package; it does not establish
whole-package equivalence to this checkout or exercise an installed runtime/profile.

| Capability | Native Ghidra behavior | Current facade | Retained native prototype |
| --- | --- | --- | --- |
| Shared versions/history | Repository owns program versions and version history | Used, with exact-version readback | Used |
| Server authority | Repository read/write/admin ACLs enforce remote access | Distinct reader/publisher; actual authority probed | One writable `mergeproof` account for all clients |
| Parallel private work | Normal non-exclusive checkout of the same shared item | Detached local `.gzf` imports; no native agent checkout | Three normal checkouts verified |
| Ancestry/change capture | Checkout ID/base and native change sets persist in the local project | Own base/working snapshots plus scalar/opaque-operation journals | Native project survives separate JVM operations |
| Divergent publication | `DomainFile.checkin` invokes native multi-user merge as needed | Coordinator chooses candidate; low-level exclusive DB-buffer publication | Native divergent check-in verified |
| Receive shared edits | `DomainFile.merge` implements Update without publication | Coordinator `scalarRefresh` and snapshot replacement | Not exercised; disabling its guard is not proof |
| Conflict decisions | Native resolvers detect conflicts and request decisions | Scalar expected-value setters and complex-divergence rejection | Native conflict refusal, no resolution/retry workflow |
| Exclusive structural edits | Exclusive checkout for memory-layout/language operations | Private copies bypass shared-checkout constraints; unchanged-base snapshot publication | Block attributes tested; layout/language exclusivity unproved |
| Reopen/mode changes | Reopen the same native project and checkout | Each restore imports into another UUID project | Separate JVM reuse tested; product lifecycle integration absent |
| Storage | Native DB buffers/version files and local working copies | Native storage plus exports, packed snapshots, candidates and retained launch projects | Six successful copies dropped; long-run storage not measured |
| Cross-workspace sharing | Explicitly select the same repository item | Item path incorporates a workspace-specific target ID | One disposable repository only |
| Unknown publication | Native history/checkout observations provide evidence | Durable intents, freeze and independent content readback exist | No crash/lost-reply acceptance |

## Findings and implementation consequences

### A1. The facade's backend contract embeds the snapshot replacement model

`ResearchBackend` exposes `latest/fields/candidate/publish`; `GhidraContext` persists
`baseSnapshot/workingSnapshot/scalars/complexChanges`, but no native project locator,
checkout ID or native repository file ID. `Research.merge` decides compatibility in
TypeScript before publication. `Research.refresh` reconstructs an incoming scalar list
partly from local publication journals, rather than using native Update.

Replace this backend path with native checkout/update/check-in operations and native
conflict results. `changes status`, explicit resolution, automatic synchronization,
discard, mode changes and recovery also depend on the old representation. Replacing
only `merge.ts` would leave those assumptions intact. Existing public change counts
are journal/scalar counts, not native object/range counts; a revised native result
contract needs explicit acceptance rather than silently reinterpreting those fields.

Evidence: `src/cli.ts:101`, `research.ts:20`, `research.ts:79`, `research.ts:546`,
`research.ts:616`, `workspace.ts:28`, `sync-policy.ts`, `lifecycle.ts` under the skill workspace.

### A2. Current publication does not produce a trustworthy checkout delta

`InsightSnapshotPublisher` obtains a low-level exclusive checkout, copies the packed
snapshot's DB buffers and fabricates change information by marking all current memory,
current datatypes and current symbols changed. This is not the originating agent's
native checkout change set. It does not explicitly record native additions or enumerate
deleted object IDs, category/tree/tag/source-archive changes and register-context ranges.
Native change-set APIs distinguish these domains.

This is a source-level migration hazard, not a newly demonstrated loss in current
snapshot publication. Whole-buffer readback can verify the resulting DB content; it
does not prove the change history suitable for a later native three-way merge.
Do not mix old snapshot writers and native clients on the assumption their ancestry
is interchangeable. Retire this helper as the regular native publication writer;
retain useful independent fingerprint/readback and recovery principles.

A migration must establish a known native baseline/epoch for subsequent real checkouts,
preserve old history, and explicitly handle pending detached private work. A fresh
versioned item seeded through native APIs is a candidate approach; this audit does not
authorize creating it in existing research storage or discarding old contexts. Do not
repair missing history by inventing another coordinator delta/merge implementation.

Evidence: `references/native/InsightSnapshotPublisher.java:53` and `:68`; native
`ProgramDBChangeSet.java`, `ProgramChangeSet.java`, `DataTypeChangeSet.java`.

### A3. Restart, save and inspection create additional full-program representations

`privateCopy` links a saved `.gzf`, creates a fresh UUID project, then imports it.
`capture` saves and exports another `.gzf` before capturing it into the artifact store.
`latest` opens a fresh shared reader and exports a full shared snapshot. `candidate`
creates another imported project. `stopRecord` stops the process and records its
termination; it does not delete those project/export directories.

The artifact store deduplicates identical file bytes by SHA256, and the input link is
a hardlink. Neither mechanism deduplicates imported native DBs or changing snapshots
at the object/block level. Do not count every link as a physical copy, and do not
interpret content addressing as incremental program storage. No new disk measurement
was made in this audit.

Persist one project per working context independently of process launches. Use native
save/reopen for ordinary persistence; packed exports remain explicit portability or
recovery artifacts with bounded retention, not the default save/refresh transport.
Ghidra's native version files record buffer history, but they are not zero-cost or a
substitute for measuring actual disk/network behavior. The current full block-stream
writer also warrants a separate transfer-size comparison; savings are not quantified here.

Evidence: `contexts.ts:81`, `:222`, `:301`, `:721`, `:762`, `:169`; `artifacts.ts:62`;
native `db/buffers/VersionFile.java`, `ManagedBufferFile.java`.

### A4. Native Update and conflict resolution remain missing acceptance gates

`DomainFile.merge` is Ghidra's Update operation: receive latest while retaining private
changes, advance the checkout base, and create no new shared version. It uses native
changes since the checkout base. It must replace scalar refresh, not be approximated
with a snapshot switch or script replay.

The inspected bridge's `VersionControlService`/`ProjectVersionControl` offer checkout,
check-in, undo, add and history; their declared methods do not expose a native Update
wrapper. The native API exists, so add a thin adapter in the existing runtime. The
prototype patches both check-in and update headless guards, but its receipt proves
check-in only. The float/double regression establishes one headless conflict seam;
it does not prove all resolver decision/error/cancel paths or apply/resume behavior.

Required proof: A/B checkout; A publishes; B performs native Update without publishing;
B's local edits and native checkout identity survive, its base advances, and a later
check-in preserves both authors. Cover equal edits, deletions, conflicting updates,
cancel, saved restart and subsequent conflict decisions. No scalar fallback or raw
script replay is allowed when the native adapter lacks a supported headless path.

### A5. Native adoption must retain the existing publication authority boundary

Current shared readers authenticate as a verified read-only account; regular private
workers are launched without repository credentials. Publication uses the distinct
publisher. Ghidra explicitly denies read-only users native checkout ability. The
prototype uses one writable account for all JVM calls, so its successful merge cannot
establish the product's authority/isolation contract.

Prove a service-controlled native checkout edited/reopened locally without distributing
publisher credentials to arbitrary-script workers, then reopened by the authorized
publisher with checkout ancestry intact. Verify rejected reader checkout/check-in and
two independent service clients. Local request ordering is useful but cannot replace
the server's ACL or check-in arbitration. One server account per AI agent is not assumed.

The server does not own Factory request IDs, application leases or multi-step exactly-once
workflows. Native `RepositoryAdapter` even contains reconnection/retry paths in some
mutating methods. Inspect/fault-test those boundaries; retain durable intent, unknown
outcome freeze, native history and independent readback rather than blindly retrying.

Evidence: `contexts.ts:234`, `:313`; `server.ts:183`; `InsightServerProbe.java`;
`InsightServerInit.java`; proof runner credentials; native `DomainFile.java:347`,
`RepositoryAdapter.java:726`.

### A6. Native exclusivity, open handles and `.keep` copies are real lifecycle rules

The bundled repository help requires an exclusive checkout for memory-map and language
changes. Normal checkouts permit ordinary parallel analysis; exclusive mode prevents
other checkouts while held. `TRANSIENT` is connection-lifetime exclusive access, not an
automatically garbage-collected normal agent checkout.

Structural commands/scripts must follow native exclusive-access rules. Do not bypass
them by publishing a detached whole DB when the shared head happens to match. The
current proof covers bytes and block attributes, not adding/moving/removing blocks or
changing language/compiler configuration under contention.

Ghidra forces `keepCheckedOut=true` if a program remains open during check-in. Close
all owned consumers before expecting release/drop. Explicit check-in handlers can
disable creating `.keep`; dirty native Update creates a `.keep` backup and normally
tries to replace the prior exact `.keep`. That is not evidence of inherently unbounded
backup accumulation, but the copy must be accounted for. There is also a temporary
`.merge` item during dirty Update. Reuse/drop an owned context project deliberately;
do not add a fresh persistent project for each native step.

Native checkouts support offline work and are not application heartbeat leases. GC
must reconcile checkout state with owned project/lease/journal state, preserve unknown
and unpublished work, and never terminate a checkout simply because its timestamp is old.

Evidence: native repository help, `CheckoutType.java`, `DomainFile.java:472`,
`GhidraFileData.java:1617`, `:1944`, `:2109`, `:2173`.

### A7. Same server/repository does not yet mean the same analysis across profiles

`Workspace.importTarget` derives `t_...` from a random workspace namespace and binary
SHA256; `programPath` maps that ID to `/<target>.bin`. Local profiles also get separate
repositories. This intentionally isolates profiles and does not prevent agents in the
same profile from sharing a target. It does mean independently initialized profiles or
machines do not automatically join the same native item merely by choosing one external
repository and opening identical input bytes.

If cross-workspace collaboration is included, persist an explicit shared-model binding:
server/repository, native item ID/path, source identity and relevant load/runtime settings.
Keep local session/target IDs separate. Do not remove the namespace globally or auto-join
equal SHA256 inputs; that would collapse intentionally separate investigations.
Cross-workspace convergence remains a separate acceptance scope.

## Boundaries worth preserving

Keep Factory's command/profile/permission/IPC ownership, target/source validation, actual
repository authority probes, immutable input handling, durable intents and independent
exact-version readback. The initial import's staged/verified conditional creation addresses
an absent canonical item; do not confuse that bootstrap with ongoing merge. Its low-level
implementation can be evaluated separately against native add-to-version-control.

Ghidra is not a distributed live-edit CRDT or a Git branch/PR server. Agents edit local
checkouts; the native client engine merges with versions held on the server. Normal
checkout files still consume local disk. Repository ACLs/version history do not collect
our launch directories or preserve Factory journals. Program user-data is a separate
user-filesystem object from versioned program properties; external files, debugger traces,
tool preferences and arbitrary research materials are not automatically merged as program
analysis. The existing cross-program documentation/VT transfer tools are explicit private
analysis features, not an alternative shared-publication authority.

## Recommended delivery sequence and gates

| Step | Concrete change | Acceptance needed before the next dependency |
| --- | --- | --- |
| 1 | Prove a persistent service-owned normal checkout with credential separation | Multiple saved JVM restarts preserve ID/base and native additions/deletions; script worker cannot publish; publisher can resume the same project |
| 2 | Add native Update and native conflict transport in the existing runtime | Receive without publication, preserve local edits and advanced ancestry, cancel/restart; pin every required headless patch |
| 3 | Establish explicit shared-item identity and a clean native-history migration boundary | No mixed legacy/native writers; old history and pending detached work remain retained; cross-profile sharing only if explicitly selected |
| 4 | Route open/save/reopen/mode/merge/refresh/discard/sync/status/recovery to the same native context | Installed CLI A/B scenarios use native operations; source and runtime admission reject the scalar/snapshot publisher path for native contexts |
| 5 | Verify publication and close/release/drop successful projects | Open-consumer case, head races, server/client restart, lost replies and authorization failures; no unknown result becomes deletion/retry |
| 6 | Measure repeated cycles and then implement bounded GC | Track native working DBs, `.keep`/`.merge`, exports, snapshots and server history separately; successful project count follows live contexts, not JVM launch count; preserve failed/unpublished owners |

The follow-up [native checkout lifecycle prototype](NATIVE-CHECKOUT-LIFECYCLE.md)
combines **credential-separated checkout + saved restart + native Update**. Its
separate runtime evidence supplements this source-only audit; earlier proof limitations
above describe the audited sources, not a claim about the follow-up candidate.
Broadening scalar merge, adding cleanup alone, or declaring
the existing merge proof to be production readiness would miss the remaining architecture.
Existing `ec2-native` migration requires its own scoped work; this audit changes none of it.
