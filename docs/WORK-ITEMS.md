# Full facade implementation work items

The owner selected one combined M0–M5 delivery and closed the product decisions in
[the plan](PLAN.md#closed-owner-decisions), then authorized autonomous implementation on 2026-10-14.
Items produce code, fixtures or exact-revision evidence inside the
existing product; they do not add separate CLIs, a generic plugin framework or agent-visible jobs.

## Completed delivery

All ordered M0–M5 work items, including M5-06, passed combined acceptance at implementation
revision `300884e3c9be0928a8e1659e088aa2144c2c70b4`. The
[full report](verification/full-facade.json) records 23 native groups, 93 offline tests, installed
CLI/Factory IPC/OS-keyring checks and seven actual owner-crash phases. All 210 operations and eight
bridge equivalents have [command/effect evidence](verification/coverage-evidence.json).
The installed native runtime also works without a `mcpJar` override or bridge checkout.

The records below are checkpoint history: their intermediate open-gate notes are superseded by
the combined report, while each receipt still identifies exactly what its individual runner proved.
Native Windows/Linux, automatic strategies, archive-service deployment and npm publication remain
outside the selected delivery.

## Checkpoint history

M1-01 passed on an owned native fixture: private save/reopen, headless/GUI interchange,
full-state publication, independent readback and stale-base refusal. The
[receipt](verification/native-snapshots.json) records exact source/runtime hashes and its limits.
M1-02 through M1-04 have their substrate checkpoints: immutable input artifacts, root sessions,
tuple bindings, saved private/base snapshots, durable request reservations and atomic saved-state
acknowledgments; managed local/external server authority; owned headless/GUI context lifecycle.
The offline suite has 33 passing tests, including four real processes racing the same open ID.
[Server evidence](verification/managed-server.json) and
[context evidence](verification/durable-contexts.json) record native runtime/source hashes, four
private views across two research sessions/two inputs, GUI interchange, backend SIGKILL continuation,
capacity refusal and wrong-source startup cleanup. Fixture credentials use a synthetic adapter;
installed Factory credential/profile/command integration remains part of M2/M4 acceptance.

M2-01 through M2-03 now expose `insight-cli` with root targets/sessions, scoped research and
ordinary private edits. The offline suite passes 39 tests; isolated offline package installation,
JSON/RPC, skill/resources, missing selectors, permission denial and spaces/Unicode relocation pass.
An owned native Factory CLI/API fixture passed open retry, strings→xrefs→function/decompile,
rename/comment save/readback, A/B isolation and clear/null. Native installed IPC/credentials and
broader schema/failure acceptance remain M4/M5 gates.

M3-01 through M3-04 now have their implementation checkpoints: scalar three-way comparison,
explicit resolution, safe incoming refresh, complete unchanged-base saved-state publication,
independent exact-version buffer verification and committed-response reconciliation without a
second check-in. The [native receipt](verification/session-merge.json) records seven published
revisions, complex types/signature/memory effects, retained divergence and the tested source hashes.
The offline suite passes 49 tests, including per-context setter/merge ordering and a later shared
change invalidating an explicit resolution. Isolated package installation/relocation still passes.
The complete owner/backend crash matrix and installed native IPC/credentials remain M4 gates;
these checkpoints do not establish general native changeset coverage. M4/M5 and combined facade
acceptance are not complete.

M4-01 now has an installed owner/IPC checkpoint. The [receipt](verification/installed-sessions.json)
records two inputs with equal filenames/addresses, four independent contexts, parallel CLI calls,
conflicts retained after owner replacement, a managed server restart and seven owner SIGKILL
phases. Repeated effects are counted in the fixture; committed publication reconciles to R2 without
a second dispatch. The native artifact uses real Factory IPC and unique OS-keyring accounts.
It exposed a lifecycle defect: a replacement owner previously counted unread surviving contexts
without releasing them during shutdown. Cleanup now authenticates those receipts with a signal
independent of cancelled commands. The offline regression includes a real unread owned child.
The expanded offline suite passes 51 tests. The receipt identifies the exact tested artifact and
source hashes; subsequent query input/error refinements are not that installed artifact.

The read expansion now exposes 74 pinned scoped query contracts, with typed flags, operation
result checks, bounded JSON, explicit session/target scope and Factory ReadOnly gates. All 74
native calls passed; [query evidence](verification/query-contracts.json) additionally asserts known
types/enums, imported functions, properties/bookmarks, P-code, strings/xrefs and exact controlled
emulation outputs. The offline suite passes 53 tests. Variant/nested-output completion and the
actual script inventory remain open; the pinned script-list endpoint returns guidance rather than
an inventory. This receipt does not complete those rows or editing coverage. The final M4 matrix
will repeat on the full M5 artifact, including remaining backend/setup failures and all groups.

The package now contains the pinned bridge runtime and its Apache-2.0 license/notice; ordinary
configuration needs Java/Ghidra, without a bridge source checkout or Python bridge. The
[structural receipt](verification/structural-mutations.json) passed 31 saved editing effects with
that bundled runtime, including retaining the original while cloning a type, exact 64-bit enum
and property values, complete publication and another agent's refresh. Its source hashes identify
the tested checkpoint; later function/batch/analysis additions require their own evidence.
Script discovery now returns installation/context inventory IDs rather than backend guidance.
The facade also exposes function/variable/tag edits, scripts, batch comments/documentation and
analysis commands with immutable saved-state verification. Two upstream WRITE annotations
(`analyze_data_region`, `detect_array_bounds`) are implemented as ReadOnly queries because their
pinned implementations do not modify the program. The offline suite currently passes 66 tests,
including lost structural-response recovery from a retained immutable candidate without replay.
The [function/batch receipt](verification/function-edits.json) additionally passed 22 saved effects
(functions/variables/tags, scripts, comments/documentation and analysis), request retries,
publication and a second session's refresh. The runner checks source hashes at both ends so its
receipt identifies a stable tested checkpoint. Subsequent GUI preparation ordering has a separate
offline regression; the receipt's headless batch does not establish GUI navigation acceptance.
The [data-edit receipt](verification/data-edits.json) passed the six remaining ordinary editing
operations: C type import (saved equivalence against independently parsed expected types),
data classification/globals, implicit member `this`, typed documentation with quoted/newline
text and flow repair. It includes retry, publication, isolation and refresh assertions with
stable source hashes. `set-global` uses the Destructive gate because its eviction variant can
remove named neighbouring data. The original documentation endpoint's regex parser is replaced
by an equivalent transactional typed-JSON action, followed by saved effect verification.
Blocked continuation attempts terminate before starting a new open intent, so repeated attempts
cannot accumulate mutually blocking unknown opens. The offline regression retries three times,
then establishes the retained effect without replay.

Cross-context work has native checkpoints: [four reads](verification/cross-reads.json),
[private documentation transfer](verification/documentation-transfer.json) and
[failed cleanup recovery](verification/cross-recovery.json). Explicit second/source selectors
choose private snapshots, including two inputs with equal filenames. Opposing callers complete
without a context-lock deadlock. Transfer preview leaves the receiver unchanged; saved destination
verification precedes acknowledgment, and explicit merge publishes it. An offline lost-response
case changes the source afterward and proves recovery uses the retained earlier source once.
The cleanup test retains a failed temporary close and releases only that verified owned stage on
the next call. Full category variants, native cancellation/owner faults and final artifact repetition
remain open. The whole M5 gate and final installed crash matrix are not complete.

## Engineering defaults

The [debugger backend crash checkpoint](verification/debugger-crash.json) kills the original
owned GUI child during a lost interrupt response. An LLDB child owner in a separate OS session
handles terminal loss, verifies inferior termination and records completion before replacement.
The former process does not survive as a stopped orphan. The latest independently verified
uncertain trace candidate is retained, continuation is disconnected, private work and another
session survive, and the action/launch is not repeated. A quoted working directory is enforced
instead of relying on the source launcher's optional hint. The repeated sixteen-operation
[recovery scenario](verification/debugger-recovery.json) also verifies ordinary live close.
The offline suite now passes 90 tests, including stale-candidate and already-ended close cases.

[Scalar projection after complex edits](verification/scalar-projection.json) now verifies that
batch/script/structural saved results supersede earlier tracked values before merge or refresh.
A lost batch response reconciles its retained candidate once; incoming conflicts report and
preserve the actual later local value. Deleting a renamed function retains an explicit removed
field with complex state, then publishes the complete unchanged-base snapshot without reviving
its old name. The offline suite passes 89 tests. Workspace schema four retains earlier data and
prevents an older build from treating a removed function name as a scalar rename.

[Session save and local discard](verification/lifecycle-selection.json) closes the two remaining
explicit lifecycle equivalences. Session-wide saving visits only that session's contexts and
retains per-input outcomes; local discard saves the former snapshot and restores the selected
context's own base without publication. Native scalar/structure edits, two inputs, another
agent's newer shared revision, same-ID retrieval and a lost local switch are checked. A later
explicit refresh receives the newer revision. The offline suite now passes 87 tests.
The catalog audit resolves all 210 current mappings plus eight bridge-control equivalents;
that structural accounting remains separate from final behavioral/installed acceptance.

The [debugger checkpoint](verification/debugger.json) exercises all sixteen public debugger
leaves against an owned macOS Mach-O using LLDB: launch/offers, status, trace/module inventory,
registers/stack, exact memory, both mapping directions, breakpoints, interrupt/resume and all
three step kinds. Independently verified packed traces survive GUI closure and reopen as
disconnected; private static edits and another session remain intact. The
[response-recovery checkpoint](verification/debugger-recovery.json) loses a successful CPU step
response and verifies exactly one dispatch, read-only observation, selected-context close and
disconnected continuation without another launch. Actual memory must be captured and KNOWN;
the facade refuses unrecorded bytes instead of accepting the backend's zero-filled response.
Breakpoint verification distinguishes current trace placements from retained static bookmarks.
Backend/owner crash variants and the final installed matrix remain open.

The [archive checkpoint](verification/archive-exchange.json) exercises both ingest operations
using the pinned payload builder and an owned local HTTP service contract. Private names and
comments, exact matching hashes, preview without network, created/updated/conflict counts,
request retries and lost-response retention are checked. Node owns the network request and
optional Factory secret; no archive token enters Ghidra or a debuggee. External uncertainty
does not block local research. The offline suite passes 85 tests. These exact source checkpoints
do not finish the combined M5 gate, installed crash repetition or remaining functional variants.

The [GUI control checkpoint](verification/ui-controls.json) verifies the four public UI leaves:
cursor facets, owned tool discovery, goto/readback and temporary prompt policy. Backend program
names are resolved against verified metadata and replaced with logical session/target scope.
Both headless unavailability reasons and actual GUI functionality are checked. Private edits
survive mode changes; another agent's view stays unchanged. The offline suite now has 81 passing
tests, including navigation response loss without replay and disconnected UI continuation.
Debugger execution and the full combined acceptance gate remain open.

The administrative checkpoint adds fourteen configured-server leaves with actual repository,
ACL/history/checkout readback and protected publication authority. The
[server receipt](verification/server-administration.json) identifies the tested native checkpoint.
Scoped health/save/close and stateless exact number conversion passed a separate
[native lifecycle scenario](verification/facade-lifecycle.json); offline fault checks reconcile lost
save/close acknowledgments without repeating effects. Managed project lifecycle, folder/file moves,
private GZF export/import and native project archive/restore passed the
[project scenario](verification/project-files.json), preserving independent restored and research
views. Native completion journals support project response recovery; missing journals remain
blocked and readable. Later journal refinements require their own exact checkpoint. GUI controls,
debugger, archive exchange, remaining variants and final combined artifact acceptance remain open.


These are implementation choices within the agreed contract, rather than additional owner gates:

- Keep the earlier prototype storage/journals separate and intact. Do not silently migrate them
  into a new identity/schema or drop unresolved work; no legacy command-compatibility layer is required.
- Use a stable profile-scoped input identity based on immutable consumed bytes. Ghidra load settings,
  canonical model metadata, saved revisions and actual instance bindings remain tool state. Keep
  one canonical Ghidra model per target/profile in this pass; reject incompatible opening settings
  rather than inventing analysis variants. A supported local rebase/edit is tracked as program state,
  not a change to the input identity.
- Save and verify private program state before returning `applied`. If a backend operation starts
  long-running analysis, do not equate acceptance with completion. Preserve the request intent,
  report its actual state and use scoped analysis status; do not run a second conflicting mutation.
- Initially order reads with mutations within a context to ensure coherent responses. Relax read
  concurrency only with proof of consistent snapshots. Different contexts remain independently
  routable, subject to reported resource limits; a busy instance is not reassigned to another target.
- Persist caller request IDs before dispatch and bind them to effective input, not only raw argv.
  Same-ID retrieval can return unknown/partial state; it never implies automatic re-execution.
- Define nullable comments and rename/namespace collisions in typed schemas with actual backend
  normalization/readback. JSON can represent absence as null; CLI text/clear forms must be unambiguous.
- Use generated Factory help and one command definition for CLI/API. Complex values can use typed
  JSON/file inputs; they are domain parameters rather than MCP payloads or caller-built journals.
- Pin and verify compatible runtime/build inputs. Use managed dependency locations or explicit
  profile configuration; no author-only checkout/path may be required by the installed artifact.
- External actions have explicit operation outcomes and authority checks. Program rollback does
  not undo debugger execution, server administration, files or archive requests. Cleanup operates
  only on receipt-verified owned resources; explicit administration is a separate surface.

## Ordered backlog

| Item | Depends on | Concrete result and completion check |
| --- | --- | --- |
| M1-01 Native private state and publication proof | M0 | Disposable program: preserve comments, rename, types/signatures, structural/memory changes across save/reopen; publish verified private state when shared base is unchanged; detect a diverged base before publication. Verify headless/GUI save/open interoperability. This proof precedes committing the storage design. |
| M1-02 Root identity and durable contexts | M1-01 | Implement profile-scoped targets, sessions and tuple bindings; persist private view/base/pending state. Equal basenames/addresses stay separate; same bytes reuse target identity; concurrent open/retry returns one context; prototype journals remain intact. |
| M1-03 Managed local and external server profiles | M1-02 | Bootstrap owned local storage/server/repository and secrets; support explicit external server configuration. Verify credentials/ACL boundaries, wrong-profile rejection and ownership without adopting existing resources. |
| M1-04 Owned headless/GUI lifecycle | M1-03 | Start, verify, continue and release isolated contexts; introduce GUI on demand. Preserve saved state during process/mode replacement, account for live/failed startup and verify cleanup of only owned processes. |
| M2-01 Public Factory command tree and reads | M1-04 | Deliver `insight-cli`, open/status and strings→xrefs→get/decompile through generated help, CLI JSON and Factory `cli.execute`. Every research result carries scope; missing selectors fail; results are bounded and traversable. |
| M2-02 Ordinary edits and durable request identity | M2-01 | Rename/comments use automatic effect capture/readback/save. Verify read-own-writes, independent views, partial failures and restart survival. Same request-id returns original result/state; changed payload fails; lost initial-open response does not create another session. |
| M2-03 Typed schema/error/permission checks | M2-02 | Null/clear comments, address spaces, names/collisions, bounded inputs/results and backend errors are consistent across transports. Permission denial and malformed/partial responses cannot yield `applied` or a false successful result. |
| M3-01 Verified scalar merge | M2-03 | Implement original/local/shared comparison for proven comment/name effects, dependencies and explicit resolution. Exercise one-sided/equal/overlapping changes, stale expectations and nullable fields on actual saved state. |
| M3-02 Complex saved-state publication | M3-01, M1-01 | Use the proven native mechanism for verified complex local state at an unchanged shared base. Serialize publishers; a diverged base outside verified categories retains both versions as conflict. Never use raw script replay as merge or force-replace a shared version. |
| M3-03 Incoming refresh and publication gate | M3-02 | Safely receive non-conflicting changes while preserving local/shared conflicts. Any selected merge conflict publishes nothing. Per-context ordering determines whether a concurrent setter is included or stays pending; counts describe actual scoped outcomes. |
| M3-04 Publication recovery and retry evidence | M3-03 | Persist publication intent/results, verify committed history/readback and reconcile lost responses without another check-in. Unknown outcomes block the shared model across sessions. Unresolved external/local effects are retained and do not silently replay. |
| M4-01 Installed research/concurrency/crash matrix | M3-04 | Packed installed CLI: two inputs, two agents each, multiple CLI processes, conflicts, refresh, failed setup, owner/backend failures and server restart. Independent readers prove published values and preserved local work; exact artifact evidence is sanitized. |
| M4-02 Packaging and progressive skill | M4-01 | Locked offline build/test/install/relocation, Factory compatibility identity, runtime/proto/license resources and matching skill pass. Help/API/permissions/profile isolation work without source checkouts; npm publication remains outside the pass. |
| M5-01 Remaining static research/query groups | M4-02 | Complete the coverage rows for analysis/listing/xrefs/security analysis/documentation/emulation. Multi-target operations resolve explicit source/destination contexts; validate effects as well as annotations. |
| M5-02 Remaining program editing groups | M5-01 | Complete types/symbols/functions/program/batch/script rows with saved-state capture and actual effect assertions. Verify unchanged-base publication, diverged-base conflicts and partial/non-idempotent behavior. Do not widen scalar merge coverage without proof. |
| M5-03 Project/server/GUI administrative equivalents | M5-02 | Complete scoped project/file/server and GUI control rows or equivalent actions. Preserve publication authority, request outcomes and explicit selectors; exercise destructive behavior only on owned disposable fixtures. |
| M5-04 Debugger integration and native acceptance | M5-03 | Isolated managed GUI with a native macOS fixture exercises all 16 debugger operations: launch/offers/status, mappings, modules/traces, reads, breakpoints, interrupt/resume/step and stack. Persist traces where supported; a lost debuggee reports disconnected and is not silently recreated. |
| M5-05 Archive exchange | M5-04 | Both archive operations support profile configuration, payload/response validation, bounded bulk results, conflict/error counts and retained retry outcomes against an owned contract fixture. Declare the matching service contract; developing/provisioning the external service is excluded. |
| M5-06 Combined full delivery gate | M5-05 | Account for all 210 catalog operations and eight bridge controls with command/equivalence evidence. Repeat M4 on the final artifact, run all required checks/review/CI and verify installed skill/help match the full surface. Keep omissions open; only then mark delivery ready. |

The order intentionally establishes private-state publication and recovery before expanding
editing breadth. Operation groups can be implemented concurrently only where dependencies permit;
this backlog does not itself authorize launching extra agents or unrelated work.

## Acceptance evidence required

Each delivered coverage row must identify its command/equivalent, actual runtime mode, selectors,
permission behavior, typed input/output case and relevant read/effect/persistence assertion. Native
evidence distinguishes PE static research from macOS live debugging and names the tested runtime
versions. Contract fixtures prove an external adapter, not an independently deployed service's
production behavior. Do not replace missing functional evidence with an unavailable guard or an
HTTP success assertion.

M4 passing is an internal checkpoint. M5-06 is the single final gate for the owner's complete
delivery request. Documentation/count audits are complete planning inputs; none of the code work
in this backlog is complete merely because it is documented here.

The runtime/debugger hardening checkpoint passes all sixteen native debugger leaves, restored
address mappings, static breakpoint change tracking and two simultaneous GUI/LLDB processes with
one actual GUI SIGKILL. B stays connected; A restores a disconnected trace without replay.
Runtime identity now covers relevant installed SDK code/data/native/Python inputs and JDK
tools/modules/configuration. Session status pages contexts and exposes scoped uncertain external
requests. All 92 offline tests and isolated installed-package checks pass. The combined final
native matrix and installed owner-fault repetition are still required before M5-06 completion.


## API-gap P0/P1 follow-up (2026-10-15)

The owner authorized autonomous closure of every P0/P1 in [the API comparison](gaps_api_ghidra.md),
real-Ghidra verification, documentation, commit and push. G01–G07 now include native analysis
replacements, actual/parser-backed type and prototype validation, bounded integer-slot emulation,
structured common results and work budgets, qualified heuristics, entry provenance, full audited
memory creation inputs and explicit/default conventions. Saved effects retain the existing
complex-edit/conflict contract and reconcile lost native replies without replay.

[Current evidence](verification/api-gaps.json) binds source identity, 99 offline tests, focused native
cases, affected query/edit/cross regressions and packaged CLI/IPC acceptance. The earlier M0–M5
report remains evidence at its own source revision. P2/P3 do not become part of this follow-up;
no npm publication or change to shared publication policies is included.


## API-gap selected P2 follow-up (2026-10-15)

The owner authorized autonomous closure of the P2 findings, native verification, documentation,
commit and push. The selected N01–N09 workflows and G07 direct placeholder convenience are
implemented; [P2 evidence](verification/api-gaps-p2.json) identifies the independently tested
source, native groups, package and OS boundaries. New program edits retain complex-change
publication/conflict rules. Native VT is a tool object inside the existing research scope;
FID and BSim use their actual SDK databases. Live writes remain separate uncertain effects.
No automatic publication, universal DB merge or generic plugin manager was added.
