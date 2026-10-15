# Verification scope

## Current G01–G07 P0/P1 closure

[API-gap closure evidence](api-gaps.json) records implementation `3c6450d8a05745227caae0ad983388e563eaf551`,
99 passing offline tests and eight passing native groups: 17 focused cases, affected query/edit/cross regressions and installed
CLI/IPC/OS-keyring checks. `scripts/proof-api-gaps-matrix.mjs` runs the eight native groups
sequentially with before/after source identity checks; `proof-api-gaps.mjs` can run the focused
closure cases by itself. All data, local repositories, processes and accounts are owned fixtures.

The new tests exercise real x86/x64 PE and SysV ELF computation, unsupported AArch64/floating-point
rejection, partial scans, a 5000-symbol work-budget case, saved memory/signature effects, lost-answer
reconciliation without duplicate creation and two-agent publication/refresh. Installed acceptance
executes the packaged native query kernels and saved-memory digest verification through Factory IPC.
The source/receipt/artifact hashes identify the tested candidate; private paths/logs remain outside
this directory. Run with `--ack-disposable` and explicit runtime/compiler paths as below.

The final prepared tarball matches the artifact exercised by installed native acceptance:
SHA256 `507a357e913b865a10c71b51d206e5597ace7adac2c69677da5c02dea3b94a6c`.
The separate locked offline package/relocation check also passes.

This supplements the historical full matrix rather than claiming a new GUI/debugger/seven-fault
matrix for unchanged surfaces. Native Windows/Linux, generic DB merging and npm publication remain
outside this closure. Constant signatures and supported emulation/regex policies are bounded,
explicit catalogs; remaining upstream scans report their unbounded work policy.

## Historical combined full facade acceptance

The [full report](full-facade.json) records the completed M0–M5 gate: 93 offline tests, 23 native
groups and the exact installed artifact/source hashes. [Operation evidence](coverage-evidence.json)
accounts for all 210 pinned operations and eight bridge equivalents. The installed matrix uses
real Factory IPC, OS-keyring accounts, two inputs/four contexts and seven owner SIGKILL phases.
[Installed packaged runtime](installed-packaged-runtime.json) additionally verifies native loading
from the installed bundled JAR without a source-checkout override.

Implementation revision: `300884e3c9be0928a8e1659e088aa2144c2c70b4`. Tarball SHA256:
`64d52ed60e896e973596a243be66c3fe4bab9884fee2f1480956da4184e31e88`. Native acceptance is macOS,
Ghidra 12.1.2, Java 21 and Node 24.21.0; other native OS acceptance is deferred. Archive evidence
checks the integration contract against an owned fixture. External-service deployment, automatic
strategies, universal native DB merge, execution resurrection and npm publication are excluded.

Every runner is under `scripts/` and requires `--ack-disposable` plus explicit `--java`,
`--ghidra-home`, `--mcp-jar`, `--clang` and `--lld` paths as applicable. Run
`acceptance-facade.mjs --faults` for installed owner failures; native runners refuse CI and use only
owned fixtures. The full report lists all 23 runner names and individual receipt hashes.
Historical prototype/checkpoint notes below do not limit or replace the completed combined gate.

## Historical and individual checkpoint scope

The default suite uses offline synthetic publishers and real child-process SIGKILL at acceptance,
local application, save, persisted check-in intent, publication acknowledgment and verification.
It checks journal survival, recovery without another check-in, live-owner refusal, idempotency,
conflicts, wrong bindings, partial results, permission gates, profile isolation and protocol output.
The isolated package proof uses locked offline npm installation, spaces/Unicode relocation and
the installed skill/resources without a Factory source checkout.

Native acceptance is separate: `scripts/acceptance-ghidra.mjs --ack-disposable --faults` also
requires `--ghidra-home`, `--java`, `--mcp-jar`, `--python`, `--bridge-directory`, `--clang` and
`--lld`. It creates and owns a disposable server, repository data, test accounts and locally
compiled PE EXEs. Runtime logs and paths stay in the private fixture directory. Only sanitized
assertions/counts belong in this directory or public issue evidence.

The two-program matrix uses equal basenames, two readers and dedicated MCP bridges per program,
four durable proposals, duplicate submission and three competing CLI calls. Independent readers
verify exact published comments, untouched sentinels and history after a clean server restart.
Fault repositories separately exercise owner death at queued acceptance, actual comment application,
save, before check-in, after committed check-in and independent publication readback. Native
credentials and dynamic publisher tokens use Factory's OS secret store in a unique fixture namespace.

Pre-intent failed stages preserve local work and stay blocked until explicit operator cleanup
releases the identified checkout. A missing batch marker after persisted check-in intent remains
uncertain and cannot be abandoned or replayed. Committed markers are reconciled by history,
independent readback and checkout-release proof. Receipt-verified leftover Ghidra processes and
fixture secret keys are cleaned by the runner. No test terminates all server checkouts.

The supported evidence is Ghidra 12.1.2, Java 21 and the pinned GhidraMCP 7.0.0 contract. Tiny PE
fixtures do not establish capacity for large databases, other runtime versions, an atomic remote
batch or native database merge. CI never runs native acceptance.

## Recorded runs

[Native snapshot proof](native-snapshots.json) establishes the M1-01 prerequisite on an owned
tiny PE fixture: private edits survive save/reopen and headless/GUI interchange, a complete saved
database publishes at an unchanged base, independent readers verify its comments/name/type/
signature/memory and original input identity, and a stale base creates no new version. It uses
the native buffer-stream and change-set protocols rather than replaying a script. Source hashes
identify the exact proof scripts. This does not establish automatic native database merging,
general change-set completeness or the final facade's recovery/acceptance.

Run `scripts/proof-native-snapshots.mjs --ack-disposable` with `--ghidra-home`, `--java`,
`--mcp-jar`, `--clang` and `--lld` for this prerequisite. It refuses CI and owns its temporary
server, projects and GUI processes. Its test-only credentials are synthetic; no user project
or existing server is selected.

[Managed server proof](managed-server.json) verifies a locally owned server/repository, random
credentials initialized before listeners, read-only reader versus publisher authority, authenticated
process identity, refusal of wrong authority/token/profile, external connection without process
ownership and repository retention after restart. Run `scripts/proof-managed-server.mjs` with
`--ack-disposable`, `--ghidra-home`, `--java` and `--mcp-jar`.

[Durable context proof](durable-contexts.json) verifies four private views across two EXEs and two
research sessions. Equal filenames/function addresses do not alias targets; A's comment stays
private from B and the other input; headless/GUI switching, close/reopen, backend SIGKILL and a
replacement runtime retain saved unpublished work. A fifth reservation exercises the capacity
refusal, and a wrong source identity aborts startup without replacing another context. Run
`scripts/proof-contexts.mjs` with the snapshot proof's runtime/compiler flags. Both runners refuse
CI and use synthetic credential adapters; they prove native mechanisms rather than the installed
Factory facade. Their source hashes identify the exact exercised code. M2–M5 acceptance remains
required. The default offline suite currently passes 33 tests, including content identity,
four-process open reservation, request outcomes and stale-write/atomic-acknowledgment checks.

[Native Factory research proof](research-cli.json) exercises the public command tree against an
owned PE/server: initial open retry, literal strings→xrefs→containing function→decompile, verified
rename/comment saves, independent A/B views, clear/null and the same scoped JSON-RPC commands.
Run `scripts/proof-research-cli.mjs` with `--ack-disposable` and the context proof's runtime/compiler
flags. Its Factory fixture provides synthetic credentials; it does not replace final installed IPC,
OS-credential, crash, merge/refresh or full-catalog acceptance. The installed offline package proof
has been updated for `@ixab3r/insight-cli` and the matching public skill/resources.

| Evidence | Revision | Result |
| --- | --- | --- |
| [Native crashes](native-crashes.json) | 31eb08d | Two-program matrix and all six native owner crash phases passed |
| [Native lifecycle](native-lifecycle.json) | d8f700a | Failed bridge cleanup, dead-worker reuse, reader checkout/check-in denial, full matrix/restart and bridge cleanup passed |
| Offline suite | d8f700a | 25 tests passed on Node 24.21.0 |
| Isolated package | d8f700a | Locked offline install, skill/resources, JSON/RPC, permission denial and relocation passed |
| Independent review | d8f700a | PASS after both reader lifecycle findings were corrected |

The lifecycle corrections did not change publication/recovery semantics, so the earlier native
crash evidence remains applicable. Each native receipt identifies the exact packaged artifact.
Factory IPC a2094fb separately passed 1306 tests, external package consumption and independent
review; its [PR #51](https://github.com/iXab3r/EyeAuras.CliFactory/pull/51) CI is green.
Public evidence contains counts, hashes and assertions only; runtime paths, credentials and raw
logs remain outside this repository. No npm registry publication was performed.

[Native session merge proof](session-merge.json) exercises seven actual shared revisions through
the public Factory command tree: A/B private views, safe refresh, mixed/overlapping conflict gates,
stale and explicit resolution, committed response loss and independent complete-buffer recovery.
Structures, a function signature, memory and a scalar edit after the local signature change publish
at an unchanged base; a diverged structural result retains its private version as a conflict.
Run `scripts/proof-merge.mjs` with the research proof's runtime/compiler flags and
`--ack-disposable`. The exact source hashes and tested limits are in the receipt. This uses a
source-package Factory fixture and synthetic credentials; final installed IPC/OS secrets, the full
crash matrix and full catalog/debugger/archive gates remain separate acceptance work.

[Installed session checkpoint](installed-sessions.json) exercises the packed facade through its
real Factory IPC owner with unique OS credential accounts. It records four contexts on two inputs,
parallel CLI callers, conflict retention across owner restart, managed server restart and owner
SIGKILL at accepted, local effect, local save, local acknowledgment, published, verified and
publication-intent stages. A genuinely unproved publication stays blocked. Counted backend
dispatches verify that reconciliation does not repeat setters/publication. Run
`scripts/acceptance-facade.mjs --ack-disposable --faults` with the same native runtime/compiler flags.
Its barrier wrapper and isolated application identity are fixture-only; the installed runtime and
resources were compared byte-for-byte with the source build. The receipt retains the exact
artifact hash and tested source hashes. Later query input/error refinements are outside that
artifact; all reliability cases must repeat on the completed full facade.

[Native query checkpoint](query-contracts.json) records 74 scoped public query calls and typed
result checks against an owned PE/import DLL. Known input assertions cover function/P-code data,
structure layout, enum members, data type size, imports, properties/bookmarks, strings/xrefs and
controlled emulation (integer result 19 and a known candidate hash match). Run
`scripts/proof-queries.mjs --ack-disposable` with the same runtime/compiler flags; `--group` narrows
an exploratory diagnostic run and does not produce the full known-value assertion claim. The
receipt retains source/runtime hashes and limits. Program setup through the fixture seam does not
establish public editing coverage; script inventory and other result variants remain open.

[Structural editing checkpoint](structural-mutations.json) records 31 actual saved effects,
including type cloning without altering the source, layouts/categories, exact 64-bit enum/property
values, labels/references, bookmarks/options, memory flags and rebasing. The default bundled bridge
runtime passed complete private-state publication and another session's refresh. Run
`scripts/proof-mutations.mjs --ack-disposable` with `--java`, `--ghidra-home`, `--clang` and `--lld`;
`--mcp-jar` is an optional exact-hash override. The receipt's hashes identify its original tested
checkpoint; later edits need separate evidence and the combined installed delivery gate.

[Function/batch editing checkpoint](function-edits.json) records 22 saved function/variable/tag,
script, comment/documentation and analysis effects with the bundled bridge. Every request retry
retrieves its result; full publication and refresh expose the final function to another session.
The runner also exercises the two data-inspection queries. Run `scripts/proof-functions.mjs`
with the structural runner's flags. It checks source hashes at the start and end. GUI navigation,
remaining editing variants and the final installed acceptance remain outside this checkpoint.

[Data/member/documentation checkpoint](data-edits.json) records the six remaining ordinary
program editing operations on an owned PE. Independent C parsing verifies saved imported types;
classification/global data, implicit `this`, quoted/newline documentation and instruction-seed
repair checks precede acknowledgment. The final snapshot publishes and refreshes into another
session. Run `scripts/proof-data.mjs` with the same disposable/runtime/compiler flags. The
source hashes remain stable across that run. Cross-target transfers, editing variants, server/
GUI/debugger/archive and the combined installed delivery gate still require their own evidence.

[Cross-context reads](cross-reads.json) prove four comparisons using declared private contexts,
two inputs with equal filenames and opposing callers. [Documentation transfer](documentation-transfer.json)
proves preview, saved destination checks, request retry, no-op counts, unchanged source and
complete publication. [Temporary cleanup recovery](cross-recovery.json) injects a failed owned
temporary-program close, then proves the next call releases that retained stage and returns only
the declared contexts. Run `scripts/proof-cross.mjs`, `scripts/proof-transfer.mjs` and
`scripts/proof-cross-faults.mjs` with the same disposable/runtime/compiler flags. Each checks stable
source hashes. Later scalar-projection/recovery refinements have offline coverage; native all-category
variants, cancellation/owner faults and final installed repetition remain separate gates.

[Server administration](server-administration.json) records fourteen public leaves on an owned
local server: repository creation/listing/files/history, ACL users/readback, checkout inspection
and verified termination, disconnect/reconnect and request retries. Run
`scripts/proof-administration.mjs` with the same disposable/runtime/compiler flags. Administrative
unknown-outcome recovery and external-profile variants remain separate acceptance work.

[Facade lifecycle](facade-lifecycle.json) verifies scoped health, save without publication, close
retry, process release, reopening retained work and another agent's unchanged view, plus exact
64-bit conversion. Run `scripts/proof-facade-lifecycle.mjs`. Offline tests additionally cover lost
save/close acknowledgment. The receipt predates subsequent project integration.

[Managed projects and files](project-files.json) verifies create/open/close/delete, folders and
moves, private GZF export/import, project archive/restore, retries and independent restored files.
Run `scripts/proof-projects.mjs`. This receipt identifies the initial project checkpoint; native
completion-journal recovery, subsequent refinements and final installed repetition require their
own evidence. Projects and file exports do not publish or replace a selected research context.

[Project response recovery](project-recovery.json) repeats that whole scenario after adding native
completion journals. A deliberately lost creation response is recovered from its exact saved
request/result pair without another creation. Run `scripts/proof-project-recovery.mjs`; absent
completion proof still blocks effects. Its hashes identify this later checkpoint.

[Owned GUI controls](ui-controls.json) verifies headless cursor unavailability, real owned tool
inventory, browser navigation with cursor readback, prompt-policy enable/status/disable, request
retry, logical program scope and private work across GUI/headless transitions. Another session
retains its independent view. Run `scripts/proof-ui.mjs` with the same disposable/runtime/compiler
flags. The source hashes identify this checkpoint; debugger and final installed acceptance remain
separate. Offline tests cover lost navigation response observation and disconnected UI actions.

[GUI response recovery](ui-recovery.json) repeats those controls with a lost successful goto
response and counts actual navigation dispatches. Continuation observes the live cursor without
another goto. It also exercises the correction for a headless stop receipt retained when the same
project root becomes GUI: that earlier receipt cannot prove whether the replacement process ended.
Current PID/binding verification remains required. Run `scripts/proof-ui-recovery.mjs` with the
same flags. Native debugger execution and final installed fault repetition remain separate gates.

[Owned native debugger](debugger.json) covers all sixteen leaves and three step kinds against
a synthetic Mach-O/LLDB process. Exact memory is read from the target, independently saved
trace databases reopen disconnected, static private work survives and another session stays
unchanged. Run `scripts/proof-debugger.mjs` with the disposable/runtime/compiler flags.
[Debugger response recovery](debugger-recovery.json) repeats that scenario with a lost successful
step response: four intended steps cause exactly four native calls, repeated retrieval causes
none, selected-context close succeeds and reopening does not launch a target. Run
`scripts/proof-debugger-recovery.mjs`. Backend/owner crash variants and the final installed
artifact remain separate gates.

[Archive exchange](archive-exchange.json) verifies the two pinned payload operations on private
native PE data against an owned local HTTP contract fixture. It checks preview without requests,
names/comments/hash fields, created/updated/conflict counts, same-ID retrieval and a deliberately
lost external response without another POST. Another session is unchanged and private research
remains usable. Run `scripts/proof-archive.mjs` with the same flags. This proves the integration
contract; developing or deploying an independent archive service is excluded.

[Session save and local discard](lifecycle-selection.json) verifies explicit session-wide saving
and scalar/complex discard on two owned native inputs. The old private snapshot remains readable,
discard restores the original base while another agent's newer shared state stays intact, and a
lost local acknowledgment reconciles without another close. Run
`scripts/proof-lifecycle-selection.mjs`. `scripts/audit-coverage.mjs` separately verifies current
command/equivalence accounting for all 210 catalog paths and eight bridge controls; it does not
claim behavioral acceptance from command presence.

[Scalar projection](scalar-projection.json) exercises an ordinary name/comment edit followed by
complex batch/deletion effects. The actual saved local value replaces the earlier scalar
projection, including lost-response recovery without another batch dispatch. Refresh preserves
that value against a conflicting shared edit; complex divergence publishes nothing. Deleting a
previously renamed function publishes as a complete saved result at an unchanged base, and an
independent refresh does not recreate its stale name. Run `scripts/proof-scalar-projection.mjs`.
The query runner also repeats all 74 read adapters, including the two read-only implementations
whose upstream metadata says WRITE, with stable source hashes checked at both ends.

[Debugger backend crash](debugger-crash.json) performs a real SIGKILL through the original GUI
child handle. The owned LLDB child exits after verifying termination of the launched inferior;
the exact fixture PID is observed to have ended. The retained uncertain trace candidate survives
and reopens disconnected without another launch/action. Private A work and independent B remain
intact. A working directory containing spaces and an apostrophe is checked through the actual
inferior. Run `scripts/proof-debugger-crash.mjs`. The refreshed debugger recovery receipt repeats
all sixteen operations and normal live close with the same child lifecycle implementation.
The final installed owner/process matrix remains a separate gate.

The refreshed debugger checkpoint additionally verifies static breakpoint metadata as pending
private program state, CPU steps without extra program edits, and both mapping directions after
trace restoration into a replacement project. Restored mappings retain their saved ranges and
lifespans while relocating only the recorded context-owned program URL. The crash checkpoint
now uses two simultaneous GUI/LLDB contexts: killing A terminates its inferior while B remains
connected and reads exact memory. Both receipts identify the current runtime-input hardening.
The offline suite passes 92 tests; final combined/installed acceptance remains separate.

[Query output variants](query-variants.json) adds 21 native cases: bulk/filtered listing comments,
category/hash inventories, a program option group, deprecated data-format values, five call-graph
formats, six graph-analysis modes and multi-function/assembly selectors. It exposed and verifies
three corrected contracts: bulk comments use `results`, the pinned data listing always returns
JSON, and `json_edges` has address-based edges with its own counts. The offline suite passes
93 tests. Run `scripts/proof-query-variants.mjs` with the same disposable/runtime/compiler flags.
This checks representative result branches; it does not claim exhaustive input combinations.

The refreshed server-administration receipt verifies canonical root and nested SDK item paths.
Ghidra's `RepositoryItem.getPathName()` duplicates the separator at root; the native adapter
constructs the path from its parent/name before readback and protected-checkout checks. A real
owned canonical-program checkout survives repository-wide termination, while an ordinary
fixture checkout is terminated and verified absent. The fixture releases only its recorded
checkout afterward. This checkpoint follows the query-variant corrections.
