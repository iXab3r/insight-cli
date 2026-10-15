# Verification scope

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

[Native query checkpoint](query-contracts.json) records 72 scoped public query calls and typed
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
