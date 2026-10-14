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
