# Combined facade acceptance

The later [real-EXE CLI walkthrough](AGENT-CLI-WALKTHROUGH.md) has its own source/artifact
identity and focused regression evidence. The 33-group result below remains bound to its
recorded build; it is not automatically attributed to subsequent changes.

**Passed:** 118 offline tests, all 33 native groups and isolated package checks. The
[current report](verification/full-facade-current.json) binds the exact source/artifact to the
assertions below, including seven manual and two automatic real owner SIGKILL phases.

The final gate repeats the M0–M5 workflows and the selected P0–P3 additions against one
unchanged build. Historical reports retain their original source identities. Passing an older
group is not a substitute for repeating it on the combined candidate.

## Agent workflow and failure checks

| Scenario | Required observed result |
| --- | --- |
| A and B open two EXEs | Two sessions, two immutable targets and four private contexts. Equal basenames and function addresses do not alias either target. |
| Separate CLI processes edit private copies | A reads its own saved changes; B and the other EXE retain their original values. Explicit session/target scope routes every call. |
| A publishes; B continues | A's publication is independently read from the shared repository. B's working view stays private until refresh. |
| B refreshes with disjoint local work | Safe incoming changes arrive and B's unpublished changes survive. B can subsequently publish the combined result. |
| Local and shared values conflict | Merge publishes nothing, including otherwise safe edits. Refresh retains the local value and exposes the shared value. A stale resolution precondition rejects. Explicit resolution is checked again at publication. |
| Complex saved edits diverge | An unchanged shared base accepts a verified whole saved result. Unproved divergent categories preserve both versions as a conflict. |
| Owner/backend/server exits | Continuing the same session and target retains acknowledged private work, conflicts and request identities. Only owned processes and repositories are used. |
| A successful response is lost | Repeating the same request ID retrieves or reconciles the original result. Counters and repository history prove no duplicate setter/check-in. |
| Publication cannot be proved | The lane remains unknown/blocked. A retry does not manufacture success or repeat check-in. Saved local work remains available. |
| Opt-in synchronization | After-edit/after-save publication and before-edit refresh use the same conflict and recovery boundaries. Policies survive owner replacement; default behavior remains manual. |
| Tool-specific workflows | Native queries/edits, projects/server, cross-context transfer, archive integration, GUI/debugger, SDK additions and managed extensions pass their separate known-value assertions. |

The installed Factory IPC test kills the actual owner at seven manual phases: `accepted`,
`local_effect`, `local_save`, `local_ack`, `published`, `verified` and `publication_intent`.
It additionally kills two automatic workflows at `local_ack` and `verified`. Fixture-only barriers
hold the identified owner at the intended point; the product package contains no fault hooks.

## Reproduce

After the locked dependency setup, use Node 24, Ghidra 12.1.2, Java 21, clang and lld-link.
Set the variables below to the installed tools and the bundled pinned MCP JAR:

```sh
node scripts/acceptance-full.mjs --ack-disposable \
  --java "$INSIGHT_JAVA" --ghidra-home "$INSIGHT_GHIDRA_HOME" \
  --mcp-jar "$INSIGHT_MCP_JAR" --clang "$INSIGHT_CLANG" --lld "$INSIGHT_LLD"
```

The local-only runner first builds and runs the offline suite, then verifies a locked offline
package installation, help/JSON/RPC, permissions, hosted IPC shutdown and relocation through a
path containing spaces and Unicode. It retains that isolated package for native P3 tests. The
installed multi-agent/fault test packs independently and must produce the identical tarball hash.

Focused groups use direct native fixtures or Factory's in-process test fixture. P3 runs that
fixture against resources from the isolated installed package. The installed reliability group
separately exercises actual CLI processes, the Factory IPC owner and OS-keyring accounts. Every
native group operates real owned Ghidra; the in-process fixtures do not replace the IPC crash gate.

All 33 native runners execute sequentially with independent owned inputs, projects, repositories,
processes and cleanup. The gate hashes runtime TypeScript, compiled JavaScript, Java/JSON resources,
all proof scripts/fixtures, offline tests and pinned dependencies. It checks those identities after
packaging and every native group. Changing a bound input invalidates the run; a failed group stops
the gate. GUI and keyring tests require an interactive macOS host. Ordinary CI remains offline.

The printed diagnostics directory contains progress, private logs and individual receipts. Public
evidence contains sanitized assertions, counts and hashes; private paths, credentials, binaries and
native databases do not belong in the repository.

## Limits

This is representative known-value acceptance of the selected contracts, rather than every SDK
overload or every input combination. Static fixtures are synthetic PE/ELF inputs; debugger tests
use a separately owned host-native executable. The larger SDK fixture checks 32 MiB initialized
memory, 20000 symbols and 1000 types. These cases do not establish arbitrary production capacity.

Native combined acceptance is macOS. Earlier selected headless Windows/Linux checks keep their
own source identity. Complex semantic merging, resurrection of crashed CPU execution, building or
deploying an archive service, production migration and npm publication remain outside this gate.
