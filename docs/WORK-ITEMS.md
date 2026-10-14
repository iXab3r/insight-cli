# Full facade implementation work items

The owner selected one combined M0–M5 delivery and closed the product decisions in
[the plan](PLAN.md#closed-owner-decisions). This backlog is implementation planning, not executed
work. All items are planned. Items produce code, fixtures or exact-revision evidence inside the
existing product; they do not add separate CLIs, a generic plugin framework or agent-visible jobs.

## Engineering defaults

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
in this backlog has been implemented by this planning update.
