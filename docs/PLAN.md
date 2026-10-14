# insight-cli milestone plan

The owner requested documentation and milestone planning on 2026-10-14. The product contract is
in [DESIGN](DESIGN.md#agreed-product-model), with concrete [CLI scenarios](CLI-SCENARIOS.md).
This plan proposes implementation order and acceptance gates; it does not implement the facade,
approve npm publication, or declare the existing prototype ready for the agreed product.

## Current baseline

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
| M0 | Documented contract, walkthroughs, coverage audit and acceptance plan | — | Contract/plan recorded; full operation audit and exact schemas still planned |
| M1 | Open and continue isolated contexts for several inputs and agents | M0; relevant M1 decisions | Planned |
| M2 | Agent reads and makes recoverable ordinary edits | M1; relevant M2 decisions | Planned |
| M3 | Publish, refresh and resolve supported conflicts | M2; relevant M3 decisions | Planned |
| M4 | Installed first slice passes the complete concurrent/crash scenario | M3 | Planned |
| M5 | Broaden the facade to the inventoried Ghidra/MCP/server functionality | M4; operation-specific decisions | Planned |

M1–M3 are implementation checkpoints. M4 is acceptance of the first usable research slice.
M5 remains part of the intended product; the first slice is not a permanent comments-only ceiling.
Dates and effort estimates are not assigned before the M0 coverage audit and M1 storage/isolation
work establish the actual gaps.

### M0 — Contract and scope

- Preserve agreed targets, sessions, tool contexts, private views, explicit scope, per-context
  mutation ordering, conflict resolution and continuation semantics.
- Keep example leaf names/results distinguishable from executable prototype commands. Define the
  first-slice command/output/permission map using Factory, including scoped errors and bounded reads.
- Inventory the pinned Ghidra/MCP/server operations. For each real operation record the intended
  facade command, scope, permissions, local effect, persistence requirement and merge support.
  This is a planning table, not a new runtime registry or plugin framework.
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
comments and function names once their exact field contracts are settled. The manual path must
reproduce the agreed scenarios; this does not choose a global default or automatic policy.

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
- Mixed conflicting and non-conflicting changes follow the explicitly selected partial-publication
  rule. Counters and failure status describe what actually happened. Multiple backend calls are
  not advertised as one atomic transaction without proof.
- Publication is serialized per shared target/tool model across sessions. A fresh verified
  publication base, readback and durable outcome checks prevent stale native check-in and duplicate
  publication. Unknown outcomes block publication affecting that model, including other sessions.
- Unsupported merge scopes return a clear limitation while preserving exploratory local work.
  Functional operation coverage and automatic merge coverage remain separately documented.

### M4 — Recovery, installed delivery and first-slice acceptance

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
  review and CI complete before the source PR becomes ready for this slice.

Packing and source delivery do not authorize npm publication, production migration or replacement
of an existing RE workflow. Report resource/capacity limits from the exercised cases.

### M5 — Broader Ghidra facade

Use the M0 inventory to expand actual operation groups in reviewable increments: analysis and
listing, symbols and types, program/project/server management, and other available capabilities.
Order increments by real research needs. Every group needs public help/examples, permissions,
scope validation, failure/continuation semantics and operation-specific acceptance.

Exit: each operation in the agreed inventory is exposed through the facade or has an agreed
equivalent replacement. Unsupported/unimplemented functional entries remain open; documenting a
limitation does not count as delivering that operation. Automatic merging is claimed only for
scopes with defined and verified semantics. Agents continue using logical session/target scope
rather than backend details.

## Decisions at the point they matter

| Before | Decision needed | Constraint already agreed |
| --- | --- | --- |
| M1 storage/open | Prototype-state transition; profile-scoped identity; backend binding and load-setting compatibility; lost creation response | Immutable input targets, root sessions, no silent reset or loss of pending work |
| M2 public leaves | Exact schemas, bounded traversal, scoped errors, interrupted/lost local-write responses, reads overlapping mutation | Factory owns transports/output; explicit selectors; acknowledged edits recoverable |
| M3 supported fields | Null/absent comments, rename identity/collisions, resolution syntax for each supported field | Preserve local work; explicit original/local/shared conflict; stale resolution rejected |
| M3 multi-change operations | Refresh granularity; whether a conflict prevents the whole merge or allows supported non-conflicting changes | Accurate results; no silent overwrites or unproved atomicity |
| Automatic strategies, if requested | Publication timing and automatic incoming refresh | Existing walkthrough uses explicit commands; no automatic default selected |
| M5 operation groups | Scripts, batch analysis, structural/type changes and other non-scalar effects | Full functional facade remains the goal; no universal database auto-merge promise |

Pause/finish/reopen workflow expansion, a hypothetical second tool, cross-tool transactions and a
general plugin framework remain deferred. Add them only when a concrete consumer scenario needs them.

The next implementation-planning task is the M0 operation/gap audit and the M1-specific decisions,
not another session lifecycle design. Track delivery under [Factory #49](https://github.com/iXab3r/EyeAuras.CliFactory/issues/49)
and keep the existing consumer PR in draft until the relevant acceptance gates pass.
