# Native multi-agent merge: prototype and integration proposal

Status: the owner accepted the [native merge ownership](DESIGN.md#native-merge-ownership)
boundary on 2026-10-26. Implementation remains a disposable research prototype; the
production CLI was unchanged at that prototype revision. The subsequent
[primary CLI integration](NATIVE-CLI-INTEGRATION.md) has its own implementation/evidence
boundary. The implementation sequence below is a historical proposal, not an
accepted new public contract.

Before implementing the migration, read the
[Ghidra Server utilization audit](GHIDRA-SERVER-UTILIZATION-AUDIT.md). It traces the
active facade path and identifies remaining ancestry, Update, authority, lifecycle
and migration gates that the retained merge proof does not establish.

The subsequent [checkout lifecycle proof](NATIVE-CHECKOUT-LIFECYCLE.md) exercises
credential-separated offline editing/reopen, dirty and clean native Update,
check-in and owned-project deletion. Its separate receipt closes those bounded
prototype gates; it does not integrate the production CLI or establish recovery/GC.

## Ownership of merge semantics

The native path must use Ghidra's multi-user three-way merge over the original,
private and latest programs and their native change sets. Ghidra selects its own
resolvers and resolves object identities and dependencies. Adding more scalar fields
to insight-cli's merge implementation would retain the wrong architecture.

The existing coordinator calls `scalarMerge` and `scalarRefresh` in
`skills/ghidra-coordinator/src/research.ts`; their implementation is in `src/merge.ts`
under that workspace. Complex changes against a divergent shared revision are rejected.
That scoped publication implementation does not provide general native merging.

The prototype's `HeadlessProgramMergeManager` subclasses the stock
`ProgramMultiUserMergeManager`. It does not override resolver creation or maintain a
category list. It drives the stock resolvers synchronously and stops when a native
resolver requests a human decision. Test-only source patches bridge GUI assumptions;
one separate semantic compatibility fix in `MemoryMergeManager` is explicitly recorded.
This proves a bounded integration approach, not unmodified headless support upstream.

Ghidra Server stores shared versions and checkout metadata. Its client-side native
merge engine combines a checkout with the latest server version before check-in.
In insight-cli that native client executes inside the service-owned worker. Merging
through the shared server does not require moving merge semantics into TypeScript
or claiming that Ghidra Server itself runs the program resolvers.

The coordinator retains responsibility for target binding, server authorization,
request journals, checkout ownership, execution serialization, outcome reconciliation,
conflict transport and working-copy disposal. Factory retains host/IPC ownership.

## Disposable proof

Run `scripts/proof-native-merge.mjs` with explicit software paths, an existing output
base and `--ack-disposable`. It creates an isolated loopback Ghidra server, synthetic
program and ordinary independent checkouts. It never opens a product profile. Sources,
native outputs and failed working copies remain in the owned evidence directory.
Installed runtime JARs are hashed before and after; generated patched classes stay
inside the disposable directory.

Three clients edit from the same server revision in separate JVMs. The fixture covers
functions/signatures/locals, namespaces/symbols, creation/deletion, instructions and
defined data, bytes/block attributes, structures/enums/unions/typedefs and their use
bindings, references/comments/bookmarks/equates, properties/options/trees/tags,
register context and external functions/library paths. A second scenario combines
three independent edits to one function. Negative cases exercise type, signature,
byte and both directions of block-comment deletion/update conflicts.

Independent server readback compares the recorded object projection and checks history;
it does not establish whole-database equivalence. Successful checkouts are released and
six working projects are deleted. Rejected work retains its recorded projection and
original checkout identity/base; deleting an unpublished project is refused.

The latest return-type regression and renewed broad native run belong in
[return-type evidence](verification/native-return-type-regression.json).
The [extended evidence](verification/native-headless-merge-extended.json) records the
earlier candidate and its then-unresolved classification.
The [initial report](verification/native-headless-merge-prototype.json) is historical.

## Observed defects and remaining limits

* Stock Ghidra 12.1.2 loses an incoming block comment when the private copy's comment
  remains null. Its deletion/update conflict test is also asymmetric. The disposable
  prototype applies a pinned, separately identified native compatibility fix and tests
  both directions; production adoption needs an explicit maintained upstream patch.
* A function-conflict display path can swallow a null GUI-panel exception and report
  check-in completion. The headless adapter must reject before entering that display
  path. The failed run and independent history/readback are retained.
* Concurrent first-time `float`/`double` return types exposed that same missing headless
  conflict-display seam. A [minimal before/after regression](NATIVE-RETURN-TYPE-REGRESSION.md)
  establishes correct native detection/remapping and corrects the previous unresolved
  classification. No type-merge semantic patch is needed for this case.
* A separate attempt to preseed those builtin types caused a datatype conflict during
  a positive scenario; its cause is unclassified and its failed fixture is retained.

## Concrete implementation sequence

1. **Close the native engine/headless boundary.** Retain the first-time type-loss
   regression and ensure every native conflict-display path reaches the headless
   conflict handler before GUI assumptions. Maintain version-pinned source/provenance for every required native
   change. Add native refresh/update tests and structured native conflict extraction;
   the current prototype only refuses conflicts and does not apply resolutions.
2. **Persist one real checkout per working context.** Store repository/path, checkout
   ID, native base version, ownership and working-project location. Bind JVM launches
   to that same saved project. Preserve native ancestry/change sets across save,
   restart and arbitrary scripts, including creations and deletions. A process restart
   must not create another permanent context copy.
3. **Replace the native publication path.** Route merge/check-in and refresh through
   native APIs, removing `scalarMerge`/`scalarRefresh` as semantic authorities on this
   path. Journals may describe changes for diagnostics but cannot decide whether a
   native object can merge. Preserve the existing public CLI until its revised conflict
   contract is separately specified and accepted.
4. **Make publication recoverable.** Journal intent before native writes. After a
   successful check-in verify server history and independently read published content
   before releasing the context. Unknown outcomes freeze the lane with local data
   intact; reconcile history/content before any retry. Test interruption at every
   boundary, restart, server-head races and distinct-user server authorization.
5. **Implement the working-copy lifecycle.** On verified publication, release the
   checkout, close native handles and drop the owned private project. Continued work
   receives a new checkout from the verified shared version. Conflicts and unknown
   outcomes retain the current copy. Checkpoint publication during a long task follows
   the same cycle; it does not require keeping every previous copy.
6. **Add GC and explicit migration last.** GC considers ownership, active leases and
   heartbeat, native checkouts, unresolved journals and verified publication state.
   Age alone cannot delete live/unpublished work. First ship inventory/dry-run and
   bounded deletion of demonstrably disposable owned copies. Existing `ec2-native`
   data needs its own explicit inventory/migration acceptance; this prototype does
   not touch it.

Production acceptance must include real disposable imported programs, multiple agents
and users, newly introduced type identities, native update, conflict decisions, restart
and unknown-outcome recovery, followed by measured disk use over repeated cycles.
Memory-layout edits and arbitrary overlapping structural edits require their own native
acceptance; the current synthetic projection does not establish them.
