# Native checkout lifecycle: disposable prototype

This is the follow-up to the [server utilization audit](GHIDRA-SERVER-UTILIZATION-AUDIT.md)
and [native merge prototype](NATIVE-MERGE-PROTOTYPE.md). It exercises a saved native
checkout across credential-separated JVMs, native Update, publication and project
deletion. Production CLI routing, migration and GC are outside this prototype.

## Authority and saved identity

The runner creates a fresh loopback server and repository. Bootstrap creates two
accounts with random passwords: publisher has native administrator permission,
reader has read-only permission, and anonymous access is disabled. Passwords enter
authorized processes through environment variables; they are absent from request
JSON, Java argument files and worker environments.

The service creates ordinary independent checkouts in separate native projects.
A worker opens the existing project with a noninteractive authenticator that refuses
authentication. The saved repository binding remains attached but disconnected;
the worker can open, edit and save its checked-out local program. It receives no
publisher password, reader password, SSH key or PKI keystore. Every operation uses
a separate JVM, including reopen and subsequent publication.

The proof compares the saved project path, native file ID, local version and bounded
program projection across restarts. It also compares native datatype/symbol change
and addition arrays and the changed address set. Authorized reopen verifies the
original server checkout ID and base. It neither imports a packed program nor
creates a replacement context during reopen.

This is credential separation for cooperative service-launched processes, **not an
OS sandbox**. Hostile code running as the same operating-system user can inspect
other accessible processes/files; that is not an authority guarantee of this proof.

## Executed scenario

1. Publish synthetic baseline R1. Reader checkout is rejected by native permission
   checks. Publisher creates normal independent A/B checkouts from R1.
2. Separate workers edit functions, signatures and types, including object creation
   and deletion and the extended fixture's native categories. Worker B exits and
   reopens the same saved project. Its native change-set observations are unchanged.
3. Worker B's check-in fails with `NotConnectedException`. An independent reader
   still sees R1 and both outstanding checkouts. Publisher reopens B and verifies
   its original checkout ID/base and saved local changes.
4. Publisher checks in A as R2. B reopens offline and still sees its saved private
   view. Publisher invokes `DomainFile.merge(false, monitor)` on B: Ghidra's dirty
   native Update combines A/B, retains B's checkout ID and advances its base
   R1 → R2. Server history remains R2. Exactly one native merge invocation is observed.
5. B reopens offline again, preserving the updated projection and change sets, then
   adds another set of function/type/object changes. Publisher checks in B as R3
   without another divergent merge. A separate read-only JVM verifies the changes
   from both workers and the later edits, R3 history and no remaining checkout.
6. Close all native consumers and delete A/B's owned projects with
   `ProjectManager.deleteProject`. Native dirty Update's `fixture.keep` is accounted
   for within B's project and is removed with that project.
7. On new R3 checkouts, exercise clean Update after another publisher creates R4.
   The clean checkout keeps its ID, advances to R4 and uses Ghidra's fast path
   without a resolver invocation or `.keep`. Native `undoCheckout(false)` releases
   that unchanged checkout without a new server version, then the project is deleted.
8. A conflicting dirty Update is refused by the native headless conflict hook.
   Independent reopen confirms the private projection, observed change sets,
   original checkout ID/base and server history survive. Deletion is refused.
   Successfully published and reader/baseline evidence projects are deleted;
   unresolved private work remains retained.

The extended assertions compare functions/signatures, structures, locals, tags,
instructions, comments, created/deleted functions and types, data, enums/unions/
typedefs and their use bindings, namespaces/labels, references, bookmarks, equates,
properties/options, memory block attributes/bytes, register context and external
functions/library paths. These are bounded observations, not whole-database equality.

## Reproduce and inspect

Run the existing fixture runner with `--case checkout-lifecycle --ack-disposable` and
the existing required `--ghidra-home`, `--java`, `--mcp-jar` and `--output-base`
arguments. All supplied paths must resolve outside the protected profile. The runner
requires Ghidra 12.1.2, creates its own root, verifies ownership before native project
deletion and stops only the processes it launched. Loopback RMI access is required.

The fixture retains source snapshots/hashes, runtime inventory, request/response
records, native logs, results and a sanitized receipt under the new owned root.
The [verification report](verification/native-checkout-lifecycle.json) identifies the
accepted run. Original pre-follow-up audit/prototype documents are retained beside
that run so earlier source-only audit hashes remain interpretable.

The same pinned headless entry/display adaptations and separately documented native
memory-comment compatibility patch from the earlier prototype are compiled only into
the disposable root. This scenario adds no merge category, type mapping or coordinator
conflict winner. Installed Ghidra/bridge JAR hashes must match before and after execution.

## Integration consequences and remaining gates

Persist one native project locator/file ID/checkout ID/base per context. Launch private
workers against it without server secrets; stop/close those workers before service
Update/check-in. Hand the **same saved project** to the authorized native client.
Treat `.keep` as part of the owned project lifecycle. After verified publication,
release/close/drop; retain unresolved work. GC is a later ownership/journal/lease-aware
operation and cannot equate an old checkout with disposable data.

The prototype does not implement public CLI routing, durable publication intents,
lost-reply reconciliation, crash/cancel recovery, conflict resolution, concurrent
publisher arbitration, imported-real-binary acceptance or repeated-cycle disk budgets.
Server permission checks do not supply these application guarantees. Memory layout
and language changes still require native exclusive access. Existing detached history
and pending work need an explicit migration boundary before native adoption.

No product profile is opened; `ec2-native` is excluded from this experiment.
