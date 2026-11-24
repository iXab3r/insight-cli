# Explicit migration of legacy Ghidra research

Migration refuses live, starting or unverified Ghidra helpers across the profile,
including interrupted checkout creation without a private-worker receipt. Retained
bootstrap/initial worker PIDs and initial-model locks are checked independently.
It never stops or takes over a worker to satisfy this admission check.
An admitted open holds migration admission from before input import until the
whole command completes; migration cannot pass a still-importing open.
Moved historical direct-helper receipts count as stopped only with acknowledged
successful completion and independently absent child and owner PIDs. Unknown
effects, live PIDs and supervised child metadata still block. A local server PID
proved reused by strong process-birth identity is archived without signaling that
PID; the same server/repository binding is then restarted normally.

Use the candidate CLI from the reviewed native-engine source state. This workflow does
not install or upgrade the global CLI. Opening a legacy program reports
`coordinator.migration`; it never performs a migration implicitly.

`ghidra migrate --target <target> --dry-run` inspects one target and its retained contexts.
Use `--all` instead of `--target` to enumerate the profile's targets, including an explicit
`native_unchanged` outcome for existing native models. Dry-run requires ReadOnly and
starts read helpers (and the configured server when stopped), but performs no checkout,
check-in, model adoption or context transition. Execution requires both ReadOnly and
Destructive. Close all selected context workers before executing.

`ghidra migrate --target <target>` reserves a durable per-target journal below the
configured workspace's `legacy-migrations` tree. Repeating exactly that command resumes
it; no separate session or target is created. The source artifact hash, server/repository,
program path, file ID, complete saved-buffer fingerprint, source SHA256, language,
compiler, image base and initialized memory bytes are bound before writing. Existing
checkouts or publication attempts block promotion. A foreign nonempty engine marker is
refused. Operators must exclude older snapshot writers during and after conversion.

With `--all`, a target with an unresolved publication is reported as
`publication_unresolved` and skipped; selecting that target directly is refused.

Promotion uses an ordinary Ghidra checkout and transaction to add the native engine
marker, followed by normal native check-in with a unique migration history marker.
Version 1 and older repository history remain intact. The writer refuses a changed head;
it never resolves a divergent native conflict automatically. Independent reader authority
verifies the exact new version, unique history marker, full saved buffers and program
identity before the owned migration checkout is released. The project and all journals
remain retained. No program is deleted, reimported, repointed or copied over version 1.

If interruption happens after native check-in intent, resume only reconciles history and
independent readback. An absent or ambiguous history marker, changed file identity or
unproved candidate remains blocked; it never retries check-in speculatively. Interruptions
before intent resume the same owned project/checkout. A completed rerun creates no version.

## Detached work and old failed opens

A packed detached program does not prove native checkout ancestry or native change sets.
The migrator hashes and inspects every retained detached snapshot. A context with complete
saved buffers and program identity equal to the pre-migration, published or current server
version, or to the exact older server version recorded as its base, and no pending edits,
traces or unresolved operations is reset without creating a checkout. Its next open takes
one native checkout at the current revision. Its original full context and snapshot identity
remain in a dedicated migration journal. This is equality verification, not replay of
diagnostic edits. Snapshots are inspected in bounded batches.

Targets that are already native report `native_unchanged`; their detached contexts receive
the same inspection, without a migration check-in or model adoption. After migration,
[collection](GHIDRA-STORAGE-COLLECTION.md) reclaims the unreferenced packed copies.

Other detached contexts are explicitly reported as `retained`, including their session,
target, immutable snapshot, observed identity and reason. Arbitrary private changes are
not converted by scalar or script replay. Their original snapshot, pending changes,
requests and context remain untouched and available for a future native ancestry-aware
conversion. A source mismatch is a concrete refusal, even if filenames are equal.

After a verified promotion, an old unresolved `ghidra.open` with no private snapshot,
checkout, edits, traces or active worker can be completed as `failed / not_opened`.
Its original request/result remain recorded. An unowned server checkout prevents that
recovery because it could be an uncertain historical open. Already known native checkouts
are independently verified before being excluded from that uncertainty. A failed checkout
creation intent is moved into the migration recovery journal; its original project and
all request evidence remain retained. The same session/target then creates a fresh normal
checkout from the existing native model, without another import. Continue the same
session/target using a new ordinary `ghidra open --session <session> --target <target>`
request. No unknown script or publication is declared successful.

## Isolated acceptance copies

Never copy an active repository database. The cold-copy proof requires stopped Java and
Insight owners, holds source file handles denying writes/deletion for the entire copy,
independently hashes destination bytes and rechecks the complete source inventory.
Retain the manifest, source identity and process checks. Run candidates only on the new
isolated profile/control root and copied repository/context storage, with the original
managed runtime used read-only. Rebinding copied paths/ports/secrets belongs only to the
isolated fixture. Preserve the original profile, repositories, private contexts and all
history; do not stop or repoint a shared production profile to make acceptance pass.

Offline fault injection covers interruption, idempotence, identity changes, checkout
conflicts, permission gates and retained private work. Native evidence must separately
record actual model versions, open/decode/decompile/xrefs, private-context outcomes and
original-file hashes. A synthetic test is not proof of real native behavior.
