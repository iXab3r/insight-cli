# Analysis storage and migration

`storage show --json` reports effective profile storage, availability, active file/byte usage,
exact included trees, retained migration and installation default base. Before selecting a
base, storage starts in Factory profile AppData. `configure` and `migrate` select that base
for subsequent new/empty profiles as well as moving the current profile. Add `--profile-only`
to keep the installation default unchanged. The effective root appends `insight-cli/<profile>`.
Initialized profiles keep their existing locations when the default changes; profiles with
ordinary AppData analysis trees stay there until explicitly migrated.

The per-profile non-secret `analysisDirectory` setting remains in Factory's profile. The
installation default is bound storage-control metadata beside Factory's profile store, paired
with ownership metadata on the chosen base. It is not an environment or checkout setting.
Missing/replaced storage fails before creating analysis data; there is no system-disk fallback.
New profiles initialize on their first ordinary command, durably bind their own empty directory,
and keep permanent compatibility paths. `storage show` remains passive.

```sh
insight-cli permissions grant Update
insight-cli storage show --json
insight-cli storage configure --directory "/mnt/analysis volume" --json
```

`configure` requires no existing analysis entries. With existing data use `migrate`.
The directory is a **base**: the effective root appends `insight-cli/<profile>`, preserving
profile isolation. Choose an ordinary empty destination profile directory on a mounted local
filesystem. Spaces and Unicode are supported. Factory restricts the dedicated destination root to the
current user, including a Windows ACL; a filesystem that cannot apply this protection fails
before copying.

The complete `workspace`, `materials`, `temp` and `runtime` trees move: immutable inputs,
artifact/candidate snapshots, workspace SQLite DB/WAL, native private project/context DBs,
local Ghidra Server repositories, operation/publication/import journals, debugger traces,
process captures, exports, native helper compilation and verification working data.
**Runtime installations, acquisition caches, selections and process receipts move too**;
installation staging and activation must share a filesystem. External tool installations and
user-selected outputs outside these trees keep their locations.

Factory keeps profiles, permissions, IPC election/socket, migration-control metadata and
application logs in current-user AppData. Secrets stay in the OS keyring. Credential/profile
identities do not change. Updating/installing npm preserves existing profile locations and does not select a disk on its own.

## Select a default after an earlier migration

For installations migrated with an older CLI, select their existing mounted base once:

```sh
insight-cli storage default --directory "/mnt/analysis volume" --json
```

This Update operation changes the installation default without moving existing data. Future
profiles inherit it without repeating configuration. The base cannot be inside a profile data
root or overlap Factory control storage. A base owned by another installation is rejected.
A missing volume or replaced base/ownership marker is never adopted automatically.

## Move an existing profile

Finish changing commands, close native contexts, and stop this profile's owned server/tool
processes through ordinary CLI commands. Inspect `tools processes --json`. Unverified lifetimes
also block migration. Do not kill guessed PIDs or stop other profiles to make preflight pass.
Factory retains IPC ownership and command admission; other profiles can keep working.

```sh
insight-cli storage migrate --directory "/mnt/analysis volume" --dry-run --json
insight-cli storage migrate --directory "/mnt/analysis volume" --json
insight-cli storage show --json
```

Dry-run reports whether it would select the installation default and checks separation, destination contents, access, conservative capacity and quiescence
without reserving/copying a migration. Source/destination/configuration roots cannot be equal
or nested. Destination symlink roots, escaping source links, special files, unresolved links
and inventories above one million entries or 128 directory levels are rejected. Internal
links retain their exact target strings. Preflight does not reserve space; concurrent disk use
can still cause a copy failure.

Migration durably reserves its journal, hashes stable source bytes, streams/syncs the copy,
independently hashes destination bytes and rechecks the source. Only then does it replace source
trees with permanent compatibility links and commit the Factory setting. Original trees are
renamed into `.storage-retained/<migration>` on their original volume. Copy/activation never
deletes them, including on failures. Existing IDs, requests, journals, candidate snapshots and
receipts retain exact bytes. Compatibility paths preserve old absolute references: do not remove
those links or their profile/source ancestors manually after migrating.

## Interruptions, uncertainty and retention

```sh
insight-cli storage resume --json
insight-cli storage rollback --json
```

Ordinary research freezes during incomplete copy/activation/rollback/cleanup. `show` and Factory
profile inspection remain available. Resume verifies completed files, recopies an incomplete
file, rechecks capacity and finishes the retained transaction. Source and destination filesystem
anchor identities are bound durably. Missing/replaced volumes fail without creating a system-disk
fallback; mount the original volume before resuming.

Rollback restores retained source and the prior Factory setting. The installation default stays
selected because subsequent profiles may already use it; a resumed older migration cannot
overwrite a newer default selection. After activation it requires
an unchanged destination and a verified retained source. Native reopening or later findings can
make rollback unsafe, in which case it refuses and preserves both copies. Use forward migration
to another empty base after using the new location. A rolled-back destination remains for manual
inspection/removal and is never automatically adopted. Cleanup permanently disables rollback.

Unknown script/publication effects do **not** need abandonment before migrating a stopped
profile. Migration starts no worker, replays no script/check-in and marks no unknown outcome
applied. Inspect the original request after migrating; existing [recovery](recovery.md)
restrictions and independent readback requirements still apply.

After independent native reopen and saved-file readback, free retained source explicitly:

```sh
insight-cli permissions grant Destructive
insight-cli storage cleanup --json
```

Cleanup verifies retained bytes, records irreversible intent, then deletes only that owned
backup. Interrupted cleanup continues through `storage resume`; rollback is already disabled.
Compatibility links, receipts and manifests remain. Clean or roll back the current migration
before starting another. This release provides no nonempty-destination adoption, reverse
synchronization, live-DB snapshotting or network-filesystem guarantees. POSIX directory fsync
is used. Windows has file fsync and rename/junction semantics; Node cannot fsync directories
there, and internal symlinks can require OS privileges.

Empty-profile initialization resumes automatically on its next command after interruption. Its
retained source contains no analysis entries, so the CLI cleans only that owned empty backup
automatically. Migration of existing data always retains its source for explicit cleanup.
